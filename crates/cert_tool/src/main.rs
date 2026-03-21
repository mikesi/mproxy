extern crate dotenv;

use clap::{Parser, Subcommand};
use dotenv::dotenv;
use mproxy_common::{cert_path, certificates::Certificate, letsencrypt};
use std::fs;
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tracing::info;
use tracing_subscriber::FmtSubscriber;

#[derive(Parser)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
  #[command(subcommand)]
  command: Commands,
}

#[derive(Subcommand)]
enum Commands {
  #[command(propagate_version = true)]
  /// Imports Certificates from Nginx-Proxy Let's Encrypt directory
  Import {
    #[arg(short = 'i', long = "input-dir", required = true)]
    input_dir: String,
  },
  /// Request New Certificate from Let's Encrypt
  CertNew {
    #[arg(short = 'e', long = "email", required = true)]
    email: String,
    #[arg(short = 'd', long = "domain", required = true)]
    domain: String,
    #[arg(short = 'a', long = "alias", required = false)]
    aliases: Vec<String>,
    /// Sets the Let's Encrypt staging directory - for testing purposes
    #[arg(short = 's', long = "staging", required = false,default_value_t = false)]
    staging: bool,
  },
  /// Tries to renew all certificates for hosts in host.toml that will expire soon.\n
  /// Make sure MPROXY_LETSENCRYPT_EMAIL is defined
  CertAutoRenew {
    /// Sets the Let's Encrypt staging directory - for testing purposes
    #[arg(short = 's', long = "staging", required = false,default_value_t = false)]
    staging: bool,
  },
  /// Renew loads a current certificate from store. \n
  /// Make sure MPROXY_LETSENCRYPT_EMAIL is defined
  CertRenew {
    /// The name of the directory that contains the certificate
    #[arg(short = 'd', long = "domain", required = true)]
    domain: String,
    /// Sets the Let's Encrypt staging directory - for testing purposes
    #[arg(short = 's', long = "staging", required = false,default_value_t = false)]
    staging: bool,
  },
  /// Tries to find an existing Certificate in the store
  CertFind {
    #[arg(short = 'd', long = "domain", required = true)]
    domain: String,
  },
  /// Reloads the server to apply new certificates and or changes in hosts.toml
  ReloadServer {
    /// Path to the admin Unix socket
    #[arg(short = 'S', long = "socket", required = false, default_value = "/var/run/mproxy_admin.sock")]
    socket: String,
  },
  /// Fetches and displays Prometheus metrics from the running mproxy instance
  Metrics {
    /// Host and port of the metrics server
    #[arg(short = 'u', long = "url", required = false, default_value = "http://127.0.0.1:9876/metrics")]
    url: String,
  },
  /// Exports certificate, private key, and hosts for a given hostname
  Export {
    #[arg(short = 'h', long = "hostname", required = true)]
    hostname: String,
  },
}

#[tokio::main]
async fn main() {
  let subscriber = FmtSubscriber::builder()
    .with_line_number(true)
    .with_file(true)
    .finish();
  tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
  dotenv().ok();
  dotenv::from_filename("/etc/mproxy/mproxy.env").ok();

  let cli = Cli::parse();

  match &cli.command {
    Commands::CertAutoRenew { staging } => {
      letsencrypt::renew_certs_in_store(*staging);
    },
    Commands::CertFind { domain } => {
      let cert = letsencrypt::find_certificate(domain.into());
      if let Some(cert) = cert {
        println!("Certificate found for domain: {}", domain);
        println!("Aliases: {:?}",cert.host_names);
        println!("\nCert: {:?}",cert.certificate_pem);
        println!("\nFull Chain: {:?}",cert.full_chain);
        println!("\nPrivate Key: {:?}",cert.private_key_pem);
        println!("\nExpire At: [{}]",cert.get_valid_until_date_time().unwrap().to_rfc3339());
      } else {
        println!("Certificate not found for domain: {}", domain);
      }
    }
    Commands::CertRenew {domain, staging} => {
      info!("Renew Certificate");
      letsencrypt::renew_certificate(domain,&std::env::var("MPROXY_LETSENCRYPT_EMAIL").unwrap(),*staging);
    }
    Commands::CertNew {domain,email, aliases, staging } => {
      match letsencrypt::request_certificate(domain, email, aliases, *staging) {
        Ok(_) => {
          println!("Certificate Request Success!");
        }
        Err(e) => {
          eprintln!("Error requesting certificate: {}", e);
          eprintln!("Error Dump: {:?}", e);
        }
      }
    }
    Commands::ReloadServer { socket } => {
      match reload_server_via_socket(socket).await {
        Ok(response) => {
          println!("{}", response);
        }
        Err(e) => {
          eprintln!("Error reloading server: {}", e);
          std::process::exit(1);
        }
      }
    }
    Commands::Metrics { url } => {
      match fetch_metrics(url).await {
        Ok(body) => {
          println!("{}", body);
        }
        Err(e) => {
          eprintln!("Error fetching metrics: {}", e);
          std::process::exit(1);
        }
      }
    }
    Commands::Import { input_dir } => {
      letsencrypt::import_from_letsencrypt_path(input_dir).await;
    }
    Commands::Export { hostname } => {
      let cert_file_path = PathBuf::from(cert_path()).join(hostname).join("cert.json");

      match fs::read_to_string(&cert_file_path) {
        Ok(cert_json) => {
          match serde_json::from_str::<Certificate>(&cert_json) {
            Ok(cert) => {
              println!("=== Certificate Export for {} ===\n", hostname);

              println!("--- Hostname ---");
              println!("{}", cert.host_name);
              println!();

              if let Some(host_names) = &cert.host_names {
                println!("--- Additional Hosts ---");
                for host in host_names {
                  println!("{}", host);
                }
                println!();
              }

              if let Some(certificate) = &cert.certificate_pem {
                println!("--- Certificate ---");
                println!("{}", certificate);
                println!();
              } else {
                println!("--- Certificate ---");
                println!("(No certificate data available)");
                println!();
              }

              if let Some(full_chain) = &cert.full_chain {
                println!("--- Full Chain ---");
                println!("{}", full_chain);
                println!();
              }

              if let Some(private_key) = &cert.private_key_pem {
                println!("--- Private Key ---");
                println!("{}", private_key);
                println!();
              } else {
                println!("--- Private Key ---");
                println!("   (No private key data available)");
                println!();
              }
            }
            Err(e) => {
              eprintln!("Error parsing certificate JSON: {}", e);
              std::process::exit(1);
            }
          }
        }
        Err(e) => {
          eprintln!("Error reading certificate file at {:?}: {}", cert_file_path, e);
          eprintln!("Make sure the hostname is correct and the certificate exists.");
          std::process::exit(1);
        }
      }
    }
  }
}

async fn fetch_metrics(url: &str) -> Result<String, Box<dyn std::error::Error>> {
  let mut stream = tokio::net::TcpStream::connect(
    url.trim_start_matches("http://")
      .split('/')
      .next()
      .unwrap_or("127.0.0.1:9876"),
  ).await?;

  let path = url.find("://")
    .and_then(|i| url[i + 3..].find('/').map(|j| &url[i + 3 + j..]))
    .unwrap_or("/metrics");

  let host = url.trim_start_matches("http://")
    .split('/')
    .next()
    .unwrap_or("127.0.0.1:9876");

  let request = format!(
    "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
    path, host
  );
  stream.write_all(request.as_bytes()).await?;

  let mut response = String::new();
  stream.read_to_string(&mut response).await?;

  if let Some(body_start) = response.find("\r\n\r\n") {
    Ok(response[body_start + 4..].to_string())
  } else {
    Ok(response)
  }
}

async fn reload_server_via_socket(socket_path: &str) -> Result<String, Box<dyn std::error::Error>> {
  let mut stream = UnixStream::connect(socket_path).await?;

  let request = format!(
    "POST /admin/reload-certs HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
  );
  stream.write_all(request.as_bytes()).await?;

  let mut response = String::new();
  stream.read_to_string(&mut response).await?;

  // Extract the body from the HTTP response
  if let Some(body_start) = response.find("\r\n\r\n") {
    Ok(response[body_start + 4..].to_string())
  } else {
    Ok(response)
  }
}
