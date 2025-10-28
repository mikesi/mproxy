extern crate dotenv;

use clap::{Parser, Subcommand};
use dotenv::dotenv;
use mproxy_common::{cert_path, certificates::Certificate, letsencrypt};
use std::fs;
use std::path::PathBuf;
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
  /// Tries to renew all certificates for hosts in host.toml that will expire soon
  CertAutoRenew {
    /// Sets the Let's Encrypt staging directory - for testing purposes
    #[arg(short = 's', long = "staging", required = false,default_value_t = false)]
    staging: bool,
  },
  /// Renew loads a current certificate from store
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
    Commands::ReloadServer { } => {

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
                println!("(No private key data available)");
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
