extern crate dotenv;
extern crate chrono;

use clap::{Parser, Subcommand};
use dotenv::dotenv;
use mproxy_common::{cert_path, certificates::Certificate, letsencrypt};
use std::fs;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::FmtSubscriber;
use chrono::prelude::*;

#[derive(Parser)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
  #[command(subcommand)]
  command: Commands,
}

#[derive(Subcommand)]
enum Commands {
  /// Adds files to myapp
  #[command(propagate_version = true)]
  Add { name: Option<String> },
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
  },
  /// Renew loads a current certificate from store
  CertRenew {
    #[arg(short = 'd', long = "domain", required = true)]
    domain: String,
  },
  /// Tries to find an existing Certificate in the store
  CertFind {
    #[arg(short = 'd', long = "domain", required = true)]
    domain: String,
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
    Commands::CertRenew {domain} => {
      info!("Renew Certificate Req");
    }
    Commands::CertNew {domain,email, aliases} => {
      match letsencrypt::request_certificate(domain, email, aliases) {
        Ok(_) => {
          println!("Certificate Request Success!");
        }
        Err(e) => {
          eprintln!("Error requesting certificate: {}", e);
          eprintln!("Error Dump: {:?}", e);
        }
      }
    }
    Commands::Add { name } => {
      println!("'myapp add' was used, name is: {name:?}");
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
