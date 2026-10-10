use std::fmt::{Debug, Formatter};
use async_trait::async_trait;
use pingora::protocols::tls::TlsRef;
use pingora::tls::pkey::PKey;
use pingora::tls::ssl::NameType;
use pingora::tls::x509::X509;
use tracing::{debug, error};
use mproxy_common::certificates::Certificate;
use crate::cert_store::CertStore;

pub struct CertHandler {
  pub cert_store: CertStore,
}

impl Debug for CertHandler {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    write!(f, "CertHandler")
  }
}

impl CertHandler {
  pub fn new() -> Box<Self> {
    Box::from(CertHandler {
      cert_store: CertStore::new(),
    })
  }

  pub fn find_cert(&self, server_name: &str) -> Option<Certificate> {
    self.cert_store.get_cert(server_name)
  }
}

#[async_trait]
impl pingora::listeners::TlsAccept for CertHandler {
  async fn certificate_callback(&self, _ssl: &mut TlsRef) -> () {
    // Store the servername in an owned String to avoid borrowing _ssl
    let servername = _ssl.servername(NameType::HOST_NAME).map(|s| s.to_string());
    match servername {
      Some(servername) => {
        if let Some(certificate) = self.find_cert(&servername) {
          if let Some(cert_full_chain) = certificate.full_chain {
            match X509::stack_from_pem(cert_full_chain.as_bytes()) {
              Ok(chain) => {
                let mut chain = chain.into_iter();
                match chain.next() {
                  Some(leaf) => {
                    if let Err(e) = _ssl.set_certificate(&leaf) {
                      error!("Error setting certificate for [{}]: {}", servername, e);
                      return;
                    }
                  }
                  None => {
                    error!("Empty certificate chain for: [{}]", servername);
                    return;
                  }
                }
                for chain_cert in chain {
                  if let Err(e) = _ssl.add_chain_cert(chain_cert) {
                    error!("Error adding chain certificate for [{}]: {}", servername, e);
                    return;
                  }
                }
              }
              Err(e) => {
                error!("Error loading cert chain for [{}]: {}", servername, e);
                return;
              }
            };
          } else {
            error!("No full chain for: [{}]", servername);
            return;
          }

          if let Some(key_pem) = certificate.private_key_pem {
            let loaded_key = match PKey::private_key_from_pem(key_pem.as_bytes()) {
              Ok(key) => key,
              Err(e) => {
                error!("Error loading key: {}", e);
                return;
              }
            };
            if let Err(e) = _ssl.set_private_key(&loaded_key) {
              error!("Error setting private key for [{}]: {}", servername, e);
              return;
            }
          } else {
            error!("No private key for: [{}]", servername);
            return;
          }

        } else {
          // NO CERT for HOSTNAME found
          error!("No Certificate for: [{}]", servername);
          return;
        }
      }
      _ => {
        error!("No Server Hostname set");
      }
    };
  }
}
