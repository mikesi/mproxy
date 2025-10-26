use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::fmt::{Display, Formatter};
use std::fs;
use std::path::PathBuf;
use chrono::{ Utc};
use time::format_description::well_known::iso8601::FormattedComponents::DateTime;
use time::OffsetDateTime;
use tracing::info;
use x509_parser::certificate::X509Certificate;
use x509_parser::{parse_x509_certificate};
use x509_parser::pem::parse_x509_pem;
use crate::host_config::HostConfig;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Certificate {
  pub host_name: String,
  pub host_names: Option<Vec<String>>,
  pub private_key_pem: Option<String>,
  pub certificate_pem: Option<String>,
  pub full_chain: Option<String>,
  pub host_config: Option<HostConfig>,
  #[serde(skip_serializing,skip_deserializing)]
  pub parsed_cert_der: RefCell<Option<Vec<u8>>>,
  pub parsed_inter_cert: RefCell<Option<Vec<u8>>>,
}

impl Display for Certificate {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    format!("{:?}", self.host_name).fmt(f)
  }
}

impl Certificate {
  pub fn new(host_name: String) -> Certificate {
    Certificate {
      host_name,
      host_names: None,
      private_key_pem: None,
      certificate_pem: None,
      full_chain: None,
      parsed_cert_der: RefCell::new(None),
      parsed_inter_cert: RefCell::new(None),
      host_config: None,
    }
  }
  pub fn from_struct(cert: Certificate) -> Certificate {
    let mut new_cert = Certificate::new(cert.host_name.clone());
    new_cert.host_names = cert.host_names;
    new_cert.private_key_pem = cert.private_key_pem;
    new_cert.certificate_pem = cert.certificate_pem;
    new_cert.full_chain = cert.full_chain;
    new_cert.parsed_cert_der = RefCell::new(None);
    new_cert.parse_inter_cert();
    new_cert.host_config = cert.host_config;
    new_cert
  }

  pub fn from_path(path: PathBuf) -> Certificate {
    info!("Looad from path: [{}]",&path.to_str().unwrap());
    let mut cert: Certificate = serde_json::from_str(fs::read_to_string(path).unwrap().as_str()).unwrap();
    cert.parsed_cert_der = RefCell::new(None);
    cert.parsed_inter_cert = RefCell::new(None);
    cert.parse_inter_cert();
    cert.host_config = None;
    cert
  }

  pub fn parse_inter_cert(&mut self){
    if self.full_chain.is_some() {
      if let Some(inter_cert_str) = Certificate::extract_inter_cert_str(self.full_chain.as_ref().unwrap()) {
        self.parsed_inter_cert = RefCell::new(Some(inter_cert_str.as_bytes().to_vec()));
      }
    }
  }

  pub fn get_host_name(&self) -> String {
    self.host_name.clone()
  }

  pub fn set_host_name(&mut self, host_name: String) {
    self.host_name = host_name;
  }

  pub fn set_host_names(&mut self, host_names: Vec<String>) {
    self.host_names = Some(host_names);
  }

  pub fn set_private_key(&mut self, private_key: String) {
    self.private_key_pem = Some(private_key);
  }

  pub fn set_certificate(&mut self, certificate: String) {
    self.certificate_pem = Some(certificate);
  }

  pub fn set_full_chain(&mut self, full_chain: String) {
    self.full_chain = Some(full_chain);
  }

  pub fn parse_cert(&self) -> Result<()> {
    let cert = self
      .certificate_pem
      .as_deref()
      .context("No certificate data available")?;

    let (_, pem) = parse_x509_pem(cert.as_bytes())
      .map_err(|e| anyhow::anyhow!("Failed to parse PEM data: {}", e))?;

    let _ = parse_x509_certificate(&pem.contents)
      .map_err(|e| anyhow::anyhow!("Invalid X.509 certificate: {}", e))?;

    *self.parsed_cert_der.borrow_mut() = Some(pem.contents.to_vec());

    Ok(())
  }

  pub fn with_parsed_cert<F, T>(&self, f: F) -> Result<T>
  where
    F: FnOnce(&X509Certificate) -> T,
  {
    if self.parsed_cert_der.borrow().is_none() {
      self.parse_cert()?;
    }

    let borrowed_der = self.parsed_cert_der.borrow();
    let der = borrowed_der.as_ref().ok_or_else(|| {
      anyhow::anyhow!("Certificate DER is unexpectedly empty after parsing")
    })?;
    let (_, cert) = parse_x509_certificate(der)
      .map_err(|e| anyhow::anyhow!("Invalid X.509 certificate: {}", e))?;

    Ok(f(&cert))
  }

  pub fn extract_inter_cert_str(pem_chain: &str) -> Option<&str> {
    let begin_marker = "-----BEGIN CERTIFICATE-----";
    let end_marker = "-----END CERTIFICATE-----";
    let mut last_pos = 0;

    while let Some(begin) = pem_chain[last_pos..].find(begin_marker) {
      let begin = last_pos + begin;
      let end = pem_chain[begin..].find(end_marker)?;
      last_pos = begin + end + end_marker.len();
    }

    // Get the last certificate block if it exists
    if last_pos > 0 {
      let begin = pem_chain[..last_pos].rfind(begin_marker)?;
      let end = pem_chain[begin..].find(end_marker)? + end_marker.len() + begin;
      return Some(&pem_chain[begin..end]);
    }

    None
  }

  pub fn get_valid_until_unix_timestamp(&self) -> Result<i64> {
    self.with_parsed_cert(|cert| {
      let valid_until = cert.validity().not_after.to_datetime();
      Ok(valid_until.unix_timestamp())
    })?
  }

  pub fn get_valid_until_date_time(&self) -> Result<chrono::DateTime<Utc>> {
    self.with_parsed_cert(|cert| {
      let valid_until = cert.validity().not_after.to_datetime();
      Ok(chrono::DateTime::from_timestamp(valid_until.unix_timestamp(),0).unwrap())
    })?
  }


  pub fn get_valid_from_unix_timestamp(&self) -> Result<i64> {
    self.with_parsed_cert(|cert| {
      let valid_from = cert.validity().not_before.to_datetime();
      Ok(valid_from.unix_timestamp())
    })?
  }

  pub fn is_expired(&self) -> Result<bool> {
    self.with_parsed_cert(|cert| {
      let expiration_date = cert.validity().not_after.to_datetime();
      Ok(OffsetDateTime::now_utc() > expiration_date)
    })?
  }

}
