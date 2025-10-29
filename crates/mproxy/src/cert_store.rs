use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{LazyLock, Mutex};
use tracing::info;
use mproxy_common::cert_path;
use mproxy_common::certificates::Certificate;
use mproxy_common::host_config::{HostConfig, HostConfigList, HostsConfigLoader};

// This is a Global Certificate Map that is used by the CertHandler
static CERT_MAP: LazyLock<Mutex<HashMap<String, Option<Certificate>>>> = LazyLock::new(|| {
  info!("CERT_MAP Init");
  Mutex::new(HashMap::new())
});



#[derive(Debug)]
pub struct CertStore {
  host_config_loader: Option<HostsConfigLoader>,
}


// Manage the Certificates
impl CertStore {
  pub fn new() -> Self {
    Self {
      host_config_loader: None,
    }
  }

  pub fn refresh_hosts(&mut self) {
    if let Some(host_config_loader) = &mut self.host_config_loader {
      host_config_loader.refresh_hosts_config();
    }
  }
  pub fn set_host_config_loader(&mut self, host_config_loader: HostsConfigLoader) {
    self.host_config_loader = Some(host_config_loader.into());
  }

  pub fn load_certs_from_host_config_list(&self, host_config_list: &HostConfigList) {
    host_config_list.host_configs.iter().for_each(|host_config| {
      self.host_config_to_cert(host_config);
    });
  }

  fn host_config_to_cert(&self, host_config: &HostConfig) {
    let mut map = CERT_MAP.lock().unwrap();
    let cert_path = PathBuf::from(cert_path())
      .join(cert_path())
      .join(host_config.host_name.clone())
      .join("cert.json");
    let mut cert = Some(Certificate::from_path(cert_path));
    cert.as_mut().unwrap().host_config = Some(host_config.clone());
    map.insert(host_config.host_name.clone(), cert.clone());
    if let Some(aliases) = &host_config.aliases {
      for alias in aliases {
        map.insert(alias.clone(), cert.clone());
      }
    }
  }

  pub fn set_cert(&self, server_name: &str, cert: Certificate) {
    let mut map = CERT_MAP.lock().unwrap();
    map.insert(server_name.to_string(), Some(cert.clone()));
  }

  pub fn get_cert(&self, server_name: &str) -> Option<Certificate> {
    let map = CERT_MAP.lock().unwrap();
    match map.get(server_name) {
      Some(cert) => cert.to_owned(),
      None => None,
    }
  }

  fn extract_last_cert(pem_chain: &str) -> Option<&str> {
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
}
