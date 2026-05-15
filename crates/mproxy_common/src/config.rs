use std::str::FromStr;
use tracing::{info, warn};
use crate::ip_blacklist::IpBlacklist;

#[derive(Clone, Debug)]
pub struct Config {
  pub api_port: i32,
  pub https_port: i32,
  pub global_blacklist: Option<IpBlacklist>,
}

pub trait Dump {
  fn dump(&self);
}

impl Config {
  pub fn new() -> Self {
    let global_blacklist = std::env::var("MPROXY_GLOBAL_BLACKLIST_IPS")
      .ok()
      .and_then(|raw| {
        if raw.trim().is_empty() {
          None
        } else {
          match IpBlacklist::from_string(raw.as_str()) {
            Ok(list) if !list.is_empty() => Some(list),
            Ok(_) => None,
            Err(err) => {
              warn!("Invalid MPROXY_GLOBAL_BLACKLIST_IPS value: {}", err);
              None
            }
          }
        }
      });

    Self {
      api_port: 3005,
      https_port: FromStr::from_str( std::env::var("MPROXY_HTTPS_PORT").unwrap_or("444".to_string()).as_str() ).unwrap(),
      global_blacklist,
    }
  }
}

impl Dump for Config {
  fn dump(&self) {
    info!("Dump config");
    info!("api_port: {}", self.api_port);
    info!("https_port: {}", self.https_port);
    info!("global_blacklist_enabled: {}", self.global_blacklist.is_some());
  }
}
