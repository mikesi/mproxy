use std::str::FromStr;
use tracing::info;

#[derive(Copy, Clone,Debug)]
pub struct Config {
  pub api_port: i32,
  pub https_port: i32,
}

pub trait Dump {
  fn dump(&self);
}

impl Config {
  pub fn new() -> Self {
    Self {
      api_port: 3005,
      https_port: FromStr::from_str( std::env::var("MPROXY_HTTPS_PORT").unwrap_or("444".to_string()).as_str() ).unwrap(),
    }
  }
}

impl Dump for Config {
  fn dump(&self) {
    info!("Dump config");
    info!("api_port: {}", self.api_port);
    info!("https_port: {}", self.https_port);
  }
}
