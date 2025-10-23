pub mod config;
pub mod letscencrypt;
pub mod certificates;
pub mod host_config;

pub fn data_path() -> String {
    std::env::var("MPROXY_DATA_PATH").expect("MPROXY_DATA_PATH must be set")
}

pub fn cert_path() -> String {
    format!("{}/certs", data_path())
}


pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
