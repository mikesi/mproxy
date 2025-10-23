pub mod config;
pub mod letscencrypt;
pub mod certificates;
pub mod host_config;

pub fn data_path() -> String {
    std::env::var("MPROXY_DATA_PATH").expect("MPROXY_DATA_PATH must be set")
}

pub fn cert_path() -> String {
    std::env::var("MPROXY_CERT_PATH")
        .unwrap_or_else(|_| format!("{}/certs", data_path()))
}
