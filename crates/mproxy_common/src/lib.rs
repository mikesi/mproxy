pub mod config;
pub mod letsencrypt;
pub mod certificates;
pub mod host_config;

pub fn data_path() -> String {
    std::env::var("MPROXY_DATA_PATH").expect("MPROXY_DATA_PATH must be set")
}

pub fn cert_path() -> String {
    std::env::var("MPROXY_CERT_PATH")
        .unwrap_or_else(|_| format!("{}/certs", data_path()))
}

pub fn acme_challenge_path() -> String {
    format!("{}/acme-challenge", data_path())
}

pub fn acme_path() -> String {
    format!("{}/acme", data_path())
}
