extern crate dotenv;

use std::fs;
use std::path::PathBuf;
use dotenv::dotenv;
use tokio::task::JoinHandle;
use tracing::subscriber::set_global_default;
use tracing::info;
use tracing_subscriber::FmtSubscriber;
use mproxy_common::acme_challenge_path;
use mproxy_common::host_config::{HostsConfigLoader};
use crate::cert_store::CertStore;

// Declare the server module
mod server;
mod cert_store;
mod cert_handler;
// mod s3_proxy;

#[tokio::main]
async fn main() {
    let subscriber = FmtSubscriber::builder().with_line_number(true).with_ansi(true).with_file(true)
      .finish();
    set_global_default(subscriber)
      .expect("setting default subscriber failed");
    dotenv().ok();
    dotenv::from_filename("/etc/mproxy/mproxy.env").ok();
    info!("Starting MProxy v{} Built@:[{}]", env!("CARGO_PKG_VERSION"),env!("BUILD_DATE"));

    // try to ensure challenge path
    let challenge_path = acme_challenge_path();
    if !PathBuf::from(&challenge_path).exists() {
        fs::create_dir_all(&challenge_path).expect(format!("Failed to create challenge path at: [{}]",challenge_path).as_str());
    }

    let mut join_handles: Vec<JoinHandle<()>> =  Vec::new();
    let config_loader = HostsConfigLoader::new();
    let config = config_loader.load();

    info!("Host config list: {:#?}", config);


    let mut cert_store = CertStore::new();

    cert_store.load_certs_from_host_config_list(&config_loader.load());
    cert_store.set_host_config_loader(config_loader);

    let monitor_handle = tokio::spawn(async move {
        loop {
            // info!("Monitoring...");
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            cert_store.refresh_hosts();
        }
    });

    join_handles.push(monitor_handle);

    std::thread::spawn(move || {
        server::server::start_server();
    });

    ctrlc::set_handler(move || {
        info!("SHUTDOWN SIGNAL RECEIVED - Exiting");
        std::process::exit(0);
    }).expect("Error setting Ctrl-C handler");

    for handle in join_handles {
        handle.await.unwrap();
    }

}
