extern crate dotenv;

use std::fs;
use std::path::PathBuf;
use dotenv::dotenv;
use tokio::task::JoinHandle;
use tracing::subscriber::set_global_default;
use tracing::{error, info};
use tracing_subscriber::FmtSubscriber;
use mproxy_common::acme_challenge_path;
use mproxy_common::host_config::HostsConfigLoader;
use crate::cert_store::CertStore;

mod server;
mod cert_store;
mod cert_handler;
mod s3_proxy;
mod metrics;
mod metrics_endpoint;
mod admin_endpoints;

extern crate jemallocator;

#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[tokio::main]
async fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_line_number(true)
        .with_ansi(true)
        .with_file(true)
        .finish();
    set_global_default(subscriber).expect("setting default subscriber failed");
    dotenv().ok();
    dotenv::from_filename("/etc/mproxy/mproxy.env").ok();
    info!("Starting MProxy v{} Built@:[{}] Profile:[{}]", env!("CARGO_PKG_VERSION"), env!("BUILD_DATE"), env!("PROFILE"));

    let mut join_handles: Vec<JoinHandle<()>> = Vec::new();

    let admin_api_enabled = std::env::var("MPROXY_ADMIN_API")
        .map(|s| s.to_lowercase() == "true")
        .unwrap_or(false);
    if admin_api_enabled {
        info!("Admin API enabled (MPROXY_ADMIN_API=true)");
        let admin_handle = tokio::spawn(async move {
            if let Err(e) = admin_endpoints::start_admin_socket_server().await {
                error!("Admin socket server error: {}", e);
            }
        });
        join_handles.push(admin_handle);
    } else {
        info!("Admin API disabled (MPROXY_ADMIN_API!=true)");
    }

    let metrics_enabled = std::env::var("MPROXY_METRICS")
        .map(|s| s.to_lowercase() != "false")
        .unwrap_or(true);

    if metrics_enabled {
        metrics::METRICS.set_build_info();
        let metrics_handle = tokio::spawn(async move {
            if let Err(e) = metrics_endpoint::start_metrics_server().await {
                error!("Metrics server error: {}", e);
            }
        });
        join_handles.push(metrics_handle);
        info!("Metrics enabled");
    } else {
        info!("Metrics disabled (MPROXY_METRICS=false)");
    }

    // try to ensure challenge path
    let challenge_path = acme_challenge_path();
    if !PathBuf::from(&challenge_path).exists() {
        fs::create_dir_all(&challenge_path).expect(
            format!("Failed to create challenge path at: [{}]", challenge_path).as_str(),
        );
    }

    let config_loader = HostsConfigLoader::new();
    let config = config_loader.load();
    info!("Host config list: {:#?}", config);

    let mut cert_store = CertStore::new();
    cert_store.load_certs_from_host_config_list(&config_loader.load());
    cert_store.set_host_config_loader(config_loader);

    let monitor_handle = tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            cert_store.refresh_hosts();
        }
    });
    join_handles.push(monitor_handle);

    let update_interval_secs = std::env::var("MPROXY_UPTIME_UPDATE_INTERVAL")
        .unwrap_or_else(|_| "10".to_string())
        .parse::<u64>()
        .unwrap_or(10);

    let uptime_handle = tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(update_interval_secs)).await;
            metrics::METRICS.increment_uptime(update_interval_secs);
        }
    });
    join_handles.push(uptime_handle);

    std::thread::spawn(move || {
        server::server::start_server();
    });

    ctrlc::set_handler(move || {
        info!("SHUTDOWN SIGNAL RECEIVED - Exiting");
        std::process::exit(0);
    })
    .expect("Error setting Ctrl-C handler");

    for handle in join_handles {
        handle.await.unwrap();
    }
}
