use mproxy_common::host_config::{HostConfig, HostMode};
use tokio::net::TcpListener;
use tracing::{error, info};

pub struct TcpForwarder {
    listen_port: u16,
    upstream_addr: String,
    host_name: String,
}

impl TcpForwarder {
    pub fn new(listen_port: u16, upstream_addr: String, host_name: String) -> Self {
        Self {
            listen_port,
            upstream_addr,
            host_name,
        }
    }

    pub async fn run(&self) {
        let bind_addr = format!("0.0.0.0:{}", self.listen_port);
        let listener = match TcpListener::bind(&bind_addr).await {
            Ok(l) => {
                info!(
                    "TCP forwarder listening on {} -> {} (host: {})",
                    bind_addr, self.upstream_addr, self.host_name
                );
                l
            }
            Err(e) => {
                error!(
                    "TCP forwarder failed to bind {}: {} (host: {})",
                    bind_addr, e, self.host_name
                );
                return;
            }
        };

        loop {
            let (mut inbound, peer_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    error!("TCP forwarder accept error on port {}: {}", self.listen_port, e);
                    continue;
                }
            };

            let upstream_addr = self.upstream_addr.clone();
            let host_name = self.host_name.clone();
            let listen_port = self.listen_port;

            tokio::spawn(async move {
                info!(
                    "TCP forward connection from {} on port {} (host: {})",
                    peer_addr, listen_port, host_name
                );

                let mut outbound = match tokio::net::TcpStream::connect(&upstream_addr).await {
                    Ok(s) => s,
                    Err(e) => {
                        error!(
                            "TCP forwarder failed to connect to upstream {}: {} (host: {})",
                            upstream_addr, e, host_name
                        );
                        return;
                    }
                };

                match tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await {
                    Ok((to_upstream, to_client)) => {
                        info!(
                            "TCP forward closed for {} (host: {}): {} bytes up, {} bytes down",
                            peer_addr, host_name, to_upstream, to_client
                        );
                    }
                    Err(e) => {
                        error!(
                            "TCP forward error for {} (host: {}): {}",
                            peer_addr, host_name, e
                        );
                    }
                }
            });
        }
    }
}

pub async fn start_tcp_forwarders(host_configs: &[HostConfig]) {
    let forwarders: Vec<_> = host_configs
        .iter()
        .filter(|hc| matches!(hc.effective_mode(), HostMode::Tcp | HostMode::Both))
        .filter_map(|hc| {
            hc.tcp_forward_port.map(|port| {
                TcpForwarder::new(port, hc.upstream_address.clone(), hc.host_name.clone())
            })
        })
        .collect();

    if forwarders.is_empty() {
        info!("No TCP forwarders configured");
        return;
    }

    info!("Starting {} TCP forwarder(s)", forwarders.len());

    let mut handles = Vec::new();
    for forwarder in forwarders {
        handles.push(tokio::spawn(async move {
            forwarder.run().await;
        }));
    }

    for handle in handles {
        if let Err(e) = handle.await {
            error!("TCP forwarder task panicked: {}", e);
        }
    }
}
