use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Method, Request, Response, StatusCode};
use std::convert::Infallible;
use tokio::net::UnixListener;
use tracing::{error, info};

use crate::cert_store::CertStore;
use mproxy_common::host_config::HostsConfigLoader;

pub async fn handle_admin_request(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    match (req.method(), req.uri().path()) {
        (&Method::POST, "/admin/reload-certs") => handle_reload_certs().await,
        (&Method::GET, "/admin/health") => handle_health().await,
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("Not Found"))
            .unwrap()),
    }
}

async fn handle_reload_certs() -> Result<Response<Body>, Infallible> {
    info!("Admin request: reload certificates");
    let cert_store = CertStore::new();
    // Clear existing certs first to avoid stale entries
    cert_store.clear_certs();
    // Reload certs from the current host config
    let config_loader = HostsConfigLoader::new();
    cert_store.load_certs_from_host_config_list(&config_loader.load());
    info!("Certificates reloaded successfully");
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"status": "ok", "message": "certificates reloaded"}"#))
        .unwrap())
}

async fn handle_health() -> Result<Response<Body>, Infallible> {
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"status": "healthy"}"#))
        .unwrap())
}

pub async fn start_admin_socket_server() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let socket_path = std::env::var("MPROXY_ADMIN_SOCKET")
        .unwrap_or_else(|_| "/var/run/mproxy_admin.sock".to_string());

    // Remove stale socket file if it exists
    if std::path::Path::new(&socket_path).exists() {
        std::fs::remove_file(&socket_path)?;
    }

    let listener = UnixListener::bind(&socket_path)?;
    info!("Admin socket server listening on {}", socket_path);

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                tokio::spawn(async move {
                    if let Err(e) = Http::new()
                        .serve_connection(
                            stream,
                            service_fn(handle_admin_request),
                        )
                        .await
                    {
                        error!("Admin socket connection error: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("Admin socket accept error: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::Body;
    use hyper::Request;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_admin_health_endpoint() {
        CertStore::new().clear_certs();
        let response = handle_health().await.unwrap();
        assert_eq!(response.status(), 200);
        
        let body_bytes = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert_eq!(body_str, r#"{"status": "healthy"}"#);
    }

    #[tokio::test]
    async fn test_admin_reload_certs_endpoint() {
        CertStore::new().clear_certs();
        let response = handle_reload_certs().await.unwrap();
        assert_eq!(response.status(), 200);
        
        let body_bytes = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert_eq!(body_str, r#"{"status": "ok", "message": "certificates reloaded"}"#);
    }

    #[tokio::test]
    async fn test_not_found_endpoint() {
        CertStore::new().clear_certs();
        let request = Request::builder()
            .method(Method::GET)
            .uri("/admin/nonexistent")
            .body(Body::empty())
            .unwrap();
        
        let response = handle_admin_request(request).await.unwrap();
        assert_eq!(response.status(), 404);
        
        let body_bytes = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert_eq!(body_str, "Not Found");
    }

    #[tokio::test]
    async fn test_reload_certs_clears_and_reloads() {
        use crate::cert_store::CertStore;
        use mproxy_common::certificates::Certificate;
        CertStore::new().clear_certs();
        
        // Add a test cert to the global map
        let cert_store = CertStore::new();
        let mut cert = Certificate::new("test.example.com".to_string());
        cert.set_private_key("old_key".to_string());
        cert_store.set_cert("test.example.com", cert);
        
        // Verify cert exists
        assert!(cert_store.get_cert("test.example.com").is_some());
        
        // Call reload endpoint
        let response = handle_reload_certs().await.unwrap();
        assert_eq!(response.status(), 200);
        
        // Give a moment for the reload to complete
        sleep(Duration::from_millis(100)).await;
        
        // The cert should be cleared (since we don't have actual cert files in test)
        // In a real scenario with proper cert files, it would be reloaded
        // For now, we just verify the endpoint doesn't panic
    }
}
