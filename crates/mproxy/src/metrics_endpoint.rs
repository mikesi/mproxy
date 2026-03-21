use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use prometheus::{Encoder, TextEncoder};
use std::convert::Infallible;
use std::net::SocketAddr;
use tracing::{error, info};

use crate::metrics::METRICS;

async fn handle_request(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/metrics") | (&Method::GET, "/") => handle_metrics().await,
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("Not Found"))
            .unwrap()),
    }
}

async fn handle_metrics() -> Result<Response<Body>, Infallible> {
    let encoder = TextEncoder::new();
    let metric_families = METRICS.registry.gather();
    let mut buffer = Vec::new();

    match encoder.encode(&metric_families, &mut buffer) {
        Ok(_) => Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", encoder.format_type())
            .body(Body::from(buffer))
            .unwrap()),
        Err(e) => {
            error!("Failed to encode metrics: {}", e);
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Failed to encode metrics"))
                .unwrap())
        }
    }
}

pub async fn start_metrics_server() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let metrics_port = std::env::var("METRICS_PORT")
        .unwrap_or_else(|_| "9876".to_string())
        .parse::<u16>()
        .unwrap_or(9876);

    let addr = SocketAddr::from(([0, 0, 0, 0], metrics_port));

    let make_svc = make_service_fn(|_conn| async {
        Ok::<_, Infallible>(service_fn(handle_request))
    });

    info!("Metrics server listening on http://0.0.0.0:{}", metrics_port);

    Server::bind(&addr).serve(make_svc).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::Body;
    use hyper::Request;

    #[tokio::test]
    async fn test_metrics_endpoint() {
        let response = handle_metrics().await.unwrap();
        assert_eq!(response.status(), 200);
        
        let body_bytes = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        
        // Should contain some prometheus metrics
        assert!(body_str.contains("mproxy_"));
        assert!(body_str.contains("uptime_seconds_total"));
    }

    #[tokio::test]
    async fn test_non_metrics_returns_not_found() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("/admin/health")
            .body(Body::empty())
            .unwrap();

        let response = handle_request(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
