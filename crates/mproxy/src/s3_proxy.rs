use async_trait::async_trait;
use pingora::Error;
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use tracing::{error, info};
use crate::metrics::METRICS;
use crate::server::server::HttpCtx;

#[derive(Clone, Debug)]
pub struct S3Proxy {
    host: String,
    allowed_buckets: Vec<String>,
    request_uri_prefix: String,
    access_key_id: String,
    secret_access_key_id: String,
    uri_prefix: String,
    auth_uri: String,
    s3_server: String,
    s3_region: String,
    s3_is_tls: bool,
}

impl S3Proxy {
    pub fn new() -> S3Proxy {
        let host = std::env::var("MPROXY_S3_PROXY_HOST").expect("MPROXY_S3_PROXY_HOST not set");
        let allowed_buckets = std::env::var("MPROXY_S3_PROXY_BUCKET_NAME").expect("MPROXY_S3_PROXY_BUCKET_NAME not set").split(',').map(|s| s.to_string()).collect();
        let request_uri_prefix = std::env::var("MPROXY_S3_REQUEST_PREFIX").expect("MPROXY_S3_REQUEST_PREFIX not set");
        let access_key_id = std::env::var("MPROXY_AWS_ACCESS_KEY_ID").expect("MPROXY_AWS_ACCESS_KEY_ID not set");
        let secret_access_key_id = std::env::var("MPROXY_AWS_SECRET_ACCESS_KEY_ID").expect("MPROXY_AWS_SECRET_ACCESS_KEY_ID not set");
        let uri_prefix = std::env::var("MPROXY_S3_URI_PREFIX").expect("MPROXY_S3_URI_PREFIX not set");
        let auth_uri = std::env::var("MPROXY_S3_AUTH_URI").expect("MPROXY_S3_AUTH_URI not set");
        let s3_server = std::env::var("MPROXY_S3_SERVER").expect("MPROXY_S3_SERVER not set");
        let s3_region = std::env::var("MPROXY_S3_REGION").expect("MPROXY_S3_REGION not set");
        let s3_proto = std::env::var("MPROXY_S3_PROTO").expect("MPROXY_S3_PROTO not set");
        let s3_is_tls = s3_proto == "https";
        S3Proxy {
            host,
            allowed_buckets,
            request_uri_prefix,
            access_key_id,
            secret_access_key_id,
            uri_prefix,
            auth_uri,
            s3_server,
            s3_region,
            s3_is_tls,
        }
    }

    pub fn verify_hmac_signature_url(&self, _url_to_verify: &str) -> bool {
        true
    }
}

#[async_trait]
impl ProxyHttp for S3Proxy {
    type CTX = HttpCtx;

    fn new_ctx(&self) -> Self::CTX {
        use crate::cert_store::CertStore;
        HttpCtx {
            server_name: None,
            cert_store: CertStore::new(),
            client_ip: String::new(),
            request_start: std::time::Instant::now(),
            request_size: 0,
            response_size: 0,
        }
    }

    async fn upstream_peer(&self, _session: &mut Session, _ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        let peer = HttpPeer::new(self.s3_server.clone(), self.s3_is_tls, self.host.clone());
        Ok(Box::new(peer))
    }

    async fn early_request_filter(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        _ctx.request_start = std::time::Instant::now();
        _ctx.request_size = 0;
        _ctx.response_size = 0;
        Ok(())
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        let method = &session.req_header().method;

        // CORS
        if method == http::Method::OPTIONS {
            let mut response_header = ResponseHeader::build(200, None)?;
            response_header.insert_header("Access-Control-Allow-Origin", "*")?;
            response_header.insert_header("Access-Control-Allow-Methods", "GET, OPTIONS")?;
            response_header.insert_header("Access-Control-Allow-Headers", "Content-Type, Accept, Authorization")?;
            response_header.insert_header("Access-Control-Max-Age", "86400")?;
            session.write_response_header(Box::new(response_header), true).await.expect("Cannot write response _header for CORS");
            return Ok(true);
        }

        // we support only OPTIONS and GET
        if method != http::method::Method::GET {
            error!("S3 - Invalid Request Method called: [{}]", method);
            session.respond_error(405).await.expect("Cannot respond with error");
            return Ok(true);
        }

        let req_uri_path = &session.req_header().uri.path();

        // uri path must start with the prefix defined
        if !req_uri_path.starts_with(self.request_uri_prefix.as_str()) {
            session.respond_error(404).await.expect("Cannot respond with error - request uri prefix");
            return Ok(true);
        }

        let parsed_path = &mut req_uri_path.split("/");
        let bucket_name = parsed_path.nth(1).unwrap();

        if !self.allowed_buckets.contains(&bucket_name.to_string()) {
            error!("Bucket {} not allowed", bucket_name);
            session.respond_error(404).await.expect("Cannot respond with error - allowed buckets");
            return Ok(true);
        }

        let _new_req_path_without_prefix = req_uri_path
            .strip_prefix(self.request_uri_prefix.as_str())
            .map_or("", |s| s)
            .to_string();

        // Set the HOST to the S3 Host
        session.req_header_mut().insert_header(http::header::HOST, self.host.clone())?;
        let _header = session.req_header_mut();

        todo!()
    }

    async fn response_filter(&self, _session: &mut Session, _upstream_response: &mut ResponseHeader, _ctx: &mut Self::CTX) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        todo!()
    }

    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<bytes::Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        if let Some(data) = body {
            ctx.request_size += data.len() as u64;
        }
        Ok(())
    }

    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<bytes::Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<std::option::Option<std::time::Duration>>
    where
        Self::CTX: Send + Sync,
    {
        if let Some(data) = body {
            ctx.response_size += data.len() as u64;
        }
        Ok(None)
    }

    async fn logging(&self, _session: &mut Session, _e: Option<&Error>, _ctx: &mut Self::CTX)
    where
        Self::CTX: Send + Sync,
    {
        let response_code = _session
            .response_written()
            .map_or(0, |resp| resp.status.as_u16());
        let duration = _ctx.request_start.elapsed().as_secs_f64();
        METRICS.record_request(response_code, "s3-proxy", duration, _ctx.request_size, _ctx.response_size);
        if _e.is_some() {
            error!("Error: [{}] [{:?}]", _session.req_header().uri, _e.unwrap());
        } else {
            info!("Request: {:?}", _session.req_header().uri);
        }
    }
}
