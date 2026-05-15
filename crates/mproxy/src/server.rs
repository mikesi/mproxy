pub mod server {
    use crate::cert_handler::CertHandler;
    use crate::cert_store::CertStore;
    use crate::metrics::METRICS;
    use crate::s3_proxy::S3Proxy;
    use async_trait::async_trait;
    use bytes::Bytes;
    use mproxy_common::acme_challenge_path;
    use mproxy_common::config::Config;
    use mproxy_common::ip_blacklist::IpBlacklist;
    use pingora::ErrorSource::Upstream;
    use pingora::http::{ResponseHeader, StatusCode};
    use pingora::listeners::tls::TlsSettings;
    use pingora::listeners::{ALPN, TcpSocketOptions, ConnectionFilter};
    use pingora::modules::http::HttpModules;
    use pingora::modules::http::compression::ResponseCompressionBuilder;
    use pingora::prelude::*;
    use pingora::protocols::TcpKeepalive;
    use pingora::server::RunArgs;
    use pingora::server::configuration::ServerConf;
    use pingora::upstreams::peer::PeerOptions;
    use std::fmt::Debug;
    use std::fs;
    use std::net::IpAddr;
    use std::path::PathBuf;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tracing::{error, info};

    // TcpConnectionTracker logs TCP connection accepts, but note that Pingora doesn't
    // provide a connection-close callback, so this counter never decrements.
    static TCP_CONNECTION_COUNT: AtomicU64 = AtomicU64::new(0);

    #[derive(Debug)]
    struct TcpConnectionTracker;

    #[async_trait]
    impl ConnectionFilter for TcpConnectionTracker {
        async fn should_accept(&self, _addr: Option<&SocketAddr>) -> bool {
            TCP_CONNECTION_COUNT.fetch_add(1, Ordering::Relaxed);
            info!("TCP connection accepted, count: {}", TCP_CONNECTION_COUNT.load(Ordering::Relaxed));
            true
        }
    }

    fn extract_client_ip(session: &Session) -> Option<IpAddr> {
        session
            .client_addr()
            .and_then(|addr| addr.as_inet().map(|inet| inet.ip()))
    }

    fn blacklist_match(
        global_blacklist: &Option<IpBlacklist>,
        cert_store: &CertStore,
        host_name: &str,
        client_ip: IpAddr,
    ) -> Option<&'static str> {
        if global_blacklist
            .as_ref()
            .is_some_and(|blacklist| blacklist.contains(client_ip))
        {
            return Some("global");
        }

        if let Some(cert) = cert_store.get_cert(host_name)
            && let Some(host_config) = cert.host_config
            && let Some(host_blacklist) = host_config.blacklisted_ips
            && host_blacklist.contains(client_ip)
        {
            return Some("per_host");
        }

        None
    }

    #[derive(Clone, Debug)]
    pub struct TlsProxyApp {
        pub global_blacklist: Option<IpBlacklist>,
    }

    #[derive(Debug)]
    pub struct HttpCtx {
        pub server_name: Option<String>,
        pub cert_store: CertStore,
        pub client_ip: String,
        pub request_start: std::time::Instant,
        pub request_size: u64,
        pub response_size: u64,
    }

    #[async_trait]
    impl ProxyHttp for TlsProxyApp {
        type CTX = HttpCtx;

        fn new_ctx(&self) -> Self::CTX {
            HttpCtx {
                server_name: None,
                cert_store: CertStore::new(),
                client_ip: String::new(),
                request_start: std::time::Instant::now(),
                request_size: 0,
                response_size: 0,
            }
        }

        async fn upstream_peer(
            &self,
            session: &mut Session,
            ctx: &mut Self::CTX,
        ) -> Result<Box<HttpPeer>> {
            // find peer address
            match ctx.cert_store.get_cert(ctx.server_name.as_ref().unwrap()) {
                None => {
                    error!("No cert found for: {}", ctx.server_name.as_ref().unwrap());
                    if let Err(e) = session.respond_error(502).await {
                        error!("Error responding to client: {}", e);
                    }
                    Err(Box::new(Error {
                        etype: HTTPStatus(502),
                        esource: Upstream,
                        retry: RetryType::Decided(false),
                        cause: None,
                        context: Option::from(ImmutStr::from("Invalid Host Requested")),
                    }))
                }
                Some(cert) => {
                    let mut peer = HttpPeer::new(
                        cert.host_config.unwrap().upstream_address,
                        false,
                        String::new(),
                    );
                    let mut peer_options = PeerOptions::new();
                    peer_options.idle_timeout = Some(Duration::from_secs(120));
                    peer_options.tcp_fast_open = true;
                    peer_options.alpn = Some(ALPN::H1).unwrap();
                    peer_options.max_h2_streams = 16;
                    peer_options.tcp_keepalive = Some(TcpKeepalive {
                        count: 32,
                        idle: Duration::from_secs(60),
                        interval: Duration::from_secs(30),
                        #[cfg(target_os = "linux")]
                        user_timeout: Duration::from_secs(0),
                    });
                    peer_options
                        .extra_proxy_headers
                        .insert("X-Forwarded-Proto".to_string(), "https".as_bytes().to_vec());
                    peer_options.extra_proxy_headers.insert(
                        "X-Forwarded-For".to_string(),
                        peer._address.to_string().as_bytes().to_vec(),
                    );
                    peer.options = peer_options;
                    Ok(Box::new(peer))
                }
            }
        }

        async fn early_request_filter(
            &self,
            session: &mut Session,
            ctx: &mut Self::CTX,
        ) -> Result<()>
        where
            Self::CTX: Send + Sync,
        {
            let host_name = SimpleHttpProxy::get_host(session);
            if host_name.is_none() {
                error!("No host specified!");
                let _ = session.respond_error(502).await;
                return Ok(());
            }
            ctx.server_name = Some(host_name.unwrap().to_string());
            ctx.request_start = std::time::Instant::now();
            ctx.request_size = 0;
            ctx.response_size = 0;

            if let Some(client_ip) = extract_client_ip(session) {
                ctx.client_ip = client_ip.to_string();
                if let Some(blacklist_type) = blacklist_match(
                    &self.global_blacklist,
                    &ctx.cert_store,
                    ctx.server_name.as_ref().unwrap(),
                    client_ip,
                ) {
                    METRICS.record_blacklist_block(
                        ctx.server_name.as_deref().unwrap_or("unknown"),
                        blacklist_type,
                    );
                    info!(
                        "Blocked request from {} for host {} by {} blacklist",
                        client_ip,
                        ctx.server_name.as_deref().unwrap_or("unknown"),
                        blacklist_type
                    );
                    session.respond_error(403).await?;
                    return Ok(());
                }
            }

            Ok(())
        }

        async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool>
        where
            Self::CTX: Send + Sync,
        {
            session.set_keepalive(Some(120));
            if ctx.server_name.is_none() {
                error!("No host specified!");
                let _ = session.respond_error(502).await;
                return Ok(true);
            }
            Ok(false)
        }

        async fn upstream_request_filter(
            &self,
            _session: &mut Session,
            _upstream_request: &mut RequestHeader,
            _ctx: &mut Self::CTX,
        ) -> Result<()>
        where
            Self::CTX: Send + Sync,
        {
            _upstream_request
                .insert_header("X-Forwarded-Proto", "https")
                .expect("TODO: panic message");
            _upstream_request
                .insert_header("X-Forwarded-Scheme", "https")
                .expect("TODO: panic message");
            if let Some(ip_str) = _session
                .client_addr()
                .and_then(|addr| addr.as_inet().map(|addr| addr.ip().to_string()))
            {
                _ctx.client_ip = ip_str.clone();
                _upstream_request
                    .insert_header("X-Real-IP", ip_str)
                    .expect("Cannot add X-Real-IP");
            }
            if let Some(content_length) = _upstream_request.headers.get("content-length") {
                if let Ok(size) = content_length.to_str().and_then(|s| Ok(s.parse::<u64>().unwrap_or(0))) {
                    _ctx.request_size = size;
                }
            }
            // Replace Cookies with Compressed cookies
            let parsed_cookies: Vec<&str> = _upstream_request
                .as_ref()
                .headers
                .get_all(http::header::COOKIE)
                .iter()
                .map(|x| x.to_str().expect("x.to_str() failed"))
                .collect();
            let compressed_cookies = parsed_cookies.join("; ");
            _upstream_request
                .insert_header("Cookie", compressed_cookies)
                .expect("Failed replace/add Cookies");
            Ok(())
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

        async fn logging(&self, session: &mut Session, _e: Option<&Error>, _ctx: &mut Self::CTX) {
            let response_code = session
                .response_written()
                .map_or(0, |resp| resp.status.as_u16());
            let duration = _ctx.request_start.elapsed().as_secs_f64();
            let host = _ctx.server_name.as_deref().unwrap_or("unknown");
            METRICS.record_request(response_code, host, duration, _ctx.request_size, _ctx.response_size);
            let log_msg = format!(
                "[{}] [{}] [{}] - [{}{}]",
                _ctx.client_ip,
                response_code,
                session.req_header().method,
                _ctx.server_name.as_deref().unwrap_or(""),
                session.req_header().uri.path_and_query().unwrap()
            );
            if _e.is_some() {
                error!("Error: {}", log_msg);
                error!("SERVER_ERROR {:?}", _e);
            }
            if response_code > 307 {
                error!("{}", log_msg);
            } else {
                info!("{}", log_msg);
            }
        }
    }

    #[derive(Clone, Debug)]
    struct SimpleHttpProxy {
        global_blacklist: Option<IpBlacklist>,
    }

    impl SimpleHttpProxy {
        pub fn new(global_blacklist: Option<IpBlacklist>) -> Self {
            SimpleHttpProxy { global_blacklist }
        }

        pub fn get_host(session: &Session) -> Option<&str> {
            if let Some(host_name) = session.req_header().uri.host() {
                return Some(host_name);
            }
            if let Some(host_name) = session.req_header().headers.get("Host") {
                return Some(host_name.to_str().unwrap());
            }
            None
        }
    }

    #[async_trait]
    impl ProxyHttp for SimpleHttpProxy {
        type CTX = HttpCtx;

        fn new_ctx(&self) -> Self::CTX {
            HttpCtx {
                server_name: None,
                cert_store: CertStore::new(),
                client_ip: String::new(),
                request_start: std::time::Instant::now(),
                request_size: 0,
                response_size: 0,
            }
        }

        async fn upstream_peer(
            &self,
            _session: &mut Session,
            _ctx: &mut Self::CTX,
        ) -> Result<Box<HttpPeer>> {
            info!("PEER");
            todo!()
        }

        async fn early_request_filter(
            &self,
            _session: &mut Session,
            ctx: &mut Self::CTX,
        ) -> Result<()>
        where
            Self::CTX: Send + Sync,
        {
            ctx.request_start = std::time::Instant::now();
            ctx.request_size = 0;
            ctx.response_size = 0;
            Ok(())
        }

        async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool>
        where
            Self::CTX: Send + Sync,
        {
            // Regardless of the host we check if it's letsencrypt challenge request
            if session
                .req_header()
                .uri
                .path()
                .starts_with("/.well-known/acme-challenge/")
            {
                let token = session.req_header().uri.path().split("/").last().unwrap();
                info!("token: {}", token);
                let token_path = PathBuf::from(acme_challenge_path()).join(token);
                return if token_path.exists() {
                    info!("Token Path found: [{}]", token_path.display());
                    let mut response_header = ResponseHeader::build(StatusCode::OK, None)?;
                    response_header
                        .insert_header(http::header::CONTENT_TYPE, "text/plain")
                        .expect("Failed to Insert Content-Type Header");
                    let token_content = fs::read_to_string(token_path).expect("Cannot read token");
                    info!("Token Content: [{}]", token_content);
                    session
                        .write_response_header(Box::new(response_header), false)
                        .await?;
                    session
                        .write_response_body(
                            Some(Bytes::copy_from_slice(token_content.as_bytes())),
                            true,
                        )
                        .await?;
                    Ok(true)
                } else {
                    info!("Token not found: [{}]", token_path.display());
                    session.respond_error(404).await?;
                    Ok(true)
                };
            }
            if let Some(host_name) = SimpleHttpProxy::get_host(session) {
                _ctx.server_name = Some(host_name.to_string().clone());

                if let Some(client_ip) = extract_client_ip(session) {
                    _ctx.client_ip = client_ip.to_string();
                    if let Some(blacklist_type) = blacklist_match(
                        &self.global_blacklist,
                        &_ctx.cert_store,
                        host_name,
                        client_ip,
                    ) {
                        METRICS.record_blacklist_block(host_name, blacklist_type);
                        info!(
                            "Blocked HTTP request from {} for host {} by {} blacklist",
                            client_ip,
                            host_name,
                            blacklist_type
                        );
                        session.respond_error(403).await?;
                        return Ok(true);
                    }
                }

                // Redirect to HTTPS all other requests
                let mut redirect_response_header =
                    ResponseHeader::build(StatusCode::TEMPORARY_REDIRECT, None)?;
                let uri = session
                    .req_header()
                    .uri
                    .path_and_query()
                    .map_or("/", |pq| pq.as_str());
                let location = format!("https://{}{}", host_name, uri);
                redirect_response_header.insert_header("Location", location.clone())?;
                redirect_response_header.insert_header("Content-Length", "0")?;
                session
                    .write_response_header(Box::new(redirect_response_header), true)
                    .await?;
                Ok(true)
            } else {
                info!("No host specified!");
                session.respond_error(404).await?;
                Ok(true)
            }
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

        async fn logging(&self, session: &mut Session, _e: Option<&Error>, _ctx: &mut Self::CTX)
        where
            Self::CTX: Send + Sync,
        {
            let response_code = session
                .response_written()
                .map_or(0, |resp| resp.status.as_u16());
            let duration = _ctx.request_start.elapsed().as_secs_f64();
            let host = _ctx.server_name.as_deref().unwrap_or("unknown");
            METRICS.record_request(response_code, host, duration, _ctx.request_size, _ctx.response_size);
            let log_msg = format!(
                "[{}] [{}] [{}] - [{}{}]",
                _ctx.client_ip,
                response_code,
                session.req_header().method,
                _ctx.server_name.as_deref().unwrap_or(""),
                session.req_header().uri.path_and_query().unwrap()
            );
            if response_code > 307 {
                error!("{}", log_msg);
                error!("{:?}", _e);
            } else {
                info!("{}", log_msg);
            }
        }
    }

    //noinspection DuplicatedCode
    pub fn start_server() {
        let global_blacklist = Config::new().global_blacklist;

        let mut pingora_server = Server::new(Opt::default()).unwrap();
        let mut conf = ServerConf::default();
        conf.upstream_keepalive_pool_size = 4096;
        conf.threads = 32;
        conf.work_stealing = true;
        pingora_server.configuration = conf.into();
        pingora_server.bootstrap();

        let http_port = std::env::var("MPROXY_HTTP_PORT")
            .unwrap_or(String::from("0"))
            .parse::<u16>()
            .unwrap();
        if http_port > 0 {
            info!("HTTP Enabled - Port: [{}]", &http_port);
            let http_proxy_app = SimpleHttpProxy::new(global_blacklist.clone());
            let mut http_proxy = http_proxy_service(&pingora_server.configuration, http_proxy_app);
            http_proxy.add_tcp(format!("0.0.0.0:{}", http_port).as_str());
            http_proxy.set_connection_filter(Arc::new(TcpConnectionTracker));
            pingora_server.add_service(http_proxy);
        } else {
            info!("No or Invalid HTTP Port Set - HTTP Disabled!");
        }

        let https_port = std::env::var("MPROXY_HTTPS_PORT")
            .unwrap_or(String::from("0"))
            .parse::<u16>()
            .unwrap();
        if https_port > 0 {
            info!("HTTPS Enabled - Port: [{}]", https_port);
            let tls_proxy_app = TlsProxyApp {
                global_blacklist: global_blacklist.clone(),
            };
            let cert_handler = CertHandler::new();

            let mut proxy = http_proxy_service(&pingora_server.configuration, tls_proxy_app);
            proxy.threads = Some(8);
            let mut downstream_modules = HttpModules::new();
            downstream_modules.add_module(ResponseCompressionBuilder::enable(6));
            proxy.app_logic_mut().unwrap().downstream_modules = downstream_modules;

            let mut tls_settings = TlsSettings::with_callbacks(cert_handler).unwrap();
            tls_settings
                .set_min_proto_version(Some(pingora::tls::ssl::SslVersion::TLS1_3))
                .unwrap();
            tls_settings.enable_h2();
            tls_settings.set_alpn(ALPN::H2H1);

            let mut sock_opt = TcpSocketOptions::default();
            sock_opt.tcp_keepalive = Some(TcpKeepalive {
                count: 32,
                idle: Duration::from_secs(60),
                interval: Duration::from_secs(30),
                #[cfg(target_os = "linux")]
                user_timeout: Duration::from_secs(0),
            });
            sock_opt.so_reuseport = Some(true);

            proxy.add_tls_with_settings(
                format!("0.0.0.0:{}", https_port).as_str(),
                Some(sock_opt),
                tls_settings,
            );
            proxy.set_connection_filter(Arc::new(TcpConnectionTracker));

            pingora_server.add_service(proxy);
        } else {
            info!("No or Invalid HTTPS Port Set - HTTPS Disabled!");
        }

        let s3_port = std::env::var("MPROXY_S3_PORT")
            .unwrap_or(String::from("0"))
            .parse::<u16>()
            .unwrap();
        if std::env::var("MPROXY_S3_ENABLED")
            .map(|s| s.to_lowercase() == "true")
            .unwrap_or(false)
            && s3_port > 0
        {
            info!("S3 Enabled");
            let s3_proxy_app = S3Proxy::new();
            let mut s3_proxy = http_proxy_service(&pingora_server.configuration, s3_proxy_app);
            s3_proxy.add_tcp(format!("0.0.0.0:{}", s3_port).as_str());
            s3_proxy.set_connection_filter(Arc::new(TcpConnectionTracker));
            pingora_server.add_service(s3_proxy);
        }

        pingora_server.run(RunArgs::default());
    }
}
