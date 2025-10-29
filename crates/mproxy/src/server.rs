pub mod server {
    use async_trait::async_trait;
    use log::error;
    use mproxy_common::{acme_challenge_path, cert_path, data_path};
    use mproxy_common::certificates::Certificate;
    use mproxy_common::host_config::{HostConfig, HostConfigList, HostsConfigLoader};
    use pingora::http::{ResponseHeader, StatusCode};
    use pingora::listeners::tls::TlsSettings;
    use pingora::listeners::{TcpSocketOptions, ALPN};
    use pingora::modules::http::compression::ResponseCompressionBuilder;
    use pingora::modules::http::HttpModules;
    use pingora::prelude::*;
    use pingora::protocols::tls::TlsRef;
    use pingora::protocols::TcpKeepalive;
    use pingora::server::configuration::ServerConf;
    use pingora::server::RunArgs;
    use pingora::tls::pkey::PKey;
    use pingora::tls::ssl::NameType;
    use pingora::tls::x509::X509;
    use pingora::upstreams::peer::PeerOptions;
    use pingora::ErrorSource::Upstream;
    use std::collections::HashMap;
    use std::fmt::{Debug, Formatter};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{LazyLock, Mutex};
    use std::time::Duration;
    use tracing::info;
    use bytes::Bytes;

    // This is a Global Certificate Map that is used by the CertHandler
    static CERT_MAP: LazyLock<Mutex<HashMap<String, Option<Certificate>>>> = LazyLock::new(|| {
        info!("CERT_MAP Init");
        Mutex::new(HashMap::new())
    });

    #[derive(Debug)]
    pub struct CertStore {
        host_config_loader: Option<HostsConfigLoader>,
    }


    // Manage the Certificates
    impl CertStore {
        pub fn new() -> Self {
            Self {
                host_config_loader: None,
            }
        }

        pub fn refresh_hosts(&mut self) {
            if let Some(host_config_loader) = &mut self.host_config_loader {
                host_config_loader.refresh_hosts_config();
            }
        }
        pub fn set_host_config_loader(&mut self, host_config_loader: HostsConfigLoader) {
            self.host_config_loader = Some(host_config_loader.into());
        }

        pub fn load_certs_from_host_config_list(&self, host_config_list: &HostConfigList) {
            host_config_list.host_configs.iter().for_each(|host_config| {
                self.host_config_to_cert(host_config);
            });
        }

        fn host_config_to_cert(&self, host_config: &HostConfig) {
            let mut map = CERT_MAP.lock().unwrap();
            let cert_path = PathBuf::from(cert_path())
                .join(cert_path())
                .join(host_config.host_name.clone())
                .join("cert.json");
            let mut cert = Some(Certificate::from_path(cert_path));
            cert.as_mut().unwrap().host_config = Some(host_config.clone());
            map.insert(host_config.host_name.clone(), cert.clone());
            if let Some(aliases) = &host_config.aliases {
                for alias in aliases {
                    map.insert(alias.clone(), cert.clone());
                }
            }
        }

        pub fn set_cert(&self, server_name: &str, cert: Certificate) {
            let mut map = CERT_MAP.lock().unwrap();
            map.insert(server_name.to_string(), Some(cert.clone()));
        }

        pub fn get_cert(&self, server_name: &str) -> Option<Certificate> {
            let map = CERT_MAP.lock().unwrap();
            match map.get(server_name) {
                Some(cert) => cert.to_owned(),
                None => None,
            }
        }

        fn extract_last_cert(pem_chain: &str) -> Option<&str> {
            let begin_marker = "-----BEGIN CERTIFICATE-----";
            let end_marker = "-----END CERTIFICATE-----";
            let mut last_pos = 0;
            while let Some(begin) = pem_chain[last_pos..].find(begin_marker) {
                let begin = last_pos + begin;
                let end = pem_chain[begin..].find(end_marker)?;
                last_pos = begin + end + end_marker.len();
            }
            // Get the last certificate block if it exists
            if last_pos > 0 {
                let begin = pem_chain[..last_pos].rfind(begin_marker)?;
                let end = pem_chain[begin..].find(end_marker)? + end_marker.len() + begin;
                return Some(&pem_chain[begin..end]);
            }
            None
        }
    }

    #[derive(Clone, Debug)]
    pub struct TlsProxyApp {}

    struct CertHandler {
        pub cert_store: CertStore,
    }

    impl Debug for CertHandler {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(f, "CertHandler")
        }
    }

    impl CertHandler {
        pub fn new() -> Box<Self> {
            Box::from(CertHandler {
                cert_store: CertStore::new(),
            })
        }

        pub fn find_cert(&self, server_name: &str) -> Option<Certificate> {
            self.cert_store.get_cert(server_name)
        }
    }

    #[async_trait]
    impl pingora::listeners::TlsAccept for CertHandler {
        async fn certificate_callback(&self, _ssl: &mut TlsRef) -> () {
            // Store the servername in an owned String to avoid borrowing _ssl
            let servername = _ssl.servername(NameType::HOST_NAME).map(|s| s.to_string());
            match servername {
                Some(servername) => {
                    if let Some(certificate) = self.find_cert(&servername) {
                        if let Some(cert_fullchain) = certificate.full_chain {
                            match X509::from_pem(cert_fullchain.as_bytes()) {
                                Ok(cert) => {
                                    _ssl.set_certificate(&cert).unwrap();
                                    _ssl.add_chain_cert(cert).unwrap();
                                }
                                Err(e) => {
                                    error!("Error loading cert: {}", e);
                                }
                            };
                        } else {
                            error!("No full chain for: [{}]", servername);
                            return;
                        }

                        if let Some(intermediate_cert) = &*certificate.parsed_inter_cert.borrow() {
                            match X509::from_pem(intermediate_cert) {
                                Ok(cert) => {
                                    _ssl.add_chain_cert(cert).unwrap();
                                }
                                Err(e) => {
                                    error!("Error loading intermediate cert: {}", e);
                                    return;
                                }
                            };
                        }

                        if let Some(key_pem) = certificate.private_key_pem {
                            let loaded_key = match PKey::private_key_from_pem(key_pem.as_bytes()) {
                                Ok(key) => key,
                                Err(e) => {
                                    error!("Error loading key: {}", e);
                                    return;
                                }
                            };
                            _ssl.set_private_key(&loaded_key).unwrap();
                        } else {
                            error!("No private key for: [{}]", servername);
                            return;
                        }

                    } else {
                        // NO CERT for HOSTNAME found
                        error!("No Certificate for: [{}]", servername);
                        return;
                    }
                }
                _ => {
                    error!("No Server Hostname set");
                }
            };
            // todo!()
        }
    }

    #[derive(Debug)]
    pub struct HttpCtx {
        server_name: Option<String>,
        cert_store: CertStore,
        client_ip: String,
    }

    #[async_trait]
    impl ProxyHttp for TlsProxyApp {
        type CTX = HttpCtx;

        fn new_ctx(&self) -> Self::CTX {
            HttpCtx {
                server_name: None,
                cert_store: CertStore::new(),
                client_ip: String::new(),
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
                    peer_options.extra_proxy_headers.insert("X-Forwarded-Proto".to_string(), "https".as_bytes().to_vec());
                    peer_options.extra_proxy_headers.insert("X-Forwarded-For".to_string(), peer._address.to_string().as_bytes().to_vec());
                    peer.options = peer_options;
                    Ok(Box::new(peer))
                }
            }
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

            Ok(())
        }

        async fn upstream_request_filter(&self, _session: &mut Session, _upstream_request: &mut RequestHeader, _ctx: &mut Self::CTX) -> Result<()>
        where
          Self::CTX: Send + Sync,
        {
            _upstream_request.insert_header("X-Forwarded-Proto", "https").expect("TODO: panic message");
            _upstream_request.insert_header("X-Forwarded-Scheme", "https").expect("TODO: panic message");
            if let Some(ip_str) = _session.client_addr().and_then(|addr| addr.as_inet().map(|addr| addr.ip().to_string())) {
                _ctx.client_ip = ip_str.clone();
                _upstream_request.insert_header("X-Real-IP",ip_str).expect("Cannot add X-Real-IP");
            }
            // Replace Cookies with Compressed cookies
            let parsed_cookies: Vec<&str> = _upstream_request.as_ref().headers.get_all(http::header::COOKIE).iter().map(|x| { x.to_str().unwrap()}).collect();
            let compressed_cookies = parsed_cookies.join("; ");
            _upstream_request.insert_header("Cookie", compressed_cookies).expect("Failed replace/add Cookies");
            Ok(())
        }

        async fn logging(&self, session: &mut Session, _e: Option<&Error>, _ctx: &mut Self::CTX) {
            let response_code = session
              .response_written()
              .map_or(0, |resp| resp.status.as_u16());
            let log_msg = format!("[{}] [{}] [{}] - [{}{}]", _ctx.client_ip,
                                  response_code.to_string(),
                                  session.req_header().method.to_string(),
                                  _ctx.server_name.as_deref().unwrap_or(""),
                                  session.req_header().uri.path_and_query().unwrap().to_string());
            // Log only global errors here
            if response_code > 204 {
                error!("{}", log_msg);
            } else {
                // info!("{}", log_msg);
            }
        }
    }

    #[derive(Clone, Debug)]
    struct SimpleHttpProxy {}

    impl SimpleHttpProxy {
        pub fn new() -> Self {
            SimpleHttpProxy {}
        }

        pub fn get_host(session: &Session) -> Option<&str> {
            if let Some(host_name) = session.req_header().uri.host() {
                return Some(host_name)
            }
            if let Some(host_name) = session.req_header().headers.get("Host") {
                return Some(host_name.to_str().unwrap())
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
            }
        }

        async fn upstream_peer(
            &self,
            _session: &mut Session,
            ctx: &mut Self::CTX,
        ) -> Result<Box<HttpPeer>> {
            info!("PEER");
            todo!()
        }


        async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool>
        where
          Self::CTX: Send + Sync,
        {
            // Regardless of the host we check if it's letsencrypt challenge request
            if session.req_header().uri.path().starts_with("/.well-known/acme-challenge/") {
                let token = session.req_header().uri.path().split("/").last().unwrap();
                info!("token: {}",token);
                let token_path = PathBuf::from(acme_challenge_path()).join(token);
                return if token_path.exists() {
                    info!("Token Path found: [{}]",token_path.display());
                    let mut response_header = ResponseHeader::build(StatusCode::OK, None)?;
                    response_header.insert_header(http::header::CONTENT_TYPE, "text/plain").expect("Failed to Insert Content-Type Header");
                    let token_content = fs::read_to_string(token_path).expect("Cannot read token");
                    info!("Token Content: [{}]",token_content);
                    session.write_response_header(Box::new(response_header), false).await?;
                    session.write_response_body(Some(Bytes::copy_from_slice(token_content.as_bytes())), true).await?;
                    Ok(true)
                } else {
                    info!("Token not found: [{}]",token_path.display());
                    session.respond_error(404).await?;
                    Ok(true)
                }
            }
            if let Some(host_name) = SimpleHttpProxy::get_host(session) {
                _ctx.server_name = Some(host_name.to_string().clone());
                // Redirect to HTTPS all other requests
                let mut redirect_response_header = ResponseHeader::build(StatusCode::TEMPORARY_REDIRECT, None)?;
                let uri = session.req_header().uri.path_and_query().map_or("/", |pq| pq.as_str());
                let location = format!("https://{}{}", host_name, uri);
                redirect_response_header.insert_header("Location", location.clone())?;
                redirect_response_header.insert_header("Content-Length", "0")?;
                session.write_response_header(Box::new(redirect_response_header), true).await?;
                return Ok(true);
            } else {
                info!("No host specified!");
                session.respond_error(404).await?;
                return Ok(true);
            }
        }

        async fn logging(&self, session: &mut Session, _e: Option<&Error>, _ctx: &mut Self::CTX)
        where
          Self::CTX: Send + Sync,
        {
            let response_code = session
              .response_written()
              .map_or(0, |resp| resp.status.as_u16());
            let log_msg = format!("[{}] [{}] [{}] - [{}{}]", _ctx.client_ip,
                                  response_code.to_string(),
                                  session.req_header().method.to_string(),
                                  _ctx.server_name.as_deref().unwrap_or(""),
                                  session.req_header().uri.path_and_query().unwrap().to_string());
            info!("{:?}", _e);
            // Log only global errors here
            if response_code > 204 {
                info!("{}", log_msg);
            } else {
                info!("{}", log_msg);
            }
        }
    }

    //noinspection DuplicatedCode
    pub fn start_server() {
        let mut pingora_server = Server::new(Opt::default()).unwrap();
        let mut conf = ServerConf::default();
        conf.upstream_keepalive_pool_size = 4096;
        conf.threads = 32;
        conf.work_stealing  = true;
        pingora_server.configuration = conf.into();
        pingora_server.bootstrap();

        let http_port = std::env::var("MPROXY_HTTP_PORT").unwrap_or(String::new()).parse::<u16>().unwrap();
        if http_port > 0 {
            info!("HTTP Enabled - Port: [{}]",&http_port);
            let http_proxy_app = SimpleHttpProxy::new();
            let mut http_proxy = http_proxy_service(&pingora_server.configuration, http_proxy_app);
            http_proxy.add_tcp(
                format!(
                    "0.0.0.0:{}",
                    http_port
                )
                  .as_str(),
            );
            pingora_server.add_service(http_proxy);
        } else {
            info!("No or Invalid HTTP Port Set - HTTP Disabled!");
        }

        let https_port = std::env::var("MPROXY_HTTPS_PORT").unwrap_or(String::new()).parse::<u16>().unwrap();
        if https_port > 0 {
            info!("HTTPS Enabled - Port: [{}]",https_port);
            let tls_proxy_app = TlsProxyApp {};
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

            proxy.add_tls_with_settings(format!("0.0.0.0:{}",https_port).as_str(), Some(sock_opt),tls_settings);

            pingora_server.add_service(proxy);
        } else {
            info!("No or Invalid HTTPS Port Set - HTTPS Disabled!");
        }

        pingora_server.run(RunArgs::default());
    }
}
