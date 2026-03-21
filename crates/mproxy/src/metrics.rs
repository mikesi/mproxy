use std::sync::LazyLock;
use prometheus::{Counter, CounterVec, Gauge, GaugeVec, Histogram, HistogramOpts, Opts, Registry};

pub struct ProxyMetrics {
    pub registry: Registry,
    pub total_requests: Counter,
    pub requests_by_status: CounterVec,
    pub requests_by_host: CounterVec,
    pub bytes_in: Counter,
    pub bytes_out: Counter,
    pub request_duration: Histogram,
    pub active_connections: Gauge,
    pub build_info: GaugeVec,
    pub uptime_seconds: Counter,
}

impl ProxyMetrics {
    pub fn new() -> Self {
        let registry = Registry::new();

        let total_requests = Counter::new(
            "mproxy_requests_total",
            "Total number of requests",
        ).unwrap();

        let requests_by_status = CounterVec::new(
            Opts::new("mproxy_requests_by_status", "Requests by status code"),
            &["status_code"],
        ).unwrap();

        let requests_by_host = CounterVec::new(
            Opts::new("mproxy_requests_by_host", "Requests by host"),
            &["host"],
        ).unwrap();

        let bytes_in = Counter::new(
            "mproxy_bytes_in_total",
            "Total bytes received from clients",
        ).unwrap();

        let bytes_out = Counter::new(
            "mproxy_bytes_out_total",
            "Total bytes sent to clients",
        ).unwrap();

        let request_duration = Histogram::with_opts(
            HistogramOpts::new("mproxy_request_duration_seconds", "Request duration in seconds")
                .buckets(vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]),
        ).unwrap();

        let active_connections = Gauge::new(
            "mproxy_active_connections",
            "Current number of active connections",
        ).unwrap();

        let build_info = GaugeVec::new(
            Opts::new("mproxy_build_info", "Build information"),
            &["version", "build_date", "profile"],
        ).unwrap();

        let uptime_seconds = Counter::new(
            "mproxy_uptime_seconds_total",
            "Total uptime in seconds",
        ).unwrap();

        registry.register(Box::new(total_requests.clone())).unwrap();
        registry.register(Box::new(requests_by_status.clone())).unwrap();
        registry.register(Box::new(requests_by_host.clone())).unwrap();
        registry.register(Box::new(bytes_in.clone())).unwrap();
        registry.register(Box::new(bytes_out.clone())).unwrap();
        registry.register(Box::new(request_duration.clone())).unwrap();
        registry.register(Box::new(active_connections.clone())).unwrap();
        registry.register(Box::new(build_info.clone())).unwrap();
        registry.register(Box::new(uptime_seconds.clone())).unwrap();

        Self {
            registry,
            total_requests,
            requests_by_status,
            requests_by_host,
            bytes_in,
            bytes_out,
            request_duration,
            active_connections,
            build_info,
            uptime_seconds,
        }
    }

    pub fn set_build_info(&self) {
        self.build_info
            .with_label_values(&[env!("CARGO_PKG_VERSION"), env!("BUILD_DATE"), env!("PROFILE")])
            .set(1.0);
    }

    pub fn record_request(&self, status_code: u16, host: &str, duration_secs: f64, bytes_in: u64, bytes_out: u64) {
        self.total_requests.inc();
        self.requests_by_status.with_label_values(&[&status_code.to_string()]).inc();
        self.requests_by_host.with_label_values(&[host]).inc();
        self.request_duration.observe(duration_secs);
        self.bytes_in.inc_by(bytes_in as f64);
        self.bytes_out.inc_by(bytes_out as f64);
    }

    pub fn increment_active_connections(&self) {
        self.active_connections.inc();
    }

    pub fn decrement_active_connections(&self) {
        self.active_connections.dec();
    }

    pub fn increment_uptime(&self, seconds: u64) {
        self.uptime_seconds.inc_by(seconds as f64);
    }

}

// Global METRICS instance
pub static METRICS: LazyLock<ProxyMetrics> = LazyLock::new(ProxyMetrics::new);
