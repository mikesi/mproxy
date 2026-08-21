# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project Overview

**mproxy** is a high-performance reverse proxy and TLS terminator written in Rust, built on [pingora](https://github.com/cloudflare/pingora). It terminates TLS (SNI-based certificate selection), reverse-proxies HTTP to backends, can forward raw TCP, manages Let's Encrypt certificates, and supports client IP blacklisting (global + per-host).

## Workspace Layout

Cargo workspace (Rust edition 2024) with three crates:

| Crate | Path | Purpose |
|---|---|---|
| `mproxy` | `crates/mproxy` | Main binary: proxy server, TLS termination, TCP forwarder, cert hot-reload, admin endpoints, metrics |
| `cert_tool` | `crates/cert_tool` | CLI for certificate management (`import`, `cert-new`, `export`) and ACME/Let's Encrypt issuance |
| `mproxy_common` | `crates/mproxy_common` | Shared library: config (`config.rs`), host config (`host_config.rs`), certificates, IP blacklist, Let's Encrypt helpers |

Other key locations:

- `systemd/` — service files (`mproxy.service`, cert-renew timer, ipblocklist-update timer) and `mproxy.env.example`
- `monitoring/` — Prometheus/Grafana docker-compose stack
- `.github/workflows/rust.yml` — CI: `cargo build --release --workspace` + `cargo test --workspace` (installs `libssl-dev`, `pkg-config`)
- `build-rpm.sh` — RPM packaging (needs `rpmbuild`, `cargo-rpm`)
- `install-systemd.sh` / `uninstall-systemd.sh` — systemd setup
- `data` — symlink to runtime data dir on this machine (contains `acme-challenge/` etc.); do not commit real data
- `dist.env` — default env vars baked into Docker image

## Build & Test Commands

```bash
# Build (both mproxy + cert_tool binaries -> target/release/)
cargo build --release

# Build a single crate
cargo build --release -p mproxy

# Tests (run these after changes; CI runs the workspace level)
cargo test --workspace
cargo test -p mproxy_common        # e.g. ip_blacklist, host_config, config tests

# Lint
cargo clippy --workspace

# Run locally (requires env vars; see below)
cargo run -p mproxy
```

Prerequisites: Rust stable toolchain, OpenSSL dev files (`libssl-dev`, `pkg-config` on Linux) — the `openssl` crate is vendored via workspace dependency.

## Configuration & Environment

mproxy is configured via a TOML hosts file + environment variables (see `README.md` for the full reference and `systemd/mproxy.env.example` for defaults):

- `MPROXY_HTTP_PORT` (e.g. 80), `MPROXY_HTTPS_PORT` (e.g. 443)
- `MPROXY_HOSTS_CONFIG_PATH` — path to `hosts.toml`
- `MPROXY_CERT_PATH` — certificate directory
- `MPROXY_DATA_PATH` — runtime data dir (ACME challenge files live at `$MPROXY_DATA_PATH/acme-challenge/`)
- `MPROXY_GLOBAL_BLACKLIST_IPS` — comma-separated IPs/CIDRs

`hosts.toml` entries (`[[host_configs]]`) support: `host_name`, `aliases`, `upstream_address`, `blacklisted_ips`, `mode` (`"http"` default | `"tcp"` | `"both"`), `tcp_forward_port`.

Env vars are loaded via `dotenv` (plus `/etc/mproxy/mproxy.env` on the host) — when changing which env vars are read, check `mproxy_common/src/config.rs` and `cert_tool/src/main.rs` (which calls `dotenv()` and loads `/etc/mproxy/mproxy.env`).

## Key Behaviors to Preserve

- **ACME HTTP-01 flow**: `cert_tool cert-new` writes token/proof files to `$MPROXY_DATA_PATH/acme-challenge/`; mproxy's HTTP listener serves `/.well-known/acme-challenge/<token>` from that directory and redirects all other HTTP paths to HTTPS. Keep both sides in sync when touching either.
- **TCP forwarding**: `mode = "tcp"` does not load a certificate; `mode = "both"` loads the cert *and* opens the raw TCP listen port.
- **IP blacklisting**: global (`MPROXY_GLOBAL_BLACKLIST_IPS`) and per-host (`blacklisted_ips`); matches return `403`. Parsing lives in `mproxy_common/src/ip_blacklist.rs` with unit tests — extend tests when changing parse semantics.
- **Certificate reload**: mproxy can reload the in-memory SNI cert map from `MPROXY_CERT_PATH` without downtime via the admin endpoint `POST /admin/reload-certs` (see `admin_endpoints.rs`, `cert_store.rs`). It does not auto-watch the cert directory.

## Conventions

- Errors: use `anyhow` for binary/CLI code; workspace deps are centralized in the root `Cargo.toml` `[workspace.dependencies]` — add new deps there first.
- Logging: `tracing` (not `println!`).
- CLI: `clap` with derive (see `cert_tool/src/main.rs`).
- Clippy lints are configured in root `Cargo.toml` `[workspace.lints.clippy]` (style allowed, `too_many_arguments` allowed). Don't add per-crate overrides without reason.
- Follow the existing module layout; shared logic between mproxy and cert_tool belongs in `mproxy_common`.

## Operational Context (local machine)

- This repo is deployed via systemd (`sudo systemctl status mproxy`) and/or RPM on this host; scripts like `renew-certs-and-restart-mproxy.sh`, `update-inbound-blocklist.sh` are operational helpers, not part of CI.
- `.env` at repo root is local-only (gitignored); real config lives under `/etc/mproxy/` on the host.
- `README.md` is the user-facing doc — keep it in sync when changing config schema, env vars, modes, or CLI commands.

## What NOT To Do

- Don't commit secrets, certificates, or `.env` contents.
- Don't change the ACME challenge path contract (`/.well-known/acme-challenge/<token>`) without updating both `mproxy` and `cert_tool`.
- Don't break the `cargo test --workspace` / `cargo build --release --workspace` CI job.
