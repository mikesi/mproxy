# mproxy

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Build Status](https://github.com/user/mproxy/actions/workflows/rust.yml/badge.svg)](https://github.com/user/mproxy/actions)

A very Simple, high-performance, lightweight reverse proxy and TLS terminator written in Rust.

mproxy is designed to be a simple and efficient solution for terminating TLS traffic and proxying requests to backend services. It is built on top of the `pingora` library, which provides a fast and reliable foundation for building network services.

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Getting Started](#getting-started)
- [Configuration](#configuration)
- [Certificate Management](#certificate-management)
- [Systemd Service](#systemd-service)
- [RPM Packages](#rpm-packages)
- [Docker](#docker)
- [License](#license)

## Features

- **TLS Termination**: mproxy can terminate TLS traffic for multiple domains, using SNI to select the appropriate certificate.
- **Easy to Configure**: Simple configuration using a TOML file for hosts and environment variables for server settings.
- **Reverse Proxy**: It can proxy requests to multiple backend services based on the hostname.
- **Automatic Certificate Management**: mproxy includes a command-line tool for importing certificates from Let's Encrypt.
- **Docker Support**: Includes a `Dockerfile` for building and running as a container.
- **Systemd Integration**: It can be run as a systemd service for easy management.
- **RPM Packaging**: The project includes scripts for building RPM packages for easy deployment on RPM-based systems.
- **High Performance**: Built on `tokio` and `pingora`, mproxy is designed to be fast and efficient.
- **Automatic Compression**: Response compression is enabled by default for improved bandwidth efficiency.

## Architecture

The project is structured as a Cargo workspace with three crates:

- `mproxy`: The main application, which contains the reverse proxy and TLS termination logic.
- `cert_tool`: A command-line tool for managing TLS certificates.
- `mproxy_common`: A shared library that contains common code used by both `mproxy` and `cert_tool`.

## Getting Started

### Prerequisites

- Rust toolchain (latest stable version)
- OpenSSL development files

### Building

To build the project, clone the repository and run the following command:

```bash
cargo build --release
```

This will build both the `mproxy` and `cert_tool` binaries, which can be found in the `target/release` directory.

### Running

To run `mproxy`, you need to create a configuration file and a directory for certificates. By default, `mproxy` looks for its configuration at `/etc/mproxy/mproxy.env` and certificates in `/etc/mproxy/certs`.

## Configuration

`mproxy` is configured using a TOML file that specifies the hosts to proxy and their upstream addresses.

**Example `hosts.toml`:**

```toml
[[host_configs]]
host_name = "example.com"
aliases = ["www.example.com"]
upstream_address = "127.0.0.1:8080"

[[host_configs]]
host_name = "another-example.com"
upstream_address = "10.0.1.112:3000"
```

You also need to set the following environment variables:

- `MPROXY_HTTP_PORT`: The port to listen on for HTTP traffic (e.g., 80).
- `MPROXY_HTTPS_PORT`: The port to listen on for HTTPS traffic (e.g., 443).
- `MPROXY_HOSTS_CONFIG_PATH`: The path to the hosts configuration file (e.g., `/etc/mproxy/hosts.toml`).
- `MPROXY_CERT_PATH`: The path to the directory where certificates are stored (e.g., `/etc/mproxy/certs`).

These variables can be placed in a `.env` file or in the systemd environment file at `/etc/mproxy/mproxy.env`.

## Certificate Management

The `cert_tool` command-line utility is used to manage TLS certificates.

### Importing Certificates from Let's Encrypt

To import certificates from a Let's Encrypt directory, use the `import` command:

```bash
./target/release/cert_tool import --input-dir /etc/letsencrypt
```

This will scan the `/etc/letsencrypt/live` directory, parse the certificates, and save them in a format that `mproxy` can use in the directory specified by the `MPROXY_CERT_PATH` environment variable.

### Exporting Certificates

To export a certificate for a specific host, use the `export` command:

```bash
./target/release/cert_tool export --hostname example.com
```

This will print the certificate, private key, and other information for the specified host to the console.

## Systemd Service

The project includes a systemd service file for running `mproxy` as a service.

### Installation

You can use the provided installation script to automatically set up the systemd service:

```bash
sudo ./install-systemd.sh
```

This script will:
- Create the `mproxy` user and group.
- Set up the necessary directories with proper permissions.
- Install the systemd service file.
- Create a default environment configuration.

### Managing the Service

- **Enable the service to start on boot:**
  ```bash
  sudo systemctl enable mproxy
  ```
- **Start the service:**
  ```bash
  sudo systemctl start mproxy
  ```
- **Check the service status:**
  ```bash
  sudo systemctl status mproxy
  ```
- **View logs:**
  ```bash
  sudo journalctl -u mproxy -f
  ```

To uninstall the systemd service, run the `uninstall-systemd.sh` script.

## RPM Packages

This project supports building RPM packages for both the `mproxy` and `cert_tool` components.

### Prerequisites

- `rpmbuild`
- `cargo-rpm`

### Building RPMs

To build the RPM packages, run the provided build script:

```bash
./build-rpm.sh
```

The RPMs will be located in the `target/x86_64-unknown-linux-gnu/release/rpmbuild/RPMS/x86_64/` directory.

### Installing the RPMs

```bash
# Install mproxy (includes systemd service)
sudo rpm -ivh target/x86_64-unknown-linux-gnu/release/rpmbuild/RPMS/x86_64/mproxy-*.rpm

# Install cert-tool
sudo rpm -ivh target/x86_64-unknown-linux-gnu/release/rpmbuild/RPMS/x86_64/cert-tool-*.rpm
```

## Docker

`mproxy` can also be run as a Docker container.

### Building the Docker Image

To build the Docker image, run the following command from the project root:

```bash
docker build -t mproxy .
```

### Running the Docker Container

To run the `mproxy` container, you need to mount your configuration and certificate directories into the container and map the HTTP and HTTPS ports.

```bash
docker run -d \
  --name mproxy \
  -p 80:80 \
  -p 443:443 \
  -v /path/to/your/hosts.toml:/etc/mproxy/hosts.toml \
  -v /path/to/your/certs:/etc/mproxy/certs \
  mproxy
```

Make sure to replace `/path/to/your/hosts.toml` and `/path/to/your/certs` with the actual paths to your configuration file and certificate directory.

The container uses the `dist.env` file for default environment variables. You can override these using the `-e` flag in the `docker run` command. For example, to change the ports:

```bash
docker run -d \
  --name mproxy \
  -p 8080:8080 \
  -p 8443:8443 \
  -e MPROXY_HTTP_PORT=8080 \
  -e MPROXY_HTTPS_PORT=8443 \
  -v /path/to/your/hosts.toml:/etc/mproxy/hosts.toml \
  -v /path/to/your/certs:/etc/mproxy/certs \
  mproxy
```

## License

This project is licensed under the Apache License, Version 2.0.
See the [LICENSE](LICENSE) file or <https://www.apache.org/licenses/LICENSE-2.0> for details.

## TODO

- **Per-host logging**
  - Structured logs with host-context (e.g., host, alias, upstream, request id, client ip, status, latency).
  - Optional per-host log routing/filenames and log level overrides via config (e.g., fields in `hosts.toml`).
  - Consider JSON output for easy ingestion by log processors.

- **Let's Encrypt HTTP-01 renewal**
  - Built-in ACME HTTP-01 challenge responder on the HTTP listener.
  - Automated certificate issuance and renewal workflow, writing results to `MPROXY_CERT_PATH`.
  - Safe reload of in-memory cert map on successful renewals without downtime.
