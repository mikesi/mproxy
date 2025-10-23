# MProxy Systemd Setup Guide

## Quick Start

### Using Installation Script (Recommended)

```bash
sudo ./install-systemd.sh
sudo systemctl enable --now mproxy
```

### Verify Installation

```bash
systemctl status mproxy
journalctl -u mproxy -f
```

## Configuration

Edit `/etc/mproxy/mproxy.env` to configure mproxy:

```bash
MPROXY_HTTPS_PORT=443
MPROXY_HTTP_PORT=80
MPROXY_API_PORT=3008
MPROXY_DATA_PATH=/var/lib/mproxy/data
MPROXY_HOSTS_CONFIG_PATH=/etc/mproxy/hosts.toml
```

After configuration changes:

```bash
sudo systemctl restart mproxy
```

## RPM Installation

When installing via RPM, systemd integration is automatic:

```bash
sudo rpm -ivh target/x86_64-unknown-linux-gnu/release/rpmbuild/RPMS/x86_64/mproxy-*.rpm
sudo systemctl enable --now mproxy
```

The RPM automatically:
- Creates the `mproxy` user and group
- Installs the systemd service file
- Creates configuration directories
- Sets up proper permissions

## Files Installed

- **Binary**: `/usr/bin/mproxy`
- **Service File**: `/usr/lib/systemd/system/mproxy.service`
- **Config**: `/etc/mproxy/mproxy.env`
- **Data Directory**: `/var/lib/mproxy/data`

## Security Features

The systemd service includes security hardening:
- Runs as dedicated `mproxy` user
- Capability-based privilege management (CAP_NET_BIND_SERVICE)
- Protected system directories
- Private tmp directory
- No new privileges allowed

## Troubleshooting

### Check Service Status
```bash
systemctl status mproxy
```

### View Logs
```bash
journalctl -u mproxy -n 100 --no-pager
```

### Check Configuration
```bash
cat /etc/mproxy/mproxy.env
```

### Restart Service
```bash
sudo systemctl restart mproxy
```

### Disable Service
```bash
sudo systemctl stop mproxy
sudo systemctl disable mproxy
```

## Uninstallation

### Manual Uninstall
```bash
sudo ./uninstall-systemd.sh
```

### Complete Removal
```bash
sudo ./uninstall-systemd.sh
sudo rm -rf /etc/mproxy
sudo rm -rf /var/lib/mproxy
sudo userdel mproxy
```

### RPM Uninstall
```bash
sudo rpm -e mproxy
```
