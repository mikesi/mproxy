# MProxy Systemd Setup Guide

## Quick Start

### Using Installation Script (Recommended)

```bash
sudo ./install-systemd.sh
sudo systemctl enable --now mproxy
```

To also install and enable nftables inbound blocklist automation:

```bash
sudo ./install-systemd.sh --with-inbound-blocklist
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

## Inbound IP Blocklist Automation (nftables)

Inbound blocklist automation is optional and is installed only when using `--with-inbound-blocklist`.
It loads the inbound list into nftables sets and drops matching sources before requests reach mproxy.

Installed units:
- `mproxy-ipblocklist-update.service`
- `mproxy-ipblocklist-update.timer` (runs every 2 hours)

Useful commands:

```bash
# Run one update now
sudo systemctl start mproxy-ipblocklist-update.service

# Clear inbound blocklist entries (keeps nftables rules/sets)
sudo /usr/local/sbin/clear-inbound-blocklist.sh

# Check timer status
systemctl status mproxy-ipblocklist-update.timer

# View updater logs
journalctl -u mproxy-ipblocklist-update.service -n 100 --no-pager
```

Related environment variables in `/etc/mproxy/mproxy.env`:

```bash
MPROXY_INBOUND_BLOCKLIST_URL=https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/inbound.txt
MPROXY_NFT_FAMILY=inet
MPROXY_NFT_TABLE=mproxy
MPROXY_NFT_CHAIN=input
MPROXY_NFT_SET_V4=inbound_v4
MPROXY_NFT_SET_V6=inbound_v6
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
