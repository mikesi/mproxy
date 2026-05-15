#!/bin/bash

# MProxy Systemd Installation Script
# This script installs mproxy as a systemd service

set -e

INSTALL_INBOUND_BLOCKLIST=0

usage() {
    cat <<EOF
Usage: sudo ./install-systemd.sh [options]

Options:
  --with-inbound-blocklist     Install and enable nftables inbound blocklist updater
  --without-inbound-blocklist  Do not install inbound blocklist updater (default)
  -h, --help                   Show this help message
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --with-inbound-blocklist)
            INSTALL_INBOUND_BLOCKLIST=1
            ;;
        --without-inbound-blocklist)
            INSTALL_INBOUND_BLOCKLIST=0
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
    shift
done

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root or with sudo"
    exit 1
fi

echo "Installing MProxy systemd service..."

# Create mproxy user if it doesn't exist
if ! id -u mproxy >/dev/null 2>&1; then
    echo "Creating mproxy user..."
    useradd -r -s /bin/false -d /var/lib/mproxy -c "MProxy service account" mproxy
else
    echo "User mproxy already exists"
fi

# Create necessary directories
echo "Creating directories..."
mkdir -p /var/lib/mproxy/data
mkdir -p /etc/mproxy

# Set ownership
chown -R mproxy:mproxy /var/lib/mproxy

# Copy environment configuration
if [ ! -f /etc/mproxy/mproxy.env ]; then
    echo "Installing environment configuration..."
    cp systemd/mproxy.env.example /etc/mproxy/mproxy.env
    chmod 600 /etc/mproxy/mproxy.env
    echo "Environment file created at /etc/mproxy/mproxy.env"
    echo "Please edit this file to match your configuration"
else
    echo "Environment file already exists at /etc/mproxy/mproxy.env"
fi

# Install systemd service file
echo "Installing systemd service file..."
cp systemd/mproxy.service /etc/systemd/system/
chmod 644 /etc/systemd/system/mproxy.service

# Install certificate renewal script
echo "Installing certificate renewal script..."
cp renew-certs-and-restart-mproxy.sh /usr/local/sbin/renew-certs-and-restart-mproxy.sh
chmod 755 /usr/local/sbin/renew-certs-and-restart-mproxy.sh

# Install systemd timer/service for certificate renewal
echo "Installing certificate renewal systemd units..."
cp systemd/mproxy-cert-renew.service /etc/systemd/system/
cp systemd/mproxy-cert-renew.timer /etc/systemd/system/
chmod 644 /etc/systemd/system/mproxy-cert-renew.service
chmod 644 /etc/systemd/system/mproxy-cert-renew.timer

if [ "$INSTALL_INBOUND_BLOCKLIST" -eq 1 ]; then
    echo "Installing inbound ip blocklist updater script..."
    cp update-inbound-blocklist.sh /usr/local/sbin/update-inbound-blocklist.sh
    chmod 755 /usr/local/sbin/update-inbound-blocklist.sh

    echo "Installing inbound ip blocklist clear script..."
    cp clear-inbound-blocklist.sh /usr/local/sbin/clear-inbound-blocklist.sh
    chmod 755 /usr/local/sbin/clear-inbound-blocklist.sh

    echo "Installing inbound ip blocklist updater systemd units..."
    cp systemd/mproxy-ipblocklist-update.service /etc/systemd/system/
    cp systemd/mproxy-ipblocklist-update.timer /etc/systemd/system/
    chmod 644 /etc/systemd/system/mproxy-ipblocklist-update.service
    chmod 644 /etc/systemd/system/mproxy-ipblocklist-update.timer
else
    echo "Skipping inbound ip blocklist installation (default). Use --with-inbound-blocklist to enable it."
fi

# Reload systemd
echo "Reloading systemd daemon..."
systemctl daemon-reload

echo "Enabling certificate renewal timer..."
systemctl enable --now mproxy-cert-renew.timer

if [ "$INSTALL_INBOUND_BLOCKLIST" -eq 1 ]; then
    echo "Running initial inbound ip blocklist update..."
    if ! /usr/local/sbin/update-inbound-blocklist.sh; then
        echo "Warning: initial inbound blocklist update failed. Check network, nftables, and mproxy.env settings."
    fi

    echo "Enabling inbound ip blocklist update timer..."
    systemctl enable --now mproxy-ipblocklist-update.timer
fi

echo ""
echo "Installation complete!"
echo ""
echo "Next steps:"
echo "1. Edit /etc/mproxy/mproxy.env to configure mproxy"
echo "2. Enable the service: sudo systemctl enable mproxy"
echo "3. Start the service: sudo systemctl start mproxy"
echo "4. Check status: sudo systemctl status mproxy"
echo "5. View logs: sudo journalctl -u mproxy -f"
