#!/bin/bash

# MProxy Systemd Installation Script
# This script installs mproxy as a systemd service

set -e

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

# Reload systemd
echo "Reloading systemd daemon..."
systemctl daemon-reload

echo ""
echo "Installation complete!"
echo ""
echo "Next steps:"
echo "1. Edit /etc/mproxy/mproxy.env to configure mproxy"
echo "2. Enable the service: sudo systemctl enable mproxy"
echo "3. Start the service: sudo systemctl start mproxy"
echo "4. Check status: sudo systemctl status mproxy"
echo "5. View logs: sudo journalctl -u mproxy -f"
