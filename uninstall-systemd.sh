#!/bin/bash

# MProxy Systemd Uninstallation Script
# This script removes mproxy systemd service

set -e

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root or with sudo"
    exit 1
fi

echo "Uninstalling MProxy systemd service..."

# Stop/disable cert renew timer if present
if systemctl is-active --quiet mproxy-cert-renew.timer 2>/dev/null; then
    echo "Stopping mproxy-cert-renew timer..."
    systemctl stop mproxy-cert-renew.timer
fi

if systemctl is-enabled --quiet mproxy-cert-renew.timer 2>/dev/null; then
    echo "Disabling mproxy-cert-renew timer..."
    systemctl disable mproxy-cert-renew.timer
fi

if systemctl is-active --quiet mproxy-cert-renew.service 2>/dev/null; then
    echo "Stopping mproxy-cert-renew service..."
    systemctl stop mproxy-cert-renew.service
fi

# Stop the service if it's running
if systemctl is-active --quiet mproxy; then
    echo "Stopping mproxy service..."
    systemctl stop mproxy
fi

# Disable the service if it's enabled
if systemctl is-enabled --quiet mproxy 2>/dev/null; then
    echo "Disabling mproxy service..."
    systemctl disable mproxy
fi

# Remove systemd service file
if [ -f /etc/systemd/system/mproxy.service ]; then
    echo "Removing systemd service file..."
    rm /etc/systemd/system/mproxy.service
fi

# Remove cert renew systemd unit files
if [ -f /etc/systemd/system/mproxy-cert-renew.timer ]; then
    echo "Removing mproxy-cert-renew timer file..."
    rm /etc/systemd/system/mproxy-cert-renew.timer
fi

if [ -f /etc/systemd/system/mproxy-cert-renew.service ]; then
    echo "Removing mproxy-cert-renew service file..."
    rm /etc/systemd/system/mproxy-cert-renew.service
fi

# Remove installed certificate renewal script
if [ -f /usr/local/sbin/renew-certs-and-restart-mproxy.sh ]; then
    echo "Removing certificate renewal script..."
    rm /usr/local/sbin/renew-certs-and-restart-mproxy.sh
fi

# Reload systemd
echo "Reloading systemd daemon..."
systemctl daemon-reload
systemctl reset-failed

echo ""
echo "Systemd service uninstalled!"
echo ""
echo "Note: The following were NOT removed:"
echo "- Configuration files in /etc/mproxy/"
echo "- Data directory /var/lib/mproxy/"
echo "- User 'mproxy'"
echo ""
echo "To completely remove mproxy:"
echo "1. Remove config: sudo rm -rf /etc/mproxy"
echo "2. Remove data: sudo rm -rf /var/lib/mproxy"
echo "3. Remove user: sudo userdel mproxy"
