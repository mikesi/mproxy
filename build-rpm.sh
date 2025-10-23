#!/bin/bash

# Exit on error
set -e

# Build the project in release mode
echo "Building the project in release mode..."
cargo build --release

# Prepare systemd files for mproxy RPM
echo -e "\nPreparing systemd files..."
mkdir -p target/x86_64-unknown-linux-gnu/release/rpmbuild/SOURCES
cp systemd/mproxy.service target/x86_64-unknown-linux-gnu/release/rpmbuild/SOURCES/
cp systemd/mproxy.env.example target/x86_64-unknown-linux-gnu/release/rpmbuild/SOURCES/

# Build RPM for mproxy
echo -e "\nBuilding RPM for mproxy..."
(cd crates/mproxy && cargo rpm build)

# Build RPM for cert_tool
echo -e "\nBuilding RPM for cert_tool..."
(cd crates/cert_tool && cargo rpm build)

echo -e "\nRPM packages have been built successfully!"
echo "You can find the RPMs in the target directories."

# List the built RPMs
echo -e "\nBuilt RPM packages:"
find target -name "*.rpm" -type f ! -name "*.src.rpm" 2>/dev/null | xargs ls -lh
