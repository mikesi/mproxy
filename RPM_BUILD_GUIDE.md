# RPM Build Guide for MProxy

## Overview

Both `mproxy` and `cert-tool` now use `cargo-rpm` for streamlined RPM building. The systemd integration is included automatically in the mproxy RPM.

## Building RPMs

### Quick Build (Recommended)

```bash
./build-rpm.sh
```

This builds both packages in one command.

### Manual Build

Build each package individually:

```bash
# Build the binaries
cargo build --release

# Build mproxy RPM (includes systemd service)
cd crates/mproxy && cargo rpm build

# Build cert-tool RPM
cd crates/cert_tool && cargo rpm build
```

## RPM Locations

After building, find the RPMs at:
- **mproxy**: `target/x86_64-unknown-linux-gnu/release/rpmbuild/RPMS/x86_64/mproxy-0.1.0-1.fc42.x86_64.rpm`
- **cert-tool**: `target/x86_64-unknown-linux-gnu/release/rpmbuild/RPMS/x86_64/cert-tool-0.1.0-1.fc42.x86_64.rpm`

## Installation

### Install Both Packages

```bash
sudo rpm -ivh target/x86_64-unknown-linux-gnu/release/rpmbuild/RPMS/x86_64/mproxy-*.rpm
sudo rpm -ivh target/x86_64-unknown-linux-gnu/release/rpmbuild/RPMS/x86_64/cert-tool-*.rpm
```

### Enable MProxy Service

After installing the mproxy RPM:

```bash
# The RPM automatically:
# - Creates mproxy user/group
# - Installs systemd service
# - Sets up directories
# - Creates default config

# Start the service
sudo systemctl enable --now mproxy

# Check status
sudo systemctl status mproxy
```

## What's Included

### MProxy RPM

**Files:**
- `/usr/bin/mproxy` - Binary
- `/usr/lib/systemd/system/mproxy.service` - Systemd unit
- `/etc/mproxy/mproxy.env` - Configuration (auto-created from .example)
- `/var/lib/mproxy/data/` - Data directory

**Post-install:**
- Creates `mproxy` system user/group
- Sets proper permissions
- Enables systemd integration

### Cert-Tool RPM

**Files:**
- `/usr/bin/cert_tool` - Binary

## Configuration Files

### Cargo.toml Metadata

Both packages use `[package.metadata.rpm]` sections:

**mproxy** (`crates/mproxy/Cargo.toml`):
- Package name: `mproxy`
- Binary target: `/usr/bin/mproxy`
- Dependencies: `openssl`, `systemd`

**cert-tool** (`crates/cert_tool/Cargo.toml`):
- Package name: `cert-tool` (note hyphen)
- Binary target: `/usr/bin/cert_tool`
- Dependencies: `openssl`

### Spec Files

Located in `.rpm/` directories:
- `crates/mproxy/.rpm/mproxy.spec` - Enhanced with systemd integration
- `crates/cert_tool/.rpm/cert-tool.spec` - Standard binary packaging

**Key Implementation Details for mproxy.spec:**
- Uses `Source1` and `Source2` directives for systemd files (no absolute paths)
- Systemd files are copied from SOURCES directory in `%prep` section
- Files are installed to proper locations before wildcard copy in `%install` section
- The build script (`build-rpm.sh`) copies systemd files to SOURCES directory before RPM build

## Troubleshooting

### Binary Not Found

If cargo-rpm can't find the binary, ensure you've built with:
```bash
cargo build --release
```

The binary must exist at: `target/x86_64-unknown-linux-gnu/release/<binary_name>`

### Spec File Not Found

cargo-rpm looks for `.rpm/<package-name>.spec` where `<package-name>` matches the `package` field in `[package.metadata.rpm]`.

For cert-tool: package name is `cert-tool` (hyphen), so spec must be `cert-tool.spec` (not `cert_tool.spec`).

### Clean Build

If issues persist:
```bash
cargo clean
cargo build --release
cd crates/mproxy && cargo rpm build
cd ../cert_tool && cargo rpm build
```

## Legacy Build Scripts

The old build scripts have been removed:
- ~~`build-cert-tool-rpm.sh`~~ - Replaced by cargo-rpm
- ~~`rpm/specs/cert-tool.spec`~~ - Moved to `.rpm/` directory

All RPM building now uses cargo-rpm for consistency.

## Verifying RPMs

### List Contents

```bash
rpm -qlp <rpm-file>
```

### Check Scripts

```bash
rpm -qp --scripts <rpm-file>
```

### Check Dependencies

```bash
rpm -qp --requires <rpm-file>
```

## Next Steps

After installation:
1. Configure mproxy: Edit `/etc/mproxy/mproxy.env`
2. Start service: `sudo systemctl start mproxy`
3. View logs: `sudo journalctl -u mproxy -f`

See `SYSTEMD_SETUP.md` for detailed systemd configuration.
