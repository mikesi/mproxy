%define __spec_install_post %{nil}
%define __os_install_post %{_dbpath}/brp-compress
%define debug_package %{nil}

Name: mproxy
Summary: A Reverse Proxy and TLS Terminator
Version: @@VERSION@@
Release: @@RELEASE@@%{?dist}
License: MIT
Group: Applications/System
Source0: %{name}-%{version}.tar.gz
Source1: mproxy.service
Source2: mproxy.env.example
Requires: systemd
BuildRequires: systemd

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

%description
%{summary}

%prep
%setup -q
# Copy systemd files from SOURCE directory
cp %{SOURCE1} .
cp %{SOURCE2} .

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}

# Install systemd service file first
mkdir -p %{buildroot}%{_unitdir}
install -m 644 mproxy.service %{buildroot}%{_unitdir}/mproxy.service

# Install environment file example  
mkdir -p %{buildroot}%{_sysconfdir}/mproxy
install -m 644 mproxy.env.example %{buildroot}%{_sysconfdir}/mproxy/mproxy.env.example

# Remove systemd files from source dir to avoid duplicating them
rm -f mproxy.service mproxy.env.example

# Copy remaining files (binaries)
cp -a * %{buildroot}

# Create data directory
mkdir -p %{buildroot}/var/lib/mproxy/data

%pre
# Create mproxy user if it doesn't exist
getent group mproxy >/dev/null || groupadd -r mproxy
getent passwd mproxy >/dev/null || \
    useradd -r -g mproxy -d /var/lib/mproxy -s /sbin/nologin \
    -c "MProxy service account" mproxy
exit 0

%post
%systemd_post mproxy.service
# Set ownership of data directory
chown -R mproxy:mproxy /var/lib/mproxy
# Create default config if it doesn't exist
if [ ! -f %{_sysconfdir}/mproxy/mproxy.env ]; then
    cp %{_sysconfdir}/mproxy/mproxy.env.example %{_sysconfdir}/mproxy/mproxy.env
    chmod 600 %{_sysconfdir}/mproxy/mproxy.env
fi

%preun
%systemd_preun mproxy.service

%postun
%systemd_postun_with_restart mproxy.service

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_bindir}/*
%{_unitdir}/mproxy.service
%dir %{_sysconfdir}/mproxy
%config(noreplace) %{_sysconfdir}/mproxy/mproxy.env.example
%attr(0755,mproxy,mproxy) %dir /var/lib/mproxy
%attr(0755,mproxy,mproxy) %dir /var/lib/mproxy/data
