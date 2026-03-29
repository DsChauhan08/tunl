# SPF Packaging Guide

This document shows how to build SPF packages for popular Linux distros and how to install from source cleanly.

## Build From Source

```bash
make check-deps
make -j$(nproc)
```

Install to system prefix:

```bash
sudo make install
```

Install into a staging root (for distro packaging):

```bash
make DESTDIR="$(pwd)/build/stage" install
```

## Dependency Install Helpers

- Debian/Ubuntu: `make install-deps-debian`
- Fedora/RHEL/CentOS: `make install-deps-fedora` (or `make install-deps-rhel`)
- Arch: `make install-deps-arch`
- openSUSE: `make install-deps-suse`
- Alpine: `make install-deps-alpine`
- macOS: `make install-deps-macos`

## Build Local .deb Package

```bash
make package-deb VERSION=2.0.0
```

Installs with:

```bash
sudo apt install ./spf_2.0.0_amd64.deb
```

## Build Local .rpm Package

```bash
make package-rpm VERSION=2.0.0
```

Installs with:

```bash
sudo dnf install ./spf-2.0.0-1.x86_64.rpm
```

## Build Both Package Types

```bash
make package-all VERSION=2.0.0
```

## CI Packaging

- `.github/workflows/packages.yml` builds `.deb` and `.rpm` for pushes/PRs and uploads artifacts.
- `.github/workflows/release.yml` builds and publishes release assets for tagged versions.
