# tunl - IPv6-First Self-Hosting Toolkit

**Host services from home using IPv6. No VPS, no NAT, no web interfaces.**

## What is tunl?

tunl is a complete **self-hosting toolkit** for home servers. With IPv6, every device on your network has a globally routable public IP—no NAT, no port forwarding, no VPS required.

```
                                 IPv6 Internet
                                       │
┌───────────────────────────────────────┼───────────────────────────────────────┐
│  Your Home Network                    │                                       │
│                                       ▼                                       │
│  ┌─────────────┐            ┌─────────────────┐           ┌─────────────────┐ │
│  │   Laptop    │◀───────────│      tunl       │◀──────────│  Internet User  │ │
│  │ 2001:db8::2 │            │  [::]::8080     │           │                 │ │
│  └─────────────┘            │  (public IPv6)  │           └─────────────────┘ │
│                             └─────────────────┘                               │
└───────────────────────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# Build
make

# Forward port 8080 to your local app on port 3000
./bin/tunl -f 8080:localhost:3000

# That's it. You're live on IPv6.
```

## Features

- **~50KB binary** - minimal, focused, no bloat
- **IPv6-first** - dual-stack sockets (accepts IPv4 and IPv6)
- **Load balancing** - round-robin, least-connections, IP-hash
- **Health checks** - automatic backend failover
- **Rate limiting** - per-IP connection throttling
- **DNS updates** - automatic IPv6 prefix change detection
- **ACME/Let's Encrypt** - automatic TLS certificates
- **Reachability check** - verify your setup works
- **Terminal UI** - ncurses dashboard (or ANSI fallback)

## Commands

```bash
tunl serve [options]      # Start proxy server
tunl dns [options]        # DNS dynamic updates
tunl cert [options]       # TLS certificates (ACME)
tunl check [options]      # Reachability test
tunl tui                  # Terminal dashboard
tunl -f <port:host:port>  # Quick forward mode
```

## Installation

```bash
# Build from source
make
sudo make install

# Dependencies (Debian/Ubuntu)
sudo apt install build-essential libssl-dev

# Optional: ncurses for enhanced TUI
sudo apt install libncurses-dev
make CFLAGS+="-DHAVE_NCURSES" LIBS+="-lncurses"
```

## Usage Examples

### Quick forward

```bash
# Forward port 8080 to localhost:3000
tunl -f 8080:localhost:3000
```

### DNS dynamic update

When your ISP changes your IPv6 prefix, tunl updates your DNS:

```bash
# Cloudflare
tunl dns --provider cf --hostname myhost.example.com --token YOUR_API_TOKEN

# Monitor for changes (runs continuously)
tunl dns --provider cf --hostname myhost.example.com --token YOUR_API_TOKEN --monitor
```

### TLS certificates

Get free Let's Encrypt certificates:

```bash
# Get certificate
tunl cert --domain myhost.example.com --email you@example.com

# Test with staging first
tunl cert --domain myhost.example.com --email you@example.com --staging
```

### Reachability check

Verify your setup works:

```bash
tunl check --hostname myhost.example.com --port 443
```

### Terminal dashboard

Live monitoring:

```bash
tunl tui
```

### Config file

```ini
# tunl.conf
[admin]
bind = ::1
port = 8081
token = your-secret-token

[rule.1]
listen = 8080
backend = localhost:3000
backend = localhost:3001
lb = rr
max_conns = 512
```

```bash
tunl serve -C tunl.conf
```

## Why IPv6?

Every IPv6-enabled home network has **public addresses for every device**:

- ❌ No NAT / CGNAT
- ❌ No port forwarding
- ❌ No VPS costs
- ❌ No third-party tunnels

Check your IPv6: `curl -6 ifconfig.me`

## Code Quality

This codebase follows Linux kernel coding standards:

- **~2,000 lines total** (9 clean modules)
- **epoll-based** I/O multiplexing
- **No memory leaks** - proper cleanup
- **Minimal dependencies** - OpenSSL and pthreads

## License

GPL-2.0. See [LICENSE](LICENSE).

---

*IPv6 first. One binary, one command, your service is online.*
