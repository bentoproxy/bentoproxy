# BentoProxy

**Open source residential proxy network built on ESP32 hardware nodes**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)

## What is BentoProxy?

BentoProxy is a residential proxy network where anyone can run proxy nodes from their home WiFi (using ESP32 hardware) and earn money for bandwidth. Proxy users access these residential IPs to fetch content, scrape websites, and bypass geographic restrictions. The entire system is **100% open source (AGPLv3)** to build trust through transparency and encourage community contributions.

**Primary use case:** Fetch podcasts, RSS feeds, and web content from residential IPs to avoid datacenter IP blocking and geographic restrictions.

## Intended Use & Ethics

BentoProxy is designed for **legitimate personal and small-scale use cases**.

**✅ Legitimate uses:**
- Fetching podcasts and RSS feeds from geo-restricted sources
- Personal web scraping and research (respecting robots.txt and rate limits)
- Accessing content you're entitled to but is geo-blocked
- Privacy-focused browsing
- Testing your own services from different networks
- Educational and research purposes

**❌ Prohibited uses:**
- Mass automated requests designed to overload websites
- Bypassing authentication or authorization systems
- Violating terms of service at scale
- Credential stuffing, brute force attacks, or other malicious activities
- Any illegal activities under applicable laws

**Built-in safeguards:**
- Rate limits: 5 MB/min per device, 8 concurrent connections max
- Port blocklist: SMTP, SMB, databases blocked by default
- No payload logging: Only metadata (host, port, bytes) is tracked
- Open source: 100% auditable code

**User Responsibility:** Users are solely responsible for how they use BentoProxy. Node operators and proxy users must comply with all applicable laws and website terms of service. The project maintainers do not condone or support abuse of this software.

The open source nature ensures transparency - unlike commercial black-box proxy services, anyone can audit exactly what BentoProxy does and doesn't do.

## Current Status

⚠️ **Alpha / Early Development**

**What works:**
- ✅ Rust orchestrator with WebSocket device management
- ✅ SOCKS5 proxy server (port 1080)
- ✅ HTTP CONNECT proxy server (port 8888)
- ✅ Device registration and authentication
- ✅ Usage tracking and flow logging
- ✅ Web dashboard for device owners and proxy users
- ✅ ESP32 firmware (basic functionality, performance optimization ongoing)

**What's coming:**
- 🚧 ESP32 firmware performance improvements
- 🚧 Payment system integration
- 🚧 Enhanced analytics dashboard
- 🚧 Mobile and desktop node support

**Early adopters and contributors welcome!** File issues, submit PRs, or run test nodes.

## Architecture

```
┌──────────────┐   SOCKS5/HTTP    ┌──────────────┐   WebSocket/TLS   ┌──────────────┐
│ Proxy User   │◄────────────────►│ Orchestrator │◄─────────────────►│  ESP32 Node  │
│              │   :1080/:8888    │ (Rust/Axum)  │    :8443/ws       │ (Home WiFi)  │
└──────────────┘                  └──────────────┘                   └──────────────┘
                                         │                                    │
                                         │                                    │
                                    SQLite DB                           Target Server
                                 (Usage tracking)                      (sees home IP)
```

**Components:**
- **Orchestrator (this repo):** Rust backend with Axum, WebSocket device management, SOCKS5/HTTP CONNECT proxies, SQLite tracking
- **ESP32 Firmware:** [bentoproxy-esp32](https://github.com/bentoproxy/bentoproxy-esp32) - C firmware for ESP32-S3 nodes
- **Protocol:** [bentoproxy-protocol](https://github.com/bentoproxy/bentoproxy-protocol) - Binary protocol specification (Rust crate)

## Quick Start

### Prerequisites

- Rust (stable channel)
- SQLite 3

### Build and Run

```bash
# Clone the repository
git clone https://github.com/bentoproxy/bentoproxy.git
cd bentoproxy

# Build
cargo build --release

# Run
cargo run --release
```

The orchestrator will start on:
- **HTTP/WebSocket:** `http://localhost:8080`
- **Device WebSocket:** `ws://localhost:8080/ws/device`
- **SOCKS5 proxy:** `localhost:1080`
- **HTTP CONNECT proxy:** `localhost:8888`

### Environment Variables

```bash
APP_ENV=production              # production | staging | development
HTTP_PORT=8080                  # Web server port
HTTP_PROXY_PORT=8888           # HTTP CONNECT proxy port
SOCKS5_PORT=1080               # SOCKS5 proxy port
DATABASE_PATH=/path/to/bento.db # SQLite database
JWT_SECRET=your-secret-key      # Session token secret
REQUIRE_SOCKS5_AUTH=true       # Require authentication for SOCKS5
```

### Register Your First Device

1. Start the orchestrator
2. Navigate to `http://localhost:8080`
3. Register as a device owner
4. Go to dashboard and click "Add Device"
5. Copy the device ID and token for your ESP32

## Features

### Proxy Support

- **HTTP CONNECT proxy** (port 8888) - Works with curl, Python requests, browsers
- **SOCKS5 proxy** (port 1080) - Protocol-agnostic, supports any TCP connection

### Management

- **Web dashboard** - Device registration, usage stats, API key management
- **Device authentication** - Pre-shared tokens for ESP32 nodes
- **User authentication** - API keys for proxy users
- **Usage tracking** - Flow logging with byte counts and timestamps

### Security

- TLS encryption for device connections (WebSocket over TLS)
- API key authentication for proxy access
- Port blocklist (SMTP, SMB, databases)
- No payload logging (only metadata)

## Development

### Build

```bash
cargo build
```

### Run in Development

```bash
cargo run
```

### Run Tests

```bash
cargo test
```

### Code Formatting

```bash
cargo fmt
cargo clippy
```

### Database

Migrations run automatically on startup. Database location: `/opt/apps/bentoproxy/{env}/data/bento.db`

## Usage Examples

### HTTP CONNECT Proxy

```bash
# curl
curl -x http://localhost:8888 \
  --proxy-header "Proxy-Authorization: Basic $(echo -n 'api:YOUR_API_KEY' | base64)" \
  https://ifconfig.me

# Python
import requests
proxies = {
    'http': 'http://api:YOUR_API_KEY@localhost:8888',
    'https': 'http://api:YOUR_API_KEY@localhost:8888'
}
response = requests.get('https://ifconfig.me', proxies=proxies)
print(response.text)  # Shows residential IP
```

### SOCKS5 Proxy

```bash
# curl
curl --socks5-hostname localhost:1080 \
  --proxy-user api:YOUR_API_KEY \
  https://ifconfig.me

# Python
import requests
proxies = {
    'http': 'socks5://api:YOUR_API_KEY@localhost:1080',
    'https': 'socks5://api:YOUR_API_KEY@localhost:1080'
}
response = requests.get('https://ifconfig.me', proxies=proxies)
print(response.text)  # Shows residential IP
```

## Contributing

Contributions are welcome! Please:

1. Check [open issues](https://github.com/bentoproxy/bentoproxy/issues) or file a new one
2. Fork the repository
3. Create a feature branch (`git checkout -b feature/your-feature`)
4. Make your changes following the code style (rustfmt, clippy)
5. Submit a pull request

## Related Projects

- **[bentoproxy-protocol](https://github.com/bentoproxy/bentoproxy-protocol)** - Binary protocol specification (Rust crate)
- **[bentoproxy-esp32](https://github.com/bentoproxy/bentoproxy-esp32)** - ESP32-S3 firmware for proxy nodes

## License

This project is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.

**What this means:**
- ✅ You can use, modify, and distribute this software freely
- ✅ You can run it for commercial purposes
- ⚠️ If you run a modified version as a network service, you **must** open source your changes
- ⚠️ Any derivative work must also be licensed under AGPL-3.0

This ensures that if someone forks BentoProxy and runs it as a service, the community benefits from their improvements.

See [LICENSE](LICENSE) for the full license text.

## Support

- **Issues:** [GitHub Issues](https://github.com/bentoproxy/bentoproxy/issues)
- **Pull Requests:** [GitHub PRs](https://github.com/bentoproxy/bentoproxy/pulls)

---

**Built with transparency. Run with trust.**
