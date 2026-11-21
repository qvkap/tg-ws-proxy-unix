# Telegram WebSocket Proxy (C Edition - Unix)

A high-performance, incredibly lightweight, and robust pure C implementation of `tg-ws-proxy` for Unix systems (Linux, FreeBSD, OpenBSD, macOS). It tunnels Telegram MTProto and SOCKS5 traffic through Cloudflare WebSockets over TLS (WSS) and applies advanced DPI circumvention techniques, completely bypassing strict censorship, TSPU, and ISP blocks.

Unlike Python implementations that consume hundreds of megabytes of RAM and heavy runtimes, this pure C version uses only ~2-3 MB of RAM and negligible CPU, making it ideal for weak VPS instances, home servers, and routers (OpenWrt).

## Censorship Circumvention Algorithms

1. **Cloudflare Reverse Proxy Pool (CfProxy)**:
   - Contains an embedded rotating pool of 20 encrypted Cloudflare reverse-proxy domains (`.co.uk`), dynamically decrypted at runtime.
   - Automatically masks MTProto as standard HTTPS WebSocket traffic (`GET /apiws`, `Sec-WebSocket-Protocol: binary`).
   - Balances traffic across proxy nodes and automatically fails over to the next healthy node upon connection issues.

2. **Multi-DC Auto-Routing (DC 1 through 5)**:
   - Automatically detects the Telegram Data Center (DC 1, 2, 3, 4, 5) from MTProto handshakes and SOCKS5 destination IPs/hostnames.
   - Dynamically targets the appropriate DC endpoint (`kws{dc}.{domain}`) to minimize latency and ensure proper Telegram routing.

3. **Intelligent SOCKS5 Interception**:
   - Detects when Telegram connects via SOCKS5 to blocked Telegram DC IP ranges (AS44907 / AS62041).
   - Transparently encapsulates the connection into the Cloudflare WSS bypass tunnel instead of attempting blocked direct IP connections.
   - Non-Telegram traffic is forwarded directly with optional DPI fragmentation.

4. **Custom Cloudflare Worker Tunneling (CfWorker)**:
   - Supports user-deployed Cloudflare Workers via `--cf-worker <domain>` or `config.json`.
   - Proxies MTProto over WebSockets directly to Telegram DCs using Cloudflare's edge network (`/apiws?dst={tg_ip}&dc={dc}`).

5. **TCP Fragmentation / Trickle DPI Bypass**:
   - For direct connections and fallbacks, splits the initial packet (handshake) across separate TCP segments with micro-delays and `TCP_NODELAY`.
   - Bypasses naive DPI filters (such as Russian TSPU) that inspect only the first packet boundary for protocol signatures.

6. **RFC 6455 Ping/Pong Keep-Alive**:
   - Automatically handles WebSocket PING frames with PONG replies, preventing Cloudflare and middlebox idle connection dropouts.

## Features

- **Pure C Minimalism**: Written in standard C with zero dependencies beyond POSIX sockets/threads and OpenSSL (`-lssl -lcrypto`).
- **Cross-Platform Unix**: Tested and compatible with Linux (Systemd, OpenRC, Runit, Dinit), FreeBSD (`rc.d`, sysctl), and macOS.
- **Protocol Multiplexing**: Single listening port serves both MTProto and SOCKS5 clients simultaneously.
- **Auto-Installation**: One-command service creation (`--autostart`) for Systemd, OpenRC, FreeBSD rc.d, and Dinit.
- **Daemon Mode**: Built-in background daemonizing (`--daemon`) with syslog logging and domain masking.
- **Self-Test Diagnostics**: Run `--test` to verify upstream Cloudflare WSS node connectivity.

## Building from Source

```bash
cd tg-ws-proxy-unix
make
```

Run test suite:
```bash
make tests
```

Install binary:
```bash
sudo make install
```

## Usage

### Standard Execution
To run in the foreground on port `8080`:
```bash
./tg-ws-proxy 8080
```
On first run, a unique secret is generated in `config.json`. Connection links (MTProto and SOCKS5) will be printed to the terminal:
```
1. MTProto Proxy Link:
   tg://proxy?server=127.0.0.1&port=8080&secret=...
2. SOCKS5 Proxy Link:
   tg://socks?server=127.0.0.1&port=8080
```

### Self-Test Connectivity
Verify connectivity to Cloudflare WSS nodes:
```bash
./tg-ws-proxy --test
```

### Command-Line Options
```
Usage: ./tg-ws-proxy [port] [options]

Options:
  [port]               Port to listen on (default: 8080)
  --daemon             Run in background with syslog logging
  --cf-worker <domain> Add custom Cloudflare worker domain
  --cf-domain <domain> Add custom Cloudflare proxy domain
  --secret <hex>       Set proxy secret (32 hex characters)
  --no-fragment        Disable TCP fragmentation DPI bypass
  --no-fallback        Disable direct TCP fallback
  --autostart          Install system service (Systemd/OpenRC/rc.d)
  --test               Run self-test on Cloudflare WSS pool
  --help               Display help message
```

### Daemon Mode
Run proxy silently in the background:
```bash
./tg-ws-proxy 8080 --daemon
```
View logs:
```bash
journalctl -t tg-ws-proxy -f
```

### Autostart Configuration
Automatically detects your init system (Systemd, OpenRC, FreeBSD rc.d, Runit, Dinit) and installs the service:
```bash
./tg-ws-proxy --autostart
```

## Configuration (`config.json`)
```json
{
  "secret": "ee3a482f7ab1b16063c9db1f8973de1fa3",
  "tcp_fragment": true,
  "direct_fallback": true
}
```

## Internal Architecture
- `src/main.c`: Protocol multiplexer, SOCKS5 interception, MTProto router, balancer, and autostart installers.
- `src/ws_client.c`: WebSocket-over-TLS client built on OpenSSL with domain resolution, RFC 6455 masking, and ping/pong keepalive.
- `include/ws_client.h`: Header definition for the WSS client engine.
