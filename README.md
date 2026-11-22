# Telegram WebSocket Proxy (C Edition - Unix)

[![Language](https://img.shields.io/badge/Language-C99-00599C.svg?style=flat-square&logo=c)](https://en.wikipedia.org/wiki/C99)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20FreeBSD%20%7C%20OpenBSD%20%7C%20macOS%20%7C%20OpenWrt-lightgrey.svg?style=flat-square)]()
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg?style=flat-square)]()
[![DPI Bypass](https://img.shields.io/badge/DPI%20Bypass-Active-success.svg?style=flat-square)]()

A high-performance, ultra-lightweight, and robust pure C implementation of `tg-ws-proxy` for Unix operating systems (**Linux**, **FreeBSD**, **OpenBSD**, **macOS**, and **OpenWrt** routers). It tunnels Telegram **MTProto** and **SOCKS5** traffic through Cloudflare WebSockets over TLS (**WSS**) and applies advanced DPI circumvention algorithms, completely bypassing strict censorship, TSPU (ТСПУ), and ISP throttling.

---

### 🇷🇺 Краткое описание на русском
**tg-ws-proxy-unix** — это легковесный прокси-сервер на чистом Си для обхода блокировок и замедлений Telegram в сетях с цензурой (РКН / ТСПУ). Маскирует трафик Telegram (MTProto и SOCKS5) под стандартные веб-сокеты Cloudflare (WSS HTTPS), позволяя клиентам без сбоев подключаться к серверам Telegram (DC 1–5), скачивать медиа и совершать звонки. Потребляет всего **2–3 МБ оперативной памяти**, что делает его идеальным решением для слабых VPS, домашних серверов и роутеров с OpenWrt.

---

## ⚡ Performance: C vs Python Edition

| Metric | tg-ws-proxy (Python) | tg-ws-proxy-unix (Pure C) |
| :--- | :--- | :--- |
| **RAM Usage** | ~80 – 150 MB | **~2 – 3 MB** (40x less) |
| **CPU Load** | Moderate (GIL, asyncio) | **Near zero (~0.1%)** |
| **Binary Size** | ~50+ MB (runtime/deps) | **~40 KB** single native binary |
| **Startup Time** | ~1.5 – 2.5 seconds | **< 5 milliseconds** |
| **Dependencies** | Python 3.10+, pip, SSL, cffi | **Zero** (standard libc + libssl) |
| **Router Support** | ❌ Heavy for OpenWrt | **✅ Ideal for OpenWrt routers** |

---

## 🛡️ Censorship Circumvention Algorithms (Методы обхода блокировок)

1. **Cloudflare Reverse Proxy Pool (CfProxy)**:
   - Contains an embedded rotating pool of 20 encrypted Cloudflare reverse-proxy domains (`.co.uk`), dynamically decrypted at runtime.
   - Automatically masks MTProto packets as legitimate HTTPS WebSocket streams (`GET /apiws`, `Sec-WebSocket-Protocol: binary`).
   - Balances traffic across proxy nodes and automatically fails over to the next healthy node upon network errors or packet loss.

2. **Multi-DC Auto-Routing (DC 1 through 5)**:
   - Automatically detects the target Telegram Data Center (DC 1, 2, 3, 4, 5) from MTProto handshakes and SOCKS5 destination IPs/hostnames.
   - Dynamically targets the appropriate DC endpoint (`kws{dc}.{domain}`) to minimize latency, avoid packet loops, and optimize media downloads.

3. **Intelligent SOCKS5 Telegram Interception**:
   - Detects when Telegram connects via SOCKS5 to blocked Telegram DC IP ranges (AS44907 / AS62041, `149.154.160.0/20`, `91.108.0.0/16`).
   - Transparently encapsulates the connection into the Cloudflare WSS bypass tunnel instead of attempting blocked direct IP connections.
   - Non-Telegram traffic is forwarded directly with optional DPI fragmentation.

4. **Custom Cloudflare Worker Tunneling (CfWorker)**:
   - Supports user-deployed Cloudflare Workers via `--cf-worker <domain>` or `config.json`.
   - Proxies MTProto over WebSockets directly to Telegram DCs using Cloudflare's edge network (`/apiws?dst={tg_ip}&dc={dc}`).

5. **TCP Fragmentation / Trickle DPI Bypass**:
   - For direct fallback connections, splits the initial packet (handshake) across separate TCP segments with micro-delays and `TCP_NODELAY`.
   - Defeats naive DPI filters (such as Russian TSPU/RKN) that inspect only the first packet boundary for protocol signatures.

6. **RFC 6455 Ping/Pong Keep-Alive**:
   - Automatically handles WebSocket PING frames with PONG replies, preventing Cloudflare and middlebox idle connection dropouts.

---

## 🚀 Quick Start & Installation

### 1. Requirements
- GCC or Clang
- OpenSSL development headers (`libssl-dev` on Debian/Ubuntu, `openssl-devel` on Alpine/CentOS/Fedora, `openssl` on FreeBSD/macOS)
- Make

```bash
# Debian / Ubuntu / Mint
sudo apt update && sudo apt install -y build-essential libssl-dev

# Alpine Linux
apk add build-base openssl-dev

# Arch Linux / Manjaro
sudo pacman -S base-devel openssl

# FreeBSD
pkg install gmake openssl
```

### 2. Build from Source
```bash
git clone https://github.com/qvkap/tg-ws-proxy-unix.git
cd tg-ws-proxy-unix
make
```

### 3. Verify Connectivity (Self-Test)
Test upstream Cloudflare WSS node connectivity:
```bash
./tg-ws-proxy --test
```

### 4. Run Proxy
```bash
./tg-ws-proxy 8080
```
On first run, a unique secret is generated in `config.json`. Both MTProto and SOCKS5 links will be printed:
```
====================================================
Telegram Multiplexed Proxy (C Edition - Unix)
Port: 8080 | TCP Fragmentation: ENABLED | Pool: 20 CF Nodes
1. MTProto Proxy Link:
   tg://proxy?server=127.0.0.1&port=8080&secret=...
2. SOCKS5 Proxy Link:
   tg://socks?server=127.0.0.1&port=8080
====================================================
```
Simply click the link on your machine or add it into your Telegram client settings (**Settings → Data and Storage → Proxy Settings**).

---

## ⚙️ Command-Line Options

```
Usage: ./tg-ws-proxy [port] [options]

Options:
  [port]               Port to listen on (default: 8080)
  --daemon             Run in background with syslog logging
  --cf-worker <domain> Add custom Cloudflare worker domain (e.g. proxy.workers.dev)
  --cf-domain <domain> Add custom Cloudflare proxy domain
  --secret <hex>       Set proxy secret (32 hex characters)
  --no-fragment        Disable TCP fragmentation DPI bypass
  --no-fallback        Disable direct TCP fallback
  --autostart          Install system service (Systemd/OpenRC/rc.d/Dinit)
  --test               Run self-test on Cloudflare WSS pool
  --help, -h           Display help message
```

---

## 🔧 Autostart & Service Installation

The proxy comes with a smart auto-installation feature that detects your init system and sets up the daemon:

```bash
sudo ./tg-ws-proxy --autostart
```

Supported service managers:
- **Systemd** (`/etc/systemd/system/tg-ws-proxy.service`)
- **OpenRC** (`/etc/init.d/tg-ws-proxy`)
- **FreeBSD rc.d** (`/etc/rc.d/tg_ws_proxy`)
- **Runit** (`/etc/sv/tg-ws-proxy`)
- **Dinit** (`/etc/dinit.d/tg-ws-proxy`)

To check logs when running as a daemon:
```bash
journalctl -t tg-ws-proxy -f
```

---

## 🌐 Configuration (`config.json`)

Settings can be persisted in `config.json` in the working directory:
```json
{
  "secret": "ee3a482f7ab1b16063c9db1f8973de1fa3",
  "tcp_fragment": true,
  "direct_fallback": true
}
```

---

## 📂 Project Architecture

```
tg-ws-proxy-unix/
├── include/
│   └── ws_client.h       # WebSocket over TLS client header
├── src/
│   ├── main.c            # Core multiplexer, SOCKS5 interception, MTProto router, autostart
│   ├── ws_client.c       # OpenSSL WSS client, RFC 6455 masking, ping/pong keepalive
│   └── mtproto_test.c    # MTProto handshake test client
├── Makefile              # Build and test orchestration
├── README.md             # Documentation and guide
└── config.json           # Local proxy configuration (generated)
```

---

## 🔍 Keywords & Topics / Теги для поиска

`telegram-proxy` `tg-ws-proxy` `mtproto-proxy` `socks5-proxy` `cloudflare-workers` `websocket-proxy` `dpi-bypass` `rkn-bypass` `tspu-bypass` `anti-censorship` `censorship-circumvention` `c99` `unix` `linux` `freebsd` `openwrt` `обход-блокировок-телеграм` `обход-тспу` `прокси-телеграм-роутер`

---

## 📄 License

Distributed under the [MIT License](LICENSE).
