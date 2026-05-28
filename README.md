# Daxson

A censorship-resistant tunnel for hostile network environments.

Daxson routes TCP traffic through an encrypted channel that is designed to be indistinguishable from normal HTTPS traffic. The outer TLS connection impersonates a real browser using [uTLS](https://github.com/refraction-networking/utls). Traffic inside the session is shaped by the Behavioral Camouflage Layer (BCL), which applies empirically-derived statistical models of real application traffic patterns to make the stream resist deep-packet inspection.

---

## How it works

```
Client (Iran)                          Server (gr.batmat.ir)
──────────────────────────────         ──────────────────────────────────────
  App (browser / Telegram)
      │
  SOCKS5 / HTTP proxy (daxson)
      │ TCP stream
      ↓
  uTLS handshake                 ──►   TLS listener (looks like HTTPS server)
  [Ed25519 device auth]          ──►   auth dispatch (0x02: device auth)
  [BCL traffic shaping]          ──►   BCL shaping (matching personality)
  [smux multiplexing]            ──►   smux session (N concurrent streams)
      │
      │  per-stream CONNECT requests
      │                          ──►   net.Dial(target)
      │                          ◄──   relay (bidirectional copy)
      ↓
  Response back to app
```

Unauthenticated connections (probers, scanners, censorship probes) never see an auth failure. They are forwarded transparently to a real nginx instance serving HTML, so the server appears to be an ordinary HTTPS website.

---

## Features

**Authentication**
- Ed25519 device identity — each device has a persistent key pair generated on first run
- Invite-link onboarding: `daxson://v1/<base64>` — signed by the server's identity key, single or multi-use, time-limited
- Bootstrap protocol: invite token → device registration → session auth (no passwords, no PSK visible to clients)
- Device revocation without key rotation

**Transport**
- uTLS browser fingerprint impersonation (Chrome, Firefox, Edge, Safari, random)
- BCL traffic shaping with five empirically-measured personalities: `browser`, `grpc`, `video`, `mobile`, `relay`
- smux multiplexing — hundreds of concurrent streams over a single TLS connection
- Exponential backoff reconnection with jitter

**Active-probe resistance**
- Authentication happens inside the encrypted channel after TLS is established
- The server's TLS certificate is a real Let's Encrypt certificate
- Unrecognized connections are forwarded to nginx; probers see real HTML

**Operational**
- Task-oriented CLI: `import` → `connect` workflow, no manual config
- Live status file updated every 10 seconds
- Built-in diagnostics: `daxson doctor`
- Management dashboard (embedded HTML, accessed via SSH tunnel)
- Prometheus metrics endpoint
- Device registry with last-seen tracking

---

## Quick start

### Server (Ubuntu/Debian)

```bash
# 1. Copy the binary
scp release/dev/daxson-linux-amd64 root@gr.batmat.ir:/usr/local/bin/daxson
ssh root@gr.batmat.ir chmod +x /usr/local/bin/daxson

# 2. Run the automated installer (handles certs, nginx, firewall, systemd):
scp scripts/server-install.sh root@gr.batmat.ir:/tmp/
ssh root@gr.batmat.ir 'DOMAIN=gr.batmat.ir CERTBOT_EMAIL=you@example.com bash /tmp/server-install.sh'

# 3. Create an invite link
ssh root@gr.batmat.ir 'sudo -u daxson daxson invite create --server gr.batmat.ir:443 --label test-v1'
# Outputs: daxson://v1/eyJz...
```

### Client (Linux / macOS)

```bash
# Import the invite (registers this device, saves profile)
daxson import 'daxson://v1/eyJz...'

# Connect (starts SOCKS5 on 127.0.0.1:1080 and HTTP proxy on 127.0.0.1:8080)
daxson connect

# Verify traffic is routed through the tunnel
curl https://api.ipify.org                                 # your real IP
curl -x socks5h://127.0.0.1:1080 https://api.ipify.org    # server's IP
```

### Client (Windows)

```powershell
.\daxson.exe import "daxson://v1/eyJz..."
.\daxson.exe connect
```

### Client (Android, via Termux)

```bash
# Inside Termux:
bash termux-setup.sh          # installs binary, sets up PATH
daxson import 'daxson://v1/eyJz...'
daxson connect
```

---

## Building

Requires Go 1.22 or later.

```bash
# Build for the current platform:
make build

# Build all release targets at once:
bash scripts/build-release.sh
```

Output in `release/<VERSION>/`:

| Binary | Platform |
|--------|----------|
| `daxson-linux-amd64` | Linux x86\_64 |
| `daxson-linux-arm64` | Linux ARM64 |
| `daxson-windows-amd64.exe` | Windows x86\_64 |
| `daxson-android-arm64` | Android ARM64 (Termux) |
| `daxson-android-arm` | Android ARM (older devices) |
| `daxsond-linux-amd64` | Server daemon, Linux x86\_64 |

All binaries are statically linked (`CGO_ENABLED=0`). No dependencies required at runtime.

---

## CLI reference

```
daxson import <daxson://...>        Import invite link, register device
daxson connect [--profile] [--log-level debug]
                                    Connect to tunnel, start SOCKS5 + HTTP proxies
daxson status                       Show live connection status
daxson doctor [--profile]           Run diagnostics (TCP, TLS, proxy, identity)
daxson init                         Guided first-time setup wizard
daxson serve [--config]             Run server (device auth + dashboard)
daxson keys show|rotate|export      Manage device key pair
daxson invite create|list|revoke    Manage invite links (server-side)
daxson devices list|revoke          Manage registered devices (server-side)
daxson version                      Print version
```

---

## Configuration

### Server (`~/.daxson/server.yaml` or `/etc/daxson/server.yaml`)

```yaml
mode: server

server:
  listen: ":443"
  tls:
    cert: /etc/letsencrypt/live/yourdomain.com/fullchain.pem
    key:  /etc/letsencrypt/live/yourdomain.com/privkey.pem
  auth:
    psk: "used only for relay-to-relay auth"
  probe_upstream: "127.0.0.1:80"   # nginx serving real HTML
  dashboard:
    listen: "127.0.0.1:9443"
    enabled: true

tunnel:
  transport:
    obfs:
      enabled: true
      personality: browser    # browser | grpc | video | mobile | relay
```

Server identity (`~/.daxson/server-identity.json`) and device registry (`~/.daxson/registry.json`) are auto-generated on first `daxson serve` start.

### Client profile (`~/.daxson/profiles/default.yaml`)

Written automatically by `daxson import`. You normally never edit this file.

```yaml
version: 1
server: gr.batmat.ir:443
tls:
  fingerprint: chrome       # chrome | firefox | edge | safari | random
transport:
  obfs:
    enabled: true
    personality: browser
proxy:
  socks5: 127.0.0.1:1080
  http: 127.0.0.1:8080
```

---

## Security model

**What is protected:**
- Authentication happens inside TLS after the encrypted channel is established. No auth material is visible in the TLS payload to a passive observer.
- Each device's Ed25519 private key never leaves the device.
- The server signs invite links with its identity key; clients verify this before registering.
- Revoked devices are rejected at auth time without revealing the reason.

**What is observable:**
- The fact that a TLS connection is made to the server's IP and port. The connection is fingerprint-matched to a browser, so it is not distinguishable from HTTPS traffic by JA3/JA3S analysis.
- Connection timing and approximate volume (the BCL shapes but does not eliminate these signals).

**What is not a goal:**
- Anonymity — this is a tunnel, not an anonymity network. The server knows your device's public key.
- Metadata resistance beyond traffic shaping — a determined nation-state adversary watching both ends can still perform correlation attacks.

---

## Relay mode

For environments where the foreign server is blocked, a domestic relay node forwards traffic:

```
Client (Iran)  →  Relay (Iran VPS or cloud)  →  Server (foreign VPS)
```

```yaml
# relay.yaml
mode: relay
server:
  listen: ":443"
  tls: { cert: ..., key: ... }
  auth: { psk: "relay-downstream-psk" }
upstream:
  addr: gr.batmat.ir:443
  tls: { server_name: gr.batmat.ir, fingerprint: chrome }
  auth: { psk: "server-psk" }
```

---

## Testing

```bash
# Full automated test suite (run after connecting):
bash scripts/test-suite.sh

# Individual checks:
daxson doctor
curl -x socks5h://127.0.0.1:1080 https://api.ipify.org
```

See [docs/setup.md](docs/setup.md) for the complete end-to-end deployment and survivability testing guide.

---

## Repository layout

```
cmd/
  daxson/          Task-oriented CLI (import, connect, serve, keys, invite, devices)
  daxsond/         Server daemon (PSK-only, legacy)
internal/
  auth/            Ed25519 device auth + HMAC-PSK + auth dispatch
  bcl/             Behavioral Camouflage Layer (traffic shaping)
  config/          Configuration schema and client profile
  dashboard/       Embedded management dashboard (REST API + HTML SPA)
  metrics/         Prometheus metrics
  mux/             smux session management
  obfs/            BCL connection wrapper
  proxy/           SOCKS5 and HTTP proxy inbounds
  registry/        Device and invite registry with atomic persistence
  relay/           Relay mode (forward between two tunnel endpoints)
  telemetry/       Session tracking and transport analytics
  transport/tls/   uTLS client + standard TLS server
  tunnel/          Core tunnel client and server
pkg/
  identity/        Ed25519 key pair management and persistence
  invite/          Invite link format and wire protocol constants
  protocol/        Frame encoding/decoding
scripts/
  build-release.sh Cross-compilation for all targets
  server-install.sh Automated server setup
  termux-setup.sh  Android Termux client setup
  test-suite.sh    End-to-end connectivity and survivability tests
docs/
  setup.md         Complete deployment and testing guide
configs/
  server.production.yaml  Production server config template
deploy/
  docker/          Dockerfile + docker-compose
  systemd/         systemd service files
```

---

## License

MIT
