# Daxson — End-to-End Deployment & Testing Guide

**Server:** `gr.batmat.ir`  
**Goal:** Working tunnel, routed real traffic, measured survivability on Iranian networks.

---

## Table of Contents

- [Phase 1 — Build Preparation](#phase-1--build-preparation)
- [Phase 2 — Server Deployment](#phase-2--server-deployment)
- [Phase 3 — Client Setup](#phase-3--client-setup)
- [Phase 4 — Android Termux](#phase-4--android-termux)
- [Phase 5 — Connectivity Validation](#phase-5--connectivity-validation)
- [Phase 6 — Survivability Testing](#phase-6--survivability-testing)
- [Phase 7 — Troubleshooting](#phase-7--troubleshooting)
- [Phase 8 — Operational Recommendations](#phase-8--operational-recommendations)

---

## Phase 1 — Build Preparation

### Prerequisites

On your build machine (Linux, macOS, or Windows with WSL):

```bash
# Install Go 1.22+
# Linux/macOS:
wget https://go.dev/dl/go1.22.6.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.22.6.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# Verify:
go version   # must print go1.22.x or higher
```

### Build all targets

```bash
# Clone or enter the repo
cd /path/to/daxson-tunnel

# Build everything at once:
bash scripts/build-release.sh
```

This produces a `release/<VERSION>/` directory:

```
release/dev/
  daxson-linux-amd64          ← Linux client
  daxson-linux-arm64          ← Linux ARM64 client / Android arm64 (Termux)
  daxson-linux-arm            ← Android arm (older 32-bit devices)
  daxson-windows-amd64.exe    ← Windows client
  daxson-android-arm64        ← Same as linux-arm64, labelled for clarity
  daxsond-linux-amd64         ← Server daemon (for systemd on amd64 VPS)
  daxsond-linux-arm64         ← Server daemon for ARM VPS
  SHA256SUMS                  ← Checksums for all binaries
```

Verify the binaries are static and will run anywhere:

```bash
file release/dev/daxson-linux-amd64
# → ELF 64-bit LSB executable, x86-64, statically linked
```

### Makefile targets (individual platforms)

```bash
make build-linux-amd64     # client + server, Linux x86_64
make build-linux-arm64     # client + server, Linux/Android ARM64
make build-windows-amd64   # client, Windows
make build-android-arm64   # client, Android ARM64
```

---

## Phase 2 — Server Deployment

**Target:** `gr.batmat.ir` — Ubuntu/Debian VPS, root access.

### 2.1 Copy binary to server

```bash
# From your build machine:
scp release/dev/daxson-linux-amd64 root@gr.batmat.ir:/tmp/daxson

# Or if using the all-in-one script, copy it alongside the scripts:
scp -r scripts/ configs/ deploy/ root@gr.batmat.ir:/tmp/daxson-deploy/
```

### 2.2 Run the install script

SSH to the server and run:

```bash
ssh root@gr.batmat.ir

# If you copied the binary manually:
cp /tmp/daxson /usr/local/bin/daxson
chmod +x /usr/local/bin/daxson

# Run the automated installer:
cd /tmp/daxson-deploy
DOMAIN=gr.batmat.ir CERTBOT_EMAIL=your@email.com bash scripts/server-install.sh
```

The script does all of the following automatically. If you prefer to do it manually, follow steps 2.3–2.11 below.

---

### 2.3 Manual: System packages

```bash
apt-get update
apt-get install -y certbot nginx curl ufw
```

### 2.4 Manual: Create system user

```bash
useradd --system --shell /sbin/nologin --create-home --home-dir /home/daxson daxson
```

### 2.5 Manual: TLS certificate (Let's Encrypt)

```bash
# Stop nginx if it's running (certbot needs port 80 for standalone challenge)
systemctl stop nginx

certbot certonly \
  --standalone \
  --non-interactive \
  --agree-tos \
  --email your@email.com \
  -d gr.batmat.ir

# Verify:
ls /etc/letsencrypt/live/gr.batmat.ir/
# fullchain.pem  privkey.pem  chain.pem  cert.pem

# Fix permissions so daxson user can read certs:
chmod 0755 /etc/letsencrypt/{live,archive}
```

Certificate auto-renews via the certbot.timer systemd timer. The tunnel server reads the cert files on each new TLS connection, so renewal does NOT require a restart.

### 2.6 Manual: Install binary

```bash
install -m 0755 /tmp/daxson /usr/local/bin/daxson
daxson version   # sanity check
```

### 2.7 Manual: Config file

```bash
mkdir -p /etc/daxson

# Generate a strong PSK for relay-to-relay connections:
PSK=$(openssl rand -hex 32)
echo "PSK: $PSK"   # ← SAVE THIS

cat > /etc/daxson/server.yaml <<EOF
mode: server

server:
  listen: ":443"
  tls:
    cert: /etc/letsencrypt/live/gr.batmat.ir/fullchain.pem
    key:  /etc/letsencrypt/live/gr.batmat.ir/privkey.pem
    next_protos:
      - h2
      - http/1.1
  auth:
    psk: "${PSK}"
  probe_upstream: "127.0.0.1:8080"
  dashboard:
    listen: "127.0.0.1:9443"
    enabled: true

tunnel:
  transport:
    obfs:
      enabled: true
      personality: browser
    mux:
      max_streams: 512
      max_frame_size: 32768
      receive_buffer: 4194304

metrics:
  listen: "127.0.0.1:9090"

logging:
  level: info
  format: json
EOF

chown root:daxson /etc/daxson/server.yaml
chmod 0640 /etc/daxson/server.yaml
```

### 2.8 Manual: nginx probe resistance

Unauthenticated TCP connections (scanners, censorship probers) are forwarded to nginx, which serves real HTML. This makes the server indistinguishable from an ordinary HTTPS server to passive observation.

```bash
mkdir -p /var/www/daxson-probe

cat > /var/www/daxson-probe/index.html <<'EOF'
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Welcome</title></head>
<body><h1>Welcome</h1><p>This server provides HTTPS services.</p></body>
</html>
EOF

cat > /etc/nginx/sites-available/daxson-probe <<'EOF'
server {
    listen 127.0.0.1:8080;
    server_name _;
    root /var/www/daxson-probe;
    index index.html;
    access_log off;
    location / {
        try_files $uri $uri/ =404;
    }
}
EOF

ln -sf /etc/nginx/sites-available/daxson-probe /etc/nginx/sites-enabled/daxson-probe
rm -f /etc/nginx/sites-enabled/default

nginx -t && systemctl enable --now nginx
```

### 2.9 Manual: Firewall

```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 443/tcp comment "daxson tunnel"
ufw --force enable
ufw status
```

Do NOT open port 9090 or 9443. Metrics and dashboard are accessed via SSH tunnels.

### 2.10 Manual: systemd service

```bash
# Copy the service file:
cp deploy/systemd/daxson-serve.service /etc/systemd/system/

systemctl daemon-reload
systemctl enable daxson-serve
```

### 2.11 Start and verify

```bash
systemctl start daxson-serve
sleep 3

systemctl status daxson-serve
# Should show: active (running)

# Tail logs:
journalctl -u daxson-serve -f

# Health check:
curl http://127.0.0.1:9090/healthz
# → {"status":"ok"}

# Metrics:
curl http://127.0.0.1:9090/metrics | grep daxson_
```

On first start, the server auto-generates its Ed25519 identity at `/home/daxson/.daxson/server-identity.json`.

```bash
# View the server identity:
sudo -u daxson daxson keys show
```

---

### 2.12 Create an invite link

Run this on the server (as the daxson user):

```bash
sudo -u daxson daxson invite create \
  --server gr.batmat.ir:443 \
  --label "test-device-1" \
  --ttl 24h

# Output looks like:
#   ✓ Invite created  (token-id: a3f9...)
#     Expires       2026-05-28 10:00 UTC
#     Max uses      1
#
# daxson://v1/eyJzZXJ2ZXIiOiJnci5iYXRtYXQuaXI6NDQzIi...
```

Copy the `daxson://v1/...` link. Give it to the client device operator.

**Invite options:**
```bash
# Multi-use invite (e.g. for a team):
sudo -u daxson daxson invite create \
  --server gr.batmat.ir:443 \
  --label "team-link-v1" \
  --max-uses 10 \
  --ttl 72h

# List all invites:
sudo -u daxson daxson invite list

# Revoke an invite:
sudo -u daxson daxson invite revoke a3f9
```

---

## Phase 3 — Client Setup

### 3.1 Linux client

```bash
# Copy the binary:
cp release/dev/daxson-linux-amd64 ~/.local/bin/daxson
chmod +x ~/.local/bin/daxson

# Or install system-wide:
sudo install -m 0755 release/dev/daxson-linux-amd64 /usr/local/bin/daxson

# Verify:
daxson version
```

**Import invite and connect:**

```bash
# Step 1: Import the invite link (registers this device with the server)
daxson import 'daxson://v1/eyJz...'

# Expected output:
#   Importing invite...
#   ✓ Server: gr.batmat.ir:443
#   ✓ Server signature verified
#   ✓ Device identity: a1b2c3  (key: ~/.daxson/identity.json)
#   ✓ Registered as hostname
#   ✓ Profile saved to ~/.daxson/profiles/default.yaml
#   Ready! Run 'daxson connect' to start the tunnel.

# Step 2: Connect
daxson connect

# Expected output:
#   Connecting to gr.batmat.ir...
#   ✓ Authenticated  (device: a1b2c3)
#
#   Tunnel ready
#   → SOCKS5  127.0.0.1:1080
#   → HTTP    127.0.0.1:8080
#
#   Press Ctrl+C to disconnect.
```

**Verify the tunnel works:**

```bash
# Your real IP (no proxy):
curl https://api.ipify.org

# Your tunneled IP (should be gr.batmat.ir's IP):
curl -x socks5h://127.0.0.1:1080 https://api.ipify.org

# These two IPs must be different.
```

### 3.2 Windows client

**Transfer the binary:**

Option A — Download to Windows (via browser or curl):
```powershell
# PowerShell:
Invoke-WebRequest -Uri "https://your-server/daxson-windows-amd64.exe" -OutFile "daxson.exe"
```

Option B — Transfer from build machine via SCP:
```powershell
# From build machine:
scp release/dev/daxson-windows-amd64.exe user@windows-machine:C:\Users\user\daxson.exe
```

**Add to PATH (optional but convenient):**
```powershell
# Create a directory and add to PATH:
New-Item -ItemType Directory -Force "C:\Program Files\daxson"
Copy-Item daxson.exe "C:\Program Files\daxson\daxson.exe"
# Add C:\Program Files\daxson to your system PATH via System Properties
```

**Import and connect:**
```powershell
# Open PowerShell (not Command Prompt — PowerShell handles long URLs better):
.\daxson.exe import "daxson://v1/eyJz..."
.\daxson.exe connect
```

Config and identity are stored in `%APPDATA%\daxson\`.

**Verify the tunnel:**
```powershell
# Check IP without proxy:
(Invoke-WebRequest -Uri "https://api.ipify.org").Content

# Check IP via SOCKS5 (requires curl for Windows, or use browser proxy settings):
curl.exe -x socks5h://127.0.0.1:1080 https://api.ipify.org
```

**Configure browser proxy:**

In Firefox: Preferences → Network Settings → Manual proxy configuration:
- SOCKS Host: `127.0.0.1`, Port: `1080`, SOCKS v5
- Check "Proxy DNS when using SOCKS v5"

In Chrome: Use SwitchyOmega extension or launch with flags:
```powershell
chrome.exe --proxy-server="socks5://127.0.0.1:1080"
```

---

## Phase 4 — Android Termux

### 4.1 Install Termux

Install Termux from **F-Droid** (not Google Play — the Play Store version is outdated):
```
https://f-droid.org/packages/com.termux/
```

### 4.2 Transfer the binary

**Option A — Direct transfer via adb** (USB or WiFi):
```bash
# From your computer:
adb push release/dev/daxson-android-arm64 /data/local/tmp/daxson

# Inside Termux:
cp /data/local/tmp/daxson ~/.local/bin/daxson
chmod +x ~/.local/bin/daxson
```

**Option B — Over SSH from your computer:**
```bash
# Inside Termux, install SSH server:
pkg install openssh
sshd   # starts on port 8022

# From your computer, find the phone's IP:
# Check the WiFi settings on the phone for its IP address
# Then:
scp -P 8022 release/dev/daxson-android-arm64 user@<PHONE_IP>:~/.local/bin/daxson

# Inside Termux:
chmod +x ~/.local/bin/daxson
```

**Option C — Run the setup script:**
```bash
# Inside Termux, if you already have the binary in the current directory:
bash termux-setup.sh
```

### 4.3 Setup and connect

```bash
# Inside Termux:

# Check architecture (should be aarch64 on modern phones):
uname -m

# Verify binary:
daxson version

# Import invite:
daxson import 'daxson://v1/eyJz...'

# Connect:
daxson connect
```

### 4.4 Configure Android apps to use the proxy

Once `daxson connect` is running, set apps to use:
- **SOCKS5 proxy:** `127.0.0.1:1080`
- **HTTP proxy:** `127.0.0.1:8080`

For system-wide proxy on Android (requires Settings access):
```
Settings → Wi-Fi → Long-press network → Modify → Advanced → Proxy → Manual
Host: 127.0.0.1
Port: 1080
```

### 4.5 Background operation and keep-alive

```bash
# Prevent CPU sleep (keeps connection alive):
termux-wake-lock

# Run in background:
nohup daxson connect > ~/.daxson/connect.log 2>&1 &
echo $! > ~/.daxson/connect.pid

# Check if running:
daxson status

# Stop:
kill $(cat ~/.daxson/connect.pid)
```

### 4.6 LTE testing on Android

When testing on LTE (which is the critical scenario for Iranian censorship):

1. Disconnect WiFi, enable mobile data
2. Note that IP will change when switching networks
3. The reconnect mechanism handles IP changes automatically
4. Observe reconnect behavior:
   ```bash
   # In a second Termux session, watch status:
   watch -n 2 daxson status
   ```

---

## Phase 5 — Connectivity Validation

Run the full automated test suite after connecting:

```bash
daxson connect &   # or in a separate terminal

bash scripts/test-suite.sh
```

### Manual validation checklist

**[ ] 1. TCP connectivity to server port**
```bash
nc -zv gr.batmat.ir 443
# Expected: Connection to gr.batmat.ir 443 port [tcp/https] succeeded!
```

**[ ] 2. TLS handshake visible**
```bash
openssl s_client -connect gr.batmat.ir:443 -servername gr.batmat.ir \
  -alpn "h2,http/1.1" </dev/null 2>&1 | grep -E "CONNECTED|Protocol|Cipher"
```

**[ ] 3. Probe resistance (server looks like HTTPS site)**
```bash
curl -s https://gr.batmat.ir/ | head -5
# Expected: returns HTML from nginx (not connection error)
```

**[ ] 4. Tunnel import**
```bash
daxson import 'daxson://v1/eyJz...'
# Expected: ✓ Registered as <hostname>
```

**[ ] 5. Tunnel connect**
```bash
daxson connect
# Expected: Tunnel ready, SOCKS5 127.0.0.1:1080, HTTP 127.0.0.1:8080
```

**[ ] 6. IP routing through tunnel**
```bash
DIRECT=$(curl -s https://api.ipify.org)
TUNNEL=$(curl -x socks5h://127.0.0.1:1080 -s https://api.ipify.org)
echo "Direct: $DIRECT  Tunnel: $TUNNEL"
# They must be DIFFERENT. Tunnel IP = gr.batmat.ir's IP.
```

**[ ] 7. DNS via SOCKS5h (no DNS leaks)**
```bash
# socks5h = DNS resolved through proxy, not locally:
curl -x socks5h://127.0.0.1:1080 -s https://example.com | head -5
```

**[ ] 8. HTTP proxy**
```bash
curl -x http://127.0.0.1:8080 -s https://api.ipify.org
```

**[ ] 9. Browser traffic (Firefox)**
- Set SOCKS5 proxy to `127.0.0.1:1080`
- Visit `https://ipinfo.io` — should show gr.batmat.ir's IP and country
- Visit `https://youtube.com` — should load (not blocked)
- Visit `https://web.telegram.org` — should load

**[ ] 10. Telegram desktop**
- Settings → Privacy → Advanced → Proxy → SOCKS5 → `127.0.0.1:1080`
- Should connect and show "Connected"

**[ ] 11. daxson status output**
```bash
daxson status
# Expected:
# Connection
#   Server           gr.batmat.ir:443
#   Device           a1b2c3
#   Profile          default
#   Uptime           0m 42s
# Proxy
#   SOCKS5           127.0.0.1:1080
#   HTTP             127.0.0.1:8080
```

**[ ] 12. daxson doctor**
```bash
daxson doctor
# Expected: All checks passed.
```

---

## Phase 6 — Survivability Testing

### 6.1 Reconnect behavior test

```bash
# On the server: watch active sessions
journalctl -u daxson-serve -f | grep -i "session\|auth\|reconnect"

# On the client: connect with debug logging
daxson connect --log-level debug

# Then: kill and restore network (simulate network interruption)
# On Linux: sudo ip link set eth0 down; sleep 5; sudo ip link set eth0 up
# Watch the client reconnect automatically within 1-60 seconds.
```

Expected behavior: client reconnects with exponential backoff (1s, 2s, 4s, 8s, up to 60s).

### 6.2 Long-session stability (2-hour test)

```bash
# Start connection
daxson connect &

# Run continuous download for 2 hours:
timeout 7200 curl -x socks5h://127.0.0.1:1080 \
  -o /dev/null --limit-rate 500k \
  "https://speed.cloudflare.com/__down?bytes=10000000000" \
  --progress-bar

# Monitor in parallel:
watch -n 10 daxson status
```

Pass criteria: connection maintained throughout without manual intervention.

### 6.3 LTE switching test

Execute on the Android Termux device:

1. Start `daxson connect`
2. Switch from WiFi to LTE — observe automatic reconnect
3. Switch LTE operator (if dual-SIM)
4. Switch back to WiFi
5. Check `daxson status` after each switch — should show reconnect and re-establish

Expected: IP change triggers reconnect; connection restores within 30 seconds.

### 6.4 ISP comparison matrix

Test from different networks and record results:

| Network | TCP Connect | TLS Handshake | Tunnel Up | Latency | Notes |
|---------|-------------|---------------|-----------|---------|-------|
| Hamrah Aval (MCI) WiFi | | | | | |
| Hamrah Aval (MCI) LTE | | | | | |
| Irancell (MTN) WiFi | | | | | |
| Irancell (MTN) LTE | | | | | |
| Rightel LTE | | | | | |
| Home ADSL/FTTH | | | | | |
| Office network | | | | | |

Fill in: ✓ Pass / ✗ Fail / ~ Degraded

### 6.5 Packet loss tolerance test

Simulate packet loss using netem (Linux client):

```bash
# Add 10% packet loss:
sudo tc qdisc add dev eth0 root netem loss 10%

# Test: measure if tunnel stays connected
daxson connect --log-level debug &
sleep 30
daxson status

# Increase to 20%:
sudo tc qdisc change dev eth0 root netem loss 20%
sleep 30
daxson status

# Remove packet loss:
sudo tc qdisc del dev eth0 root

# Result: document at what % loss the tunnel becomes unusable
```

### 6.6 Idle timeout behavior

```bash
# Connect, then leave idle for 10 minutes:
daxson connect &
sleep 600
daxson status
# Expected: still connected (keepalive maintains session)

# Run a request after idle period:
curl -x socks5h://127.0.0.1:1080 -s https://api.ipify.org
# Expected: succeeds without manual reconnect
```

### 6.7 NAT rebinding test

On LTE networks, NAT entries time out after periods of inactivity (typically 2–10 minutes). The tunnel's keepalive mechanism handles this.

```bash
# Connect, then idle for exactly 5 minutes, then test:
daxson connect &
sleep 300
time curl -x socks5h://127.0.0.1:1080 -s https://api.ipify.org
# Measure the latency of the first request after idle.
# Expected: first request may be slow (NAT rebind), but succeeds.
```

### 6.8 Survivability validation checklist

| Test | Expected | Pass? | Notes |
|------|----------|-------|-------|
| Clean connect | < 3 seconds | | |
| Reconnect after network drop | < 60 seconds | | |
| LTE ↔ WiFi switch | Auto-reconnect | | |
| 2-hour continuous session | No drops | | |
| 10% packet loss | Functional | | |
| 20% packet loss | Degraded but functional | | |
| 30% packet loss | Acceptable degradation | | |
| 10-minute idle | Session stays alive | | |
| NAT rebind (5m idle) | First request < 5s | | |
| MCI LTE block test | Tunnel works | | |
| Irancell LTE block test | Tunnel works | | |

---

## Phase 7 — Troubleshooting

### Server-side diagnostics

```bash
# Real-time logs:
journalctl -u daxson-serve -f

# Last 100 lines with full detail:
journalctl -u daxson-serve -n 100 --no-pager

# Debug mode (more verbose):
# Edit /etc/daxson/server.yaml: logging.level: debug
# Then: systemctl restart daxson-serve

# Check server is listening on port 443:
ss -tlnp | grep :443
# Expected: LISTEN  0  4096  *:443  *:*  users:(("daxson",pid=...,fd=...))

# Check metrics (server health):
curl http://127.0.0.1:9090/healthz
# Expected: {"status":"ok"}

# Count active sessions:
curl -s http://127.0.0.1:9090/metrics | grep daxson_sessions_active
# Expected: daxson_sessions_active N

# Auth failures (high number = something is wrong or being probed):
curl -s http://127.0.0.1:9090/metrics | grep daxson_auth_failures_total

# Check certificate validity:
openssl x509 -noout -dates \
  -in /etc/letsencrypt/live/gr.batmat.ir/fullchain.pem

# Check if identity file was created:
sudo -u daxson ls -la /home/daxson/.daxson/
# Expected: identity.json server-identity.json registry.json (after first invite)
```

### Client-side diagnostics

```bash
# Run doctor first:
daxson doctor --profile default

# Debug-level connection:
daxson connect --log-level debug

# Check status:
daxson status

# Check identity:
daxson keys show

# Check profile:
cat ~/.daxson/profiles/default.yaml

# Test TCP directly (bypasses daxson):
nc -zv gr.batmat.ir 443

# Test DNS resolution:
nslookup gr.batmat.ir
dig gr.batmat.ir

# Check if SOCKS5 port is listening (after daxson connect):
ss -tlnp | grep 1080
# Expected: daxson listening on 127.0.0.1:1080

# Test SOCKS5 manually:
curl -v -x socks5h://127.0.0.1:1080 https://api.ipify.org 2>&1
```

### Common errors and fixes

**Error: `profile "default" not found`**
```
Cause: Haven't imported an invite yet.
Fix:   daxson import 'daxson://v1/...'
```

**Error: `dial gr.batmat.ir:443: connection refused`**
```
Cause: Server is not running, or firewall blocking port 443.
Fix on server: systemctl status daxson-serve
               journalctl -u daxson-serve -n 50
               ufw status
```

**Error: `auth failed` or connection drops immediately**
```
Cause: Device not in registry, or invite was revoked/expired.
Fix:   Re-import invite: daxson import 'daxson://v1/...'
       On server: sudo -u daxson daxson devices list
```

**Error: `TLS handshake error` or connection hangs**
```
Cause: Server TLS certificate issues, or ISP intercepting TLS.
Fix:   Check cert on server: openssl x509 -noout -dates -in /etc/letsencrypt/live/gr.batmat.ir/fullchain.pem
       Try different fingerprint: edit ~/.daxson/profiles/default.yaml
         tls.fingerprint: firefox   # or edge, safari
```

**Error: `SOCKS5: connection refused` (proxy not responding)**
```
Cause: daxson connect is not running, or SOCKS5 addr in use.
Fix:   Check if daxson is running: daxson status
       Check if port is in use: ss -tlnp | grep 1080
       Use different port: daxson connect --socks5 127.0.0.1:1081
```

**Warning: `Not connected (last seen Xs ago)`**
```
Cause: daxson connect process died or was killed.
Fix:   Restart: daxson connect
       If recurring: check system memory, check server logs
```

**Tunnel connects but traffic doesn't route (same IP via proxy)**
```
Cause: Traffic not going through SOCKS5, or DNS leak via direct connection.
Fix:   Make sure you're using socks5h:// not socks5:// (h = DNS over SOCKS)
       In browser: verify "Proxy DNS when using SOCKS v5" is checked
```

**High latency (>500ms)**
```
Cause: Congested path, packet loss, or wrong transport personality.
Fix:   Check server load: curl http://127.0.0.1:9090/metrics | grep bytes
       Try mobile personality: edit profile transport.obfs.personality: mobile
       Check if a relay node would reduce latency
```

**Android: binary crashes or "exec format error"**
```
Cause: Wrong architecture binary.
Fix:   Check: uname -m  (should be aarch64)
       Use: daxson-android-arm64 (for aarch64)
       Use: daxson-linux-arm (for armv7l/armv8l)
```

**Android: connection drops on LTE network switch**
```
Cause: Normal — IP changed. daxson reconnects automatically.
Check: daxson status   (should show re-established within 30s)
Fix if not reconnecting: daxson doctor
```

### Server dashboard access (SSH tunnel)

The management dashboard is bound to `127.0.0.1:9443` and not exposed publicly.

Access it via SSH port forwarding:

```bash
# Open SSH tunnel:
ssh -L 9443:127.0.0.1:9443 -N root@gr.batmat.ir &

# Open in browser:
# http://localhost:9443
```

The dashboard shows:
- Connected devices
- Active sessions
- Invite management (create/revoke)
- Transport analytics
- Probe detection events
- Reconnect metrics

### Reading structured JSON logs

Server logs are in JSON format. Parse with jq:

```bash
# All logs:
journalctl -u daxson-serve -n 200 --output=json | jq '.MESSAGE | fromjson? // .'

# Only errors:
journalctl -u daxson-serve | grep '"level":"error"' | jq .

# Watch auth events:
journalctl -u daxson-serve -f | jq 'select(.msg | contains("auth"))'

# Session events:
journalctl -u daxson-serve -f | jq 'select(.msg | contains("session"))'
```

### Enabling debug logging without restart

```bash
# On the server (edit config):
sed -i 's/level: info/level: debug/' /etc/daxson/server.yaml
systemctl restart daxson-serve

# On the client:
daxson connect --log-level debug

# Revert server to info after debugging:
sed -i 's/level: debug/level: info/' /etc/daxson/server.yaml
systemctl restart daxson-serve
```

---

## Phase 8 — Operational Recommendations

### Post-testing operational checklist

**[ ] Verify certificate auto-renewal**
```bash
certbot renew --dry-run
```

**[ ] Rotate PSK if shared with relay operators**
```bash
# Generate new PSK:
openssl rand -hex 32
# Update /etc/daxson/server.yaml and all relay configs, then restart
```

**[ ] Revoke test devices before production**
```bash
sudo -u daxson daxson devices list
sudo -u daxson daxson devices revoke <device-id>
```

**[ ] Set up log rotation**
```bash
# journald handles rotation automatically; verify:
journalctl --disk-usage
# If too large: journalctl --vacuum-size=500M
```

**[ ] Set up monitoring alert for service down**
```bash
# Cron-based health check (every 5 minutes):
cat > /etc/cron.d/daxson-health <<'EOF'
*/5 * * * * root curl -sf http://127.0.0.1:9090/healthz || \
  systemctl restart daxson-serve && \
  echo "daxson-serve restarted at $(date)" | mail -s "Daxson alert" admin@example.com
EOF
```

**[ ] Keep server identity backup**
```bash
# On the server, back up the server identity key:
sudo -u daxson cp /home/daxson/.daxson/server-identity.json \
  /root/daxson-server-identity-backup.json
chmod 0600 /root/daxson-server-identity-backup.json
# Store a copy off-server (encrypted)
```

**[ ] Review key rotation strategy**

The server identity key is long-lived (signing invite links). Plan:
- Never rotate unless compromised
- If rotated, all existing invite links become unverifiable (clients can still connect if already registered)
- After rotation, regenerate server identity: `systemctl stop daxson-serve && rm /home/daxson/.daxson/server-identity.json && systemctl start daxson-serve`

**[ ] Transport tuning for Iranian networks**

Based on survivability test results:
- If MCI LTE blocks: try `personality: mobile` or `personality: grpc`
- If deep packet inspection detected: try `personality: video` (mimics video streaming)
- If idle sessions drop: reduce `keepalive_interval` from 60s to 20s
- If Irancell throttles HTTPS: test relaying through a domestic node

**[ ] Add a relay node** (if direct path is blocked)

For cases where gr.batmat.ir is blocked from specific ISPs, add a domestic relay:

```yaml
# On the relay node, relay.yaml:
mode: relay
server:
  listen: ":443"
  tls:
    cert: /etc/letsencrypt/live/relay.example.ir/fullchain.pem
    key:  /etc/letsencrypt/live/relay.example.ir/privkey.pem
  auth:
    psk: "RELAY_DOWNSTREAM_PSK"
  probe_upstream: "127.0.0.1:80"
upstream:
  addr: gr.batmat.ir:443
  tls:
    server_name: gr.batmat.ir
    fingerprint: chrome
  auth:
    psk: "SERVER_PSK_FROM_INSTALL"   # the PSK from server.yaml
tunnel:
  transport:
    obfs:
      enabled: true
      personality: relay
```

Clients would then import an invite pointing to the relay, not the main server directly.

### Key commands quick reference

```bash
# SERVER SIDE
systemctl status daxson-serve            # service status
journalctl -u daxson-serve -f            # live logs
journalctl -u daxson-serve --since "1h ago"  # last hour
sudo -u daxson daxson keys show          # server identity
sudo -u daxson daxson invite list        # all invites
sudo -u daxson daxson invite create --server gr.batmat.ir:443 --label "name"
sudo -u daxson daxson invite revoke <id> # revoke invite
sudo -u daxson daxson devices list       # registered devices
sudo -u daxson daxson devices revoke <id>  # revoke device
curl http://127.0.0.1:9090/healthz       # health check
curl http://127.0.0.1:9090/metrics | grep daxson_  # metrics
ssh -L 9443:127.0.0.1:9443 -N root@gr.batmat.ir  # dashboard tunnel

# CLIENT SIDE
daxson import 'daxson://v1/...'          # register device
daxson connect                            # connect (default profile)
daxson connect --profile work            # use named profile
daxson connect --log-level debug         # debug mode
daxson status                            # live connection status
daxson doctor                            # run diagnostics
daxson keys show                         # device identity
daxson keys rotate                       # generate new key pair
curl -x socks5h://127.0.0.1:1080 https://api.ipify.org   # test SOCKS5
curl -x http://127.0.0.1:8080 https://api.ipify.org      # test HTTP proxy
bash scripts/test-suite.sh               # full automated test suite
```
