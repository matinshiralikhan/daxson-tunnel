#!/usr/bin/env bash
# server-install.sh — One-shot Daxson server installation for Ubuntu/Debian.
#
# Run as root on the server:
#   bash server-install.sh
#
# What this script does:
#   1. Installs system packages (certbot, nginx, curl)
#   2. Creates daxson system user
#   3. Installs the daxson binary
#   4. Obtains a Let's Encrypt TLS certificate
#   5. Writes the production server config
#   6. Configures nginx for probe resistance
#   7. Configures ufw firewall
#   8. Installs and enables the systemd service
#   9. Starts the server
#
# After running this script, create your first invite link:
#   sudo -u daxson daxson invite create --server gr.batmat.ir:443 --label "test-v1"
set -euo pipefail

# ── Configuration — edit these before running ────────────────────────────────
DOMAIN="gr.batmat.ir"
CERTBOT_EMAIL=""           # Set your email for Let's Encrypt expiry notices
BINARY_URL=""              # URL to download the binary, or leave empty to build locally

# ── Derived paths ─────────────────────────────────────────────────────────────
CERT_DIR="/etc/letsencrypt/live/${DOMAIN}"
DAXSON_HOME="/home/daxson"
CONFIG_DIR="${DAXSON_HOME}/.daxson"
CONFIG_FILE="${CONFIG_DIR}/server.yaml"
BINARY_DST="/usr/local/bin/daxson"
SERVICE_FILE="/etc/systemd/system/daxson-serve.service"

RESET="\033[0m"
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
BOLD="\033[1m"

ok()   { echo -e "  ${GREEN}✓${RESET} $*"; }
warn() { echo -e "  ${YELLOW}!${RESET} $*"; }
fail() { echo -e "  ${RED}✗${RESET} $*" >&2; exit 1; }
step() { echo -e "\n${BOLD}$*${RESET}"; }

[[ $EUID -ne 0 ]] && fail "Must run as root"

# ── Step 1: System packages ───────────────────────────────────────────────────
step "Step 1 — System packages"
apt-get update -qq
apt-get install -y --no-install-recommends certbot nginx curl ufw
ok "Packages installed"

# ── Step 2: daxson system user ────────────────────────────────────────────────
step "Step 2 — System user"
if id daxson &>/dev/null; then
    warn "User 'daxson' already exists — skipping creation"
else
    useradd --system --shell /sbin/nologin --create-home --home-dir "${DAXSON_HOME}" daxson
    ok "Created system user 'daxson' (home: ${DAXSON_HOME})"
fi

# ── Step 3: Binary ───────────────────────────────────────────────────────────
step "Step 3 — Install binary"
if [[ -n "${BINARY_URL}" ]]; then
    curl -fsSL "${BINARY_URL}" -o "${BINARY_DST}"
    chmod +x "${BINARY_DST}"
    ok "Downloaded binary from ${BINARY_URL}"
elif [[ -f "bin/daxson-linux-amd64" ]]; then
    install -m 0755 bin/daxson-linux-amd64 "${BINARY_DST}"
    ok "Installed from bin/daxson-linux-amd64"
elif command -v daxson &>/dev/null; then
    ok "daxson already in PATH: $(which daxson)"
else
    fail "No binary found. Either:
  - Build first: bash scripts/build-release.sh
  - Set BINARY_URL to a download URL
  - Or install Go 1.22 and run: CGO_ENABLED=0 go build -o ${BINARY_DST} ./cmd/daxson"
fi
echo "    Version: $(${BINARY_DST} version 2>/dev/null || echo unknown)"

# ── Step 4: TLS certificate ───────────────────────────────────────────────────
step "Step 4 — TLS certificate"
if [[ -f "${CERT_DIR}/fullchain.pem" ]]; then
    ok "Certificate already exists: ${CERT_DIR}"
    openssl x509 -noout -dates -in "${CERT_DIR}/fullchain.pem" | sed 's/^/    /'
else
    # Stop nginx temporarily so certbot can use port 80
    systemctl stop nginx 2>/dev/null || true

    CERTBOT_ARGS="--standalone --non-interactive --agree-tos -d ${DOMAIN}"
    if [[ -n "${CERTBOT_EMAIL}" ]]; then
        CERTBOT_ARGS="${CERTBOT_ARGS} --email ${CERTBOT_EMAIL}"
    else
        CERTBOT_ARGS="${CERTBOT_ARGS} --register-unsafely-without-email"
    fi
    # shellcheck disable=SC2086
    certbot certonly ${CERTBOT_ARGS}
    ok "Certificate issued: ${CERT_DIR}"

    # Let certbot read certs after renewal
    chmod 0755 /etc/letsencrypt/{live,archive} 2>/dev/null || true
fi

# ── Step 5: Directory layout and config ──────────────────────────────────────
step "Step 5 — Configuration"
mkdir -p "${CONFIG_DIR}"
chown -R daxson:daxson "${CONFIG_DIR}"
chmod 0700 "${CONFIG_DIR}"

# Generate a strong PSK for relay-to-relay connections
PSK=$(openssl rand -hex 32)

cat > "${CONFIG_FILE}" <<EOF
mode: server

server:
  listen: ":443"
  tls:
    cert: ${CERT_DIR}/fullchain.pem
    key:  ${CERT_DIR}/privkey.pem
    next_protos:
      - h2
      - http/1.1
  auth:
    # PSK is used only for relay-to-relay (daxsond ↔ relay) connections.
    # Device clients use Ed25519 identity — PSK is not shared with them.
    psk: "${PSK}"
  # identity_key and registry are omitted here — they default to:
  #   ~/.daxson/server-identity.json  (auto-generated on first start)
  #   ~/.daxson/registry.json
  # Forward unauthenticated connections to nginx (active-probe resistance).
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
chown daxson:daxson "${CONFIG_FILE}"
chmod 0640 "${CONFIG_FILE}"
ok "Config written: ${CONFIG_FILE}"
warn "PSK (relay-to-relay auth): ${PSK}"
warn "Save this PSK — you will need it when adding relay nodes."

# ── Step 6: nginx probe resistance ───────────────────────────────────────────
step "Step 6 — nginx probe resistance"
mkdir -p /var/www/daxson-probe
cat > /var/www/daxson-probe/index.html <<'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Welcome</title></head>
<body><h1>Welcome</h1><p>This server provides HTTPS services.</p></body>
</html>
HTMLEOF

cat > /etc/nginx/sites-available/daxson-probe <<'NGINXEOF'
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
NGINXEOF

ln -sf /etc/nginx/sites-available/daxson-probe /etc/nginx/sites-enabled/daxson-probe
rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
nginx -t && systemctl enable --now nginx
ok "nginx configured for probe resistance on 127.0.0.1:8080"

# ── Step 7: Firewall ─────────────────────────────────────────────────────────
step "Step 7 — Firewall"
ufw --force reset > /dev/null
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 443/tcp comment "daxson tunnel"
ufw --force enable
ok "Firewall configured: SSH + port 443 open"
ufw status numbered | sed 's/^/    /'

# ── Step 8: systemd service ───────────────────────────────────────────────────
step "Step 8 — systemd service"
cat > "${SERVICE_FILE}" <<SVCEOF
[Unit]
Description=Daxson Tunnel Server (device-auth mode)
Documentation=https://github.com/daxson/tunnel
After=network-online.target nginx.service
Wants=network-online.target

[Service]
Type=simple
User=daxson
Group=daxson

ExecStart=${BINARY_DST} serve --config ${CONFIG_FILE}
ExecReload=/bin/kill -HUP \$MAINPID

Restart=on-failure
RestartSec=5s
StartLimitBurst=10
StartLimitIntervalSec=60

LimitNOFILE=131072
LimitNPROC=8192

NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=false
ReadWritePaths=${CONFIG_DIR}
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

StandardOutput=journal
StandardError=journal
SyslogIdentifier=daxson-serve

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable daxson-serve
ok "Service installed and enabled: daxson-serve"

# ── Step 9: First start ───────────────────────────────────────────────────────
step "Step 9 — Start service"
systemctl start daxson-serve
sleep 3

if systemctl is-active --quiet daxson-serve; then
    ok "Service is running"
    echo ""
    echo "    Server identity and registry are auto-generated on first start."
    echo "    Check: sudo -u daxson daxson keys show"
else
    fail "Service failed to start. Check: journalctl -u daxson-serve -n 50"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}════════════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD}  Installation complete!${RESET}"
echo -e "${BOLD}════════════════════════════════════════════${RESET}"
echo ""
echo "  Domain:   ${DOMAIN}"
echo "  Config:   ${CONFIG_FILE}"
echo "  Logs:     journalctl -u daxson-serve -f"
echo "  Metrics:  curl http://127.0.0.1:9090/metrics"
echo "  Health:   curl http://127.0.0.1:9090/healthz"
echo "  Dashboard: http://127.0.0.1:9443  (via SSH tunnel)"
echo ""
echo "  Next step — create your first invite link:"
echo "    sudo -u daxson daxson invite create \\"
echo "      --server ${DOMAIN}:443 \\"
echo "      --label \"test-device-1\" \\"
echo "      --ttl 24h"
echo ""
echo "  The invite link will look like:"
echo "    daxson://v1/eyJ..."
echo ""
echo "  Give that link to the client and have them run:"
echo "    daxson import 'daxson://v1/eyJ...'"
echo "    daxson connect"
echo ""
