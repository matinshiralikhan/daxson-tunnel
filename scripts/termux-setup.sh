#!/data/data/com.termux/files/usr/bin/bash
# termux-setup.sh — Daxson client setup for Android Termux.
#
# Run this inside Termux on your Android device:
#   curl -fsSL https://your-server/termux-setup.sh | bash
# Or copy the file and run:
#   bash termux-setup.sh
#
# What this does:
#   1. Installs required Termux packages
#   2. Downloads or uses the daxson-android-arm64 binary
#   3. Creates the config directory
#   4. Provides instructions for importing an invite and connecting

set -euo pipefail

BINARY_NAME="daxson-android-arm64"
INSTALL_DIR="${HOME}/.local/bin"
BINARY_PATH="${INSTALL_DIR}/daxson"
CONFIG_DIR="${HOME}/.daxson"

RESET="\033[0m"
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
BOLD="\033[1m"

ok()   { echo -e "  ${GREEN}✓${RESET} $*"; }
warn() { echo -e "  ${YELLOW}!${RESET} $*"; }
fail() { echo -e "  ${RED}✗${RESET} $*" >&2; exit 1; }
step() { echo -e "\n${BOLD}$*${RESET}"; }

# Detect architecture
ARCH=$(uname -m)
case "${ARCH}" in
    aarch64|arm64)  ARCH_LABEL="arm64" ;;
    armv7l|armv8l)  ARCH_LABEL="arm"   ;;
    x86_64)         ARCH_LABEL="amd64" ;;
    *)              fail "Unsupported architecture: ${ARCH}" ;;
esac

echo ""
echo -e "${BOLD}Daxson Termux Setup${RESET}"
echo -e "Architecture: ${ARCH} → ${ARCH_LABEL}"
echo ""

# ── Step 1: Termux packages ───────────────────────────────────────────────────
step "Step 1 — Termux packages"
pkg update -y -q
pkg install -y curl termux-tools
ok "Packages ready"

# ── Step 2: Binary ───────────────────────────────────────────────────────────
step "Step 2 — Binary"
mkdir -p "${INSTALL_DIR}"

if [[ -f "./${BINARY_NAME}" ]]; then
    cp "./${BINARY_NAME}" "${BINARY_PATH}"
    chmod +x "${BINARY_PATH}"
    ok "Installed from ./${BINARY_NAME}"
elif [[ -f "./daxson-linux-${ARCH_LABEL}" ]]; then
    cp "./daxson-linux-${ARCH_LABEL}" "${BINARY_PATH}"
    chmod +x "${BINARY_PATH}"
    ok "Installed from ./daxson-linux-${ARCH_LABEL}"
elif command -v daxson &>/dev/null; then
    ok "daxson already installed: $(which daxson)"
    BINARY_PATH=$(which daxson)
else
    echo ""
    warn "Binary not found locally."
    echo "  Transfer the binary to this device via one of:"
    echo ""
    echo "  Option A — from your computer over SSH:"
    echo "    # Install SSH server in Termux:"
    echo "    pkg install openssh"
    echo "    sshd"
    echo "    # Then from your computer (check your phone's IP first):"
    echo "    adb shell ip addr | grep inet"
    echo "    scp release/<VERSION>/daxson-android-arm64 \\
      user@<PHONE_IP>:8022:~/.local/bin/daxson"
    echo ""
    echo "  Option B — via adb:"
    echo "    adb push release/<VERSION>/daxson-android-arm64 \\
      /data/local/tmp/daxson"
    echo "    # Then inside Termux:"
    echo "    cp /data/local/tmp/daxson ~/.local/bin/daxson"
    echo "    chmod +x ~/.local/bin/daxson"
    echo ""
    echo "  After transferring, re-run this script."
    exit 0
fi

# Verify binary runs
if ! "${BINARY_PATH}" version &>/dev/null; then
    fail "Binary does not execute. Wrong architecture?"
fi
ok "Binary works: $(${BINARY_PATH} version)"

# ── Step 3: PATH setup ────────────────────────────────────────────────────────
step "Step 3 — PATH"
SHELL_RC="${HOME}/.bashrc"
if [[ -f "${HOME}/.zshrc" ]]; then
    SHELL_RC="${HOME}/.zshrc"
fi

if ! grep -q "${INSTALL_DIR}" "${SHELL_RC}" 2>/dev/null; then
    echo "export PATH=\"${INSTALL_DIR}:\$PATH\"" >> "${SHELL_RC}"
    ok "Added ${INSTALL_DIR} to PATH in ${SHELL_RC}"
else
    ok "PATH already configured"
fi
export PATH="${INSTALL_DIR}:${PATH}"

# ── Step 4: Config directory ──────────────────────────────────────────────────
step "Step 4 — Config directory"
mkdir -p "${CONFIG_DIR}/profiles"
ok "Config directory: ${CONFIG_DIR}"

# ── Step 5: Instructions ─────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}════════════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD}  Setup complete!${RESET}"
echo -e "${BOLD}════════════════════════════════════════════${RESET}"
echo ""
echo "  Binary:   ${BINARY_PATH}"
echo "  Config:   ${CONFIG_DIR}"
echo ""
echo -e "${BOLD}  Next steps:${RESET}"
echo ""
echo "  1. Get an invite link from your server admin."
echo "     It looks like:  daxson://v1/eyJz..."
echo ""
echo "  2. Import the invite (registers this device):"
echo "     daxson import 'daxson://v1/eyJz...'"
echo ""
echo "  3. Connect:"
echo "     daxson connect"
echo ""
echo "  4. Verify the tunnel works:"
echo "     # In a second Termux session:"
echo "     curl -x socks5h://127.0.0.1:1080 https://api.ipify.org"
echo "     # Should return your server's IP, not your phone's IP"
echo ""
echo "  5. Configure your Android apps to use the proxy:"
echo "     SOCKS5: 127.0.0.1:1080"
echo "     HTTP:   127.0.0.1:8080"
echo ""
echo "  Useful commands:"
echo "    daxson status            — check if connected"
echo "    daxson doctor            — run diagnostics"
echo "    daxson connect --log-level debug   — verbose output"
echo ""
echo "  To keep connection alive in background (Termux wake-lock):"
echo "    termux-wake-lock         — prevent CPU sleep"
echo "    daxson connect &         — run in background"
echo "    disown                   — detach from shell"
echo ""
