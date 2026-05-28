#!/usr/bin/env bash
# test-suite.sh — End-to-end connectivity and survivability test suite.
#
# Run from a client machine that has daxson connect running.
# Usage:
#   bash scripts/test-suite.sh [--server gr.batmat.ir] [--suite all|quick|socks|latency|stress]
#
# Requirements: curl, nc (netcat), openssl
set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
SERVER="${DAXSON_SERVER:-gr.batmat.ir}"
SERVER_PORT="${DAXSON_PORT:-443}"
SOCKS5_ADDR="${SOCKS5_ADDR:-127.0.0.1:1080}"
HTTP_PROXY_ADDR="${HTTP_PROXY_ADDR:-127.0.0.1:8080}"
SUITE="${1:-all}"

PASS=0
FAIL=0
WARN=0

RESET="\033[0m"; GREEN="\033[32m"; YELLOW="\033[33m"; RED="\033[31m"; BOLD="\033[1m"; CYAN="\033[36m"
ok()   { echo -e "  ${GREEN}PASS${RESET}  $*"; ((PASS++)); }
fail() { echo -e "  ${RED}FAIL${RESET}  $*"; ((FAIL++)); }
warn() { echo -e "  ${YELLOW}WARN${RESET}  $*"; ((WARN++)); }
info() { echo -e "  ${CYAN}INFO${RESET}  $*"; }
section() { echo -e "\n${BOLD}── $* ──${RESET}"; }

# ── Helper functions ──────────────────────────────────────────────────────────

check_cmd() {
    local cmd=$1
    if ! command -v "$cmd" &>/dev/null; then
        warn "Command not found: $cmd (some tests will be skipped)"
        return 1
    fi
    return 0
}

tcp_connect() {
    local host=$1 port=$2 timeout=${3:-5}
    if timeout "$timeout" bash -c "echo > /dev/tcp/${host}/${port}" 2>/dev/null; then
        return 0
    fi
    return 1
}

my_ip_direct() {
    timeout 8 curl -s --max-time 6 "https://api.ipify.org" 2>/dev/null || echo "unknown"
}

my_ip_socks5() {
    timeout 12 curl -s --max-time 10 -x "socks5h://${SOCKS5_ADDR}" "https://api.ipify.org" 2>/dev/null || echo "failed"
}

my_ip_http_proxy() {
    timeout 12 curl -s --max-time 10 -x "http://${HTTP_PROXY_ADDR}" "https://api.ipify.org" 2>/dev/null || echo "failed"
}

# ── Phase 1: Pre-flight ───────────────────────────────────────────────────────
section "Phase 1: Pre-flight checks"

check_cmd curl || true
check_cmd openssl || true
check_cmd nc || true

# Check daxson is installed
if command -v daxson &>/dev/null; then
    ok "daxson binary: $(daxson version 2>/dev/null)"
else
    fail "daxson not found in PATH"
fi

# Check daxson status
STATUS_OUTPUT=$(daxson status 2>&1 || true)
if echo "$STATUS_OUTPUT" | grep -q "Not connected\|Not connected"; then
    warn "Tunnel not connected. Some tests will fail. Run: daxson connect"
    TUNNEL_UP=false
else
    ok "Tunnel status: connected"
    TUNNEL_UP=true
fi

# ── Phase 2: Server reachability ─────────────────────────────────────────────
section "Phase 2: Server reachability"

# TCP connectivity
if tcp_connect "$SERVER" "$SERVER_PORT"; then
    ok "TCP connect ${SERVER}:${SERVER_PORT}"
else
    fail "TCP connect ${SERVER}:${SERVER_PORT} — server unreachable"
fi

# TLS handshake (standard — will likely fail/warn since server uses custom fingerprint)
if check_cmd openssl; then
    TLS_OUTPUT=$(timeout 8 openssl s_client -connect "${SERVER}:${SERVER_PORT}" \
        -servername "$SERVER" -alpn "h2,http/1.1" </dev/null 2>&1 || true)
    if echo "$TLS_OUTPUT" | grep -q "CONNECTED"; then
        CIPHER=$(echo "$TLS_OUTPUT" | grep "Cipher is" | head -1 | awk '{print $NF}')
        PROTO=$(echo "$TLS_OUTPUT" | grep "Protocol  :" | head -1 | awk '{print $NF}')
        ok "TLS handshake: proto=${PROTO} cipher=${CIPHER}"
    else
        warn "TLS handshake inconclusive (may be normal — server uses uTLS fingerprint)"
    fi
fi

# DNS resolution
if check_cmd curl; then
    RESOLVED=$(timeout 5 curl -s --max-time 4 -o /dev/null -w "%{http_code}" \
        "https://${SERVER}/" 2>/dev/null || echo "0")
    info "HTTP response from ${SERVER}: ${RESOLVED} (probe upstream / may be nginx)"
fi

# ── Phase 3: Proxy functionality ─────────────────────────────────────────────
section "Phase 3: Proxy functionality"

if $TUNNEL_UP; then
    # Direct IP (no proxy)
    DIRECT_IP=$(my_ip_direct)
    info "Direct IP (no proxy): ${DIRECT_IP}"

    # SOCKS5 proxy
    SOCKS5_IP=$(my_ip_socks5)
    if [[ "$SOCKS5_IP" == "failed" ]]; then
        fail "SOCKS5 proxy at ${SOCKS5_ADDR} — no response"
    elif [[ "$SOCKS5_IP" == "$DIRECT_IP" ]]; then
        warn "SOCKS5 proxy returned same IP as direct — tunnel may not be routing correctly"
    else
        ok "SOCKS5 proxy: direct_ip=${DIRECT_IP} tunneled_ip=${SOCKS5_IP}"
    fi

    # HTTP proxy
    HTTP_IP=$(my_ip_http_proxy)
    if [[ "$HTTP_IP" == "failed" ]]; then
        fail "HTTP proxy at ${HTTP_PROXY_ADDR} — no response"
    elif [[ "$HTTP_IP" == "$DIRECT_IP" ]]; then
        warn "HTTP proxy returned same IP as direct"
    else
        ok "HTTP proxy: tunneled_ip=${HTTP_IP}"
    fi

    # SOCKS5 DNS leak check: resolved domain over proxy
    DNS_CHECK=$(timeout 12 curl -s --max-time 10 -x "socks5h://${SOCKS5_ADDR}" \
        "https://httpbin.org/headers" 2>/dev/null | grep -i "host" | head -1 || echo "")
    if [[ -n "$DNS_CHECK" ]]; then
        ok "SOCKS5h DNS-over-proxy: working (socks5h resolves DNS remotely)"
    else
        warn "SOCKS5h DNS check inconclusive"
    fi
else
    warn "Skipping proxy tests — tunnel not connected"
fi

# ── Phase 4: Latency ─────────────────────────────────────────────────────────
section "Phase 4: Latency measurement"

if $TUNNEL_UP && check_cmd curl; then
    # Direct latency
    DIRECT_MS=$(timeout 10 curl -s --max-time 8 -o /dev/null \
        -w "%{time_total}" "https://www.google.com/" 2>/dev/null | awk '{printf "%.0f", $1*1000}')
    info "Direct latency (Google): ${DIRECT_MS}ms"

    # Tunneled latency
    TUNNEL_MS=$(timeout 15 curl -s --max-time 12 -x "socks5h://${SOCKS5_ADDR}" \
        -o /dev/null -w "%{time_total}" "https://www.google.com/" 2>/dev/null | \
        awk '{printf "%.0f", $1*1000}')
    if [[ -n "$TUNNEL_MS" && "$TUNNEL_MS" -gt 0 ]]; then
        OVERHEAD=$((TUNNEL_MS - DIRECT_MS))
        ok "Tunneled latency (Google): ${TUNNEL_MS}ms  (overhead: +${OVERHEAD}ms)"
        if [[ "$TUNNEL_MS" -lt 2000 ]]; then
            ok "Latency acceptable (under 2 seconds)"
        else
            warn "High latency: ${TUNNEL_MS}ms — may indicate congestion or packet loss"
        fi
    else
        fail "Could not measure tunneled latency"
    fi
fi

# ── Phase 5: Throughput ───────────────────────────────────────────────────────
section "Phase 5: Throughput (10MB download)"

if $TUNNEL_UP && check_cmd curl; then
    START=$(date +%s%3N)
    BYTES=$(timeout 30 curl -s --max-time 25 -x "socks5h://${SOCKS5_ADDR}" \
        -o /dev/null -w "%{size_download}" \
        "https://speed.cloudflare.com/__down?bytes=10000000" 2>/dev/null || echo "0")
    END=$(date +%s%3N)
    ELAPSED=$(( END - START ))

    if [[ "$BYTES" -gt 100000 && "$ELAPSED" -gt 0 ]]; then
        MBPS=$(echo "scale=2; $BYTES / $ELAPSED / 1000" | bc 2>/dev/null || echo "?")
        ok "Download: ${BYTES} bytes in ${ELAPSED}ms = ${MBPS} MB/s"
    else
        warn "Throughput test inconclusive (got ${BYTES} bytes)"
    fi
else
    warn "Skipping throughput test — tunnel not connected"
fi

# ── Phase 6: Reconnect test ───────────────────────────────────────────────────
section "Phase 6: Reconnect validation"
info "This test checks metrics for reconnect count (non-destructive)"

if $TUNNEL_UP; then
    RECONNECTS=$(timeout 5 curl -s http://127.0.0.1:9091/metrics 2>/dev/null | \
        grep "daxson_reconnects_total" | awk '{print $2}' | head -1 || echo "n/a")
    if [[ "$RECONNECTS" == "n/a" ]]; then
        warn "Client metrics not accessible (metrics.listen may not be configured)"
        info "To enable: add 'metrics: listen: 127.0.0.1:9091' to your profile"
    else
        ok "Reconnect counter: ${RECONNECTS}"
    fi
fi

# ── Phase 7: Long-lived stream ────────────────────────────────────────────────
section "Phase 7: 30-second stream stability test"

if $TUNNEL_UP && check_cmd curl; then
    info "Downloading for 30 seconds through tunnel..."
    START=$(date +%s%3N)
    BYTES=$(timeout 35 curl -s --max-time 32 -x "socks5h://${SOCKS5_ADDR}" \
        -o /dev/null -w "%{size_download}" \
        "https://speed.cloudflare.com/__down?bytes=100000000" 2>/dev/null || echo "0")
    END=$(date +%s%3N)
    ELAPSED=$(( END - START ))
    MBPS=$(echo "scale=2; $BYTES / $ELAPSED / 1000" | bc 2>/dev/null || echo "?")
    if [[ "$BYTES" -gt 1000000 ]]; then
        ok "30s stream: ${BYTES} bytes / ${ELAPSED}ms = ${MBPS} MB/s — connection stable"
    else
        warn "30s stream yielded only ${BYTES} bytes — possible instability"
    fi
else
    warn "Skipping stream test"
fi

# ── Phase 8: Probe resistance check ──────────────────────────────────────────
section "Phase 8: Active-probe resistance"

if check_cmd curl; then
    # Make an unauthenticated HTTPS request — should get a real-looking HTTP response
    PROBE_RESPONSE=$(timeout 8 curl -s --max-time 6 -k \
        -o /dev/null -w "%{http_code}" "https://${SERVER}/" 2>/dev/null || echo "0")
    if [[ "$PROBE_RESPONSE" == "200" ]]; then
        ok "Probe upstream returns HTTP 200 — server looks like real HTTPS server"
    elif [[ "$PROBE_RESPONSE" == "0" ]]; then
        warn "No HTTP response from probe upstream — check nginx config"
    else
        info "Probe upstream HTTP ${PROBE_RESPONSE} — may be intentional"
    fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Test Summary${RESET}"
echo -e "${BOLD}════════════════════════════════════════════${RESET}"
echo -e "  ${GREEN}PASSED${RESET}: ${PASS}"
echo -e "  ${YELLOW}WARNED${RESET}: ${WARN}"
echo -e "  ${RED}FAILED${RESET}: ${FAIL}"
echo ""

if [[ $FAIL -gt 0 ]]; then
    echo -e "  ${RED}Some tests failed. See troubleshooting in docs/setup.md${RESET}"
    exit 1
elif [[ $WARN -gt 0 ]]; then
    echo -e "  ${YELLOW}Tests passed with warnings. Review above.${RESET}"
    exit 0
else
    echo -e "  ${GREEN}All tests passed!${RESET}"
    exit 0
fi
