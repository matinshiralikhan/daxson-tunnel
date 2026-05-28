#!/usr/bin/env bash
# build-release.sh — Cross-compile daxson for all deployment targets.
#
# Outputs go to release/<VERSION>/
# Run from the repository root: bash scripts/build-release.sh
set -euo pipefail

VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
OUTDIR="release/${VERSION}"
LDFLAGS="-s -w -X github.com/daxson/tunnel/cmd/daxson/cmd.Version=${VERSION}"
GOFLAGS="-trimpath -ldflags=${LDFLAGS}"

echo "Building Daxson ${VERSION}"
echo "Output: ${OUTDIR}/"
echo ""

mkdir -p "${OUTDIR}"

build() {
    local GOOS=$1
    local GOARCH=$2
    local BINARY=$3
    local TAGS=${4:-""}

    local EXT=""
    [[ "$GOOS" == "windows" ]] && EXT=".exe"

    local OUT="${OUTDIR}/${BINARY}${EXT}"

    echo -n "  Building ${BINARY}${EXT} (${GOOS}/${GOARCH})... "
    CGO_ENABLED=0 GOOS="${GOOS}" GOARCH="${GOARCH}" \
        go build ${GOFLAGS} ${TAGS:+-tags "$TAGS"} \
        -o "${OUT}" ./cmd/daxson
    echo "OK ($(du -sh "$OUT" | cut -f1))"
}

build_server() {
    local GOOS=$1
    local GOARCH=$2
    local BINARY=$3

    local OUT="${OUTDIR}/${BINARY}"
    echo -n "  Building ${BINARY} (${GOOS}/${GOARCH})... "
    CGO_ENABLED=0 GOOS="${GOOS}" GOARCH="${GOARCH}" \
        go build ${GOFLAGS} \
        -o "${OUT}" ./cmd/daxsond
    echo "OK ($(du -sh "$OUT" | cut -f1))"
}

echo "==> Client (daxson)"
build linux   amd64 daxson-linux-amd64
build linux   arm64 daxson-linux-arm64
build windows amd64 daxson-windows-amd64
# Android uses Linux arm64 — Termux runs a Linux userspace on Android
build linux   arm64 daxson-android-arm64
build linux   arm   daxson-android-arm   # older 32-bit Android devices

echo ""
echo "==> Server daemon (daxsond)"
build_server linux amd64 daxsond-linux-amd64
build_server linux arm64 daxsond-linux-arm64

echo ""
echo "==> Checksums"
(cd "${OUTDIR}" && sha256sum * > SHA256SUMS)
cat "${OUTDIR}/SHA256SUMS"

echo ""
echo "Done. Artifacts in ${OUTDIR}/"
echo ""
echo "Quick verification:"
echo "  file ${OUTDIR}/daxson-linux-amd64"
echo "  file ${OUTDIR}/daxson-android-arm64"
