#!/usr/bin/env bash
# Download the pinned gitleaks release binary (MIT) for linux/darwin x64/arm64, verify SHA-256, install to $1.
# Pins below are rewritten by scripts/bump-gitleaks.sh. Shipped in the wheel; semgrep-asvs runs it to auto-install.
set -euo pipefail
GITLEAKS_VERSION=8.30.1
SHA256_linux_x64=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
SHA256_linux_arm64=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080
SHA256_darwin_x64=dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709
SHA256_darwin_arm64=b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5

DEST="${1:-$HOME/.local/bin}"
os="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$(uname -m)" in
  x86_64|amd64) arch=x64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "unsupported arch: $(uname -m)" >&2; exit 1 ;;
esac
sum_var="SHA256_${os}_${arch}"
expected="${!sum_var:-}"
[ -n "$expected" ] || { echo "no checksum pinned for ${os}_${arch}" >&2; exit 1; }

asset="gitleaks_${GITLEAKS_VERSION}_${os}_${arch}.tar.gz"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${asset}" -o "$tmp/$asset"
echo "${expected}  $tmp/$asset" | shasum -a 256 -c - >/dev/null
mkdir -p "$DEST"
tar -xzf "$tmp/$asset" -C "$tmp" gitleaks
install -m 0755 "$tmp/gitleaks" "$DEST/gitleaks"
echo "installed gitleaks v${GITLEAKS_VERSION} to $DEST/gitleaks"
