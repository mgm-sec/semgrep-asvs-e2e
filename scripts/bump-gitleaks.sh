#!/usr/bin/env bash
# Bump the pinned gitleaks version everywhere: install script (+ checksums) and Python module.
set -euo pipefail
v="${1:?usage: scripts/bump-gitleaks.sh <version, e.g. 8.31.0>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
sums="$(curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${v}/gitleaks_${v}_checksums.txt")"
inst="$ROOT/semgrep_asvs/install-gitleaks.sh"
sed -i.bak "s/^GITLEAKS_VERSION=.*/GITLEAKS_VERSION=${v}/" "$inst"
for t in linux_x64 linux_arm64 darwin_x64 darwin_arm64; do
  s="$(echo "$sums" | grep "gitleaks_${v}_${t}.tar.gz" | cut -d' ' -f1)"
  sed -i.bak "s/^SHA256_${t}=.*/SHA256_${t}=${s}/" "$inst"
done
sed -i.bak "s/^GITLEAKS_VERSION = \".*\"/GITLEAKS_VERSION = \"${v}\"/" "$ROOT/semgrep_asvs/__init__.py"
rm -f "$inst.bak" "$ROOT/semgrep_asvs/__init__.py.bak"
echo "gitleaks pinned to v${v}; run make test"
