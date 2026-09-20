#!/usr/bin/env bash
# Re-vendor opengrep-rules (LGPL 2.1 + Commons Clause) at the pinned commit. Never edits files.
set -euo pipefail
OPENGREP_RULES_COMMIT=f1d2b562b414783763fd02a6ed2736eaed622efa
LANGS="python php javascript typescript go"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/semgrep_asvs/rules/vendor"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Shallow fetch of exactly the pinned commit (GitHub allows fetching reachable SHAs).
git init -q "$TMP/src"
git -C "$TMP/src" remote add origin https://github.com/opengrep/opengrep-rules.git
git -C "$TMP/src" fetch -q --depth 1 origin "$OPENGREP_RULES_COMMIT"
git -C "$TMP/src" checkout -q FETCH_HEAD -- $LANGS LICENSE

mkdir -p "$DEST"
for l in $LANGS; do
  rm -rf "$DEST/$l"
  cp -R "$TMP/src/$l" "$DEST/$l"
done
cp "$TMP/src/LICENSE" "$DEST/LICENSE"
echo "$OPENGREP_RULES_COMMIT" > "$DEST/VENDOR-COMMIT"
echo "vendored opengrep-rules@$OPENGREP_RULES_COMMIT into $DEST"
