# semgrep-asvs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A pip-installable package that runs Semgrep with vendored opengrep-rules plus six custom rules and reports findings against OWASP ASVS 4.0.3 requirements and levels, usable as pre-commit hook, GitHub Action and CLI.

**Architecture:** One stdlib-only Python module (`semgrep_asvs/__init__.py`) shells out to Semgrep once, then joins rule CWE metadata (and an overrides file, and `metadata.asvs` on custom rules) to the ASVS JSON to produce text, Markdown, ASVS-tagged SARIF and JSON. Rules and ASVS data ship inside the package so a checkout and a pip install behave identically. Consumer surfaces (pre-commit hook, composite Action, Makefile) are thin wrappers around the CLI.

**Tech Stack:** Python ≥ 3.10 (stdlib only at runtime), Semgrep CE 1.177.0, hatchling, pre-commit, GitHub Actions, Renovate.

**Spec:** `docs/superpowers/specs/2026-09-20-semgrep-asvs-design.md`

## Global Constraints

- Semgrep pinned exactly once: `dependencies = ["semgrep==1.177.0"]` in `pyproject.toml`. No other file states a Semgrep version.
- Vendor rules come from `opengrep/opengrep-rules` commit `f1d2b562b414783763fd02a6ed2736eaed622efa`, copied verbatim, never edited.
- Runtime code imports only the Python standard library (plus `importlib.metadata`). No PyYAML.
- Rule syntax must stay Opengrep-compatible: no `mode: join`, no `interfile`, no Pro-only features in custom rules.
- Report wording: "related rules" and "findings". Never "verified", "compliant", "covered".
- Exit codes: 0 normally; 1 only with `--strict` and at least one ERROR-severity finding; 2 on tool errors.
- Never pass `--no-rewrite-rule-ids` to Semgrep (it silently drops findings when rule ids collide across languages, and 37 ids collide in the vendor set).
- Our code is EUPL-1.2; `semgrep_asvs/rules/vendor/` keeps upstream's LICENSE.
- Commit after every task. Commit messages end with the attribution lines from the session system reminder.
- Commands below assume a venv at `.venv` in the repo root with `pip install -e .` done (Task 1). `semgrep` on PATH means `.venv/bin/semgrep`. Never rely on a globally installed Semgrep.

## File map

| Path | Responsibility |
|---|---|
| `pyproject.toml` | Package metadata, the single Semgrep pin, console script, wheel contents |
| `semgrep_asvs/__init__.py` | Whole tool: loaders, mapping, Semgrep runner, renderers, CLI |
| `semgrep_asvs/__main__.py` | `python -m semgrep_asvs` |
| `semgrep_asvs/asvs/asvs-4.0.3.flat.json` | OWASP source data, unmodified |
| `semgrep_asvs/asvs/overrides.yaml` | Vendor rule id → ASVS ids the CWE join misses |
| `semgrep_asvs/rules/vendor/**` | opengrep-rules snapshot (+ LICENSE, VENDOR-COMMIT) |
| `semgrep_asvs/rules/custom/<lang>/*.yaml` + test file | Our six rules |
| `fixtures/<lang>/*` | Deliberately vulnerable inputs for the self-test |
| `test_semgrep_asvs.py` | All tests (stdlib unittest) |
| `known-failures.txt` | Vendor rule ids whose upstream tests fail on the pinned Semgrep |
| `scripts/sync-rules.sh` | Re-vendor from the pinned commit |
| `.pre-commit-hooks.yaml`, `action.yml`, `Makefile` | Consumer surfaces |
| `.github/workflows/ci.yml`, `.github/workflows/sync-rules.yml`, `renovate.json` | Automation |
| `README.md`, `LICENSE`, `.gitignore` | Docs and licence |

---

### Task 1: Package skeleton

**Files:**
- Create: `pyproject.toml`, `semgrep_asvs/__init__.py`, `semgrep_asvs/__main__.py`, `LICENSE`, `.gitignore`, `README.md`

**Interfaces:**
- Produces: console script `semgrep-asvs` → `semgrep_asvs:main(argv=None) -> int`; `semgrep_asvs.version() -> str`.

- [ ] **Step 1: Create the venv with Semgrep 1.177.0 and confirm the version**

```bash
python3 -m venv .venv
.venv/bin/pip install -q "semgrep==1.177.0"
.venv/bin/semgrep --version
```
Expected: `1.177.0`. (If a globally installed Semgrep is on PATH, always call `.venv/bin/semgrep` explicitly.)

- [ ] **Step 2: Write `pyproject.toml`**

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "semgrep-asvs"
version = "0.1.0"
description = "Semgrep with vendored rules, reported against OWASP ASVS 4.0.3 requirements and levels"
readme = "README.md"
license = "EUPL-1.2"
requires-python = ">=3.10"
dependencies = ["semgrep==1.177.0"]

[project.scripts]
semgrep-asvs = "semgrep_asvs:main"

[tool.hatch.build.targets.wheel]
include = [
  "semgrep_asvs/*.py",
  "semgrep_asvs/asvs/*",
  "semgrep_asvs/rules/**/*.yaml",
  "semgrep_asvs/rules/**/*.yml",
  "semgrep_asvs/rules/vendor/LICENSE",
  "semgrep_asvs/rules/vendor/VENDOR-COMMIT",
]

[tool.hatch.build.targets.sdist]
include = ["semgrep_asvs", "README.md", "LICENSE", "pyproject.toml"]
```

- [ ] **Step 3: Write the minimal module and entry point**

`semgrep_asvs/__init__.py`:
```python
"""semgrep-asvs: run Semgrep with a curated rule set and report against OWASP ASVS 4.0.3."""
from __future__ import annotations

import argparse
import sys
from importlib import metadata as importlib_metadata


def version() -> str:
    try:
        return importlib_metadata.version("semgrep-asvs")
    except importlib_metadata.PackageNotFoundError:
        return "0.0.0+uninstalled"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="semgrep-asvs", description=__doc__)
    parser.add_argument("--version", action="version", version=f"semgrep-asvs {version()}")
    parser.parse_args(argv)
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

`semgrep_asvs/__main__.py`:
```python
import sys

from semgrep_asvs import main

sys.exit(main())
```

- [ ] **Step 4: Fetch the EUPL-1.2 text, write `.gitignore` and a README stub**

```bash
curl -sSfL https://raw.githubusercontent.com/spdx/license-list-data/main/text/EUPL-1.2.txt -o LICENSE
head -3 LICENSE
printf '.venv/\n__pycache__/\n*.egg-info/\ndist/\nsemgrep-asvs-out/\n' > .gitignore
printf '# semgrep-asvs\n\nSemgrep with vendored rules, reported against OWASP ASVS 4.0.3. Full README lands in Task 8.\n' > README.md
```
Expected: `head` shows "European Union Public Licence" wording.

- [ ] **Step 5: Install editable and verify the console script**

```bash
.venv/bin/pip install -q -e .
.venv/bin/semgrep-asvs --version
.venv/bin/python -m semgrep_asvs --version
```
Expected: both print `semgrep-asvs 0.1.0`.

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml semgrep_asvs LICENSE .gitignore README.md
git commit -m "feat: package skeleton with pinned semgrep 1.177.0"
```

---

### Task 2: Vendor opengrep-rules and prove they pass on the pinned Semgrep

**Files:**
- Create: `scripts/sync-rules.sh`, `known-failures.txt`, `semgrep_asvs/rules/vendor/**` (generated), `semgrep_asvs/rules/custom/.gitkeep`, `test_semgrep_asvs.py`, `Makefile`

**Interfaces:**
- Produces: `semgrep_asvs/rules/vendor/{python,php,javascript,typescript,go}/`, `semgrep_asvs/rules/vendor/LICENSE`, `semgrep_asvs/rules/vendor/VENDOR-COMMIT`; test helpers `REPO`, `VENV_BIN`, `SEMGREP`, `RULES_DIR`, `run(cmd) -> CompletedProcess` in `test_semgrep_asvs.py`.

- [ ] **Step 1: Write the failing test file**

`test_semgrep_asvs.py`:
```python
"""Self-tests for semgrep-asvs. Run: .venv/bin/python -m unittest -v test_semgrep_asvs"""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent
VENV_BIN = Path(sys.executable).parent
SEMGREP = VENV_BIN / "semgrep"
RULES_DIR = REPO / "semgrep_asvs" / "rules"
KNOWN_FAILURES = REPO / "known-failures.txt"


def run(cmd: list, **kw) -> subprocess.CompletedProcess:
    return subprocess.run([str(c) for c in cmd], text=True, capture_output=True, cwd=REPO, **kw)


class VendorRulesTest(unittest.TestCase):
    def test_vendor_tree_present(self):
        for lang in ("python", "php", "javascript", "typescript", "go"):
            self.assertTrue((RULES_DIR / "vendor" / lang).is_dir(), lang)
        self.assertTrue((RULES_DIR / "vendor" / "LICENSE").is_file())
        self.assertRegex((RULES_DIR / "vendor" / "VENDOR-COMMIT").read_text().strip(), r"^[0-9a-f]{40}$")

    def test_rules_validate(self):
        p = run([SEMGREP, "--validate", "--metrics=off", "--config", RULES_DIR])
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_rule_unit_tests_only_known_failures(self):
        p = run([SEMGREP, "--test", "--json", "--metrics=off", "--config", RULES_DIR, RULES_DIR])
        data = json.loads(p.stdout)
        self.assertEqual(data["config_with_errors"], [], data["config_with_errors"])
        failing = {rule for res in data["results"].values() for rule, chk in res["checks"].items() if not chk["passed"]}
        known = set(KNOWN_FAILURES.read_text().split())
        self.assertEqual(failing - known, set(), f"new failing rule tests: {sorted(failing - known)}")
        self.assertEqual(known - failing, set(), f"remove from known-failures.txt, now passing: {sorted(known - failing)}")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run it to verify it fails**

```bash
.venv/bin/python -m unittest -v test_semgrep_asvs.VendorRulesTest.test_vendor_tree_present
```
Expected: FAIL (assertion, vendor dir missing).

- [ ] **Step 3: Write the sync script**

`scripts/sync-rules.sh`:
```bash
#!/usr/bin/env bash
# Re-vendor opengrep-rules (LGPL 2.1 + Commons Clause) at the pinned commit. Never edits files.
set -euo pipefail
OPENGREP_RULES_COMMIT=f1d2b562b414783763fd02a6ed2736eaed622efa
LANGS="python php javascript typescript go"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/semgrep_asvs/rules/vendor"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

git clone -q --filter=blob:none --no-checkout https://github.com/opengrep/opengrep-rules.git "$TMP/src"
git -C "$TMP/src" -c advice.detachedHead=false checkout -q "$OPENGREP_RULES_COMMIT" -- $LANGS LICENSE

mkdir -p "$DEST"
for l in $LANGS; do
  rm -rf "$DEST/$l"
  cp -R "$TMP/src/$l" "$DEST/$l"
done
cp "$TMP/src/LICENSE" "$DEST/LICENSE"
echo "$OPENGREP_RULES_COMMIT" > "$DEST/VENDOR-COMMIT"
echo "vendored opengrep-rules@$OPENGREP_RULES_COMMIT into $DEST"
```

```bash
chmod +x scripts/sync-rules.sh
scripts/sync-rules.sh
mkdir -p semgrep_asvs/rules/custom && touch semgrep_asvs/rules/custom/.gitkeep
find semgrep_asvs/rules/vendor -name '*.yaml' | wc -l
```
Expected: last line `669`.

- [ ] **Step 4: Write `known-failures.txt`**

```
avoid-query-set-extra
unsafe-argon2-config
```
(Both are upstream misses on Semgrep 1.177.0, observed on 2026-09-20: `python/django/security/audit/query-set-extra.py` line 34 and `javascript/argon2/security/unsafe-argon2-config.js` lines 32, 47.)

- [ ] **Step 5: Write the Makefile**

```makefile
PY ?= .venv/bin/python
SEMGREP ?= .venv/bin/semgrep
PATHS ?= .

.PHONY: install scan coverage validate test sync

install:
	python3 -m venv .venv && $(PY) -m pip install -q -e .

scan:
	.venv/bin/semgrep-asvs scan $(PATHS)

coverage:
	.venv/bin/semgrep-asvs coverage

validate:
	$(SEMGREP) --validate --metrics=off --config semgrep_asvs/rules

test: validate
	$(PY) -m unittest -v test_semgrep_asvs

sync:
	scripts/sync-rules.sh
```

- [ ] **Step 6: Run the vendor tests**

```bash
.venv/bin/python -m unittest -v test_semgrep_asvs.VendorRulesTest
```
Expected: 3 tests OK (the `--test` run takes a few minutes). If `test_rule_unit_tests_only_known_failures` reports different failing ids than the two listed, put the actual ids into `known-failures.txt` and record why in the commit message.

- [ ] **Step 7: Commit**

```bash
git add scripts/sync-rules.sh known-failures.txt Makefile test_semgrep_asvs.py semgrep_asvs/rules
git commit -m "feat: vendor opengrep-rules at f1d2b56 with rule test gate"
```

---

### Task 3: ASVS data, overrides file and the mapping core

**Files:**
- Create: `semgrep_asvs/asvs/asvs-4.0.3.flat.json`, `semgrep_asvs/asvs/overrides.yaml`
- Modify: `semgrep_asvs/__init__.py` (replace whole file), `test_semgrep_asvs.py` (append)

**Interfaces:**
- Produces (all in `semgrep_asvs`):
  - `ToolError(Exception)`
  - `PKG, RULES_DIR, ASVS_JSON, OVERRIDES_FILE: Path`; `LEVELS = ("L1","L2","L3")`
  - `load_asvs(path=ASVS_JSON) -> list[dict]` each `{"id","chapter","chapter_name","description","levels": set[str],"cwes": set[str]}`
  - `load_overrides(path=OVERRIDES_FILE) -> dict[str, list[str]]`
  - `custom_asvs_by_rule(rules_dir=RULES_DIR) -> dict[str, set[str]]` keyed by short id `custom.<lang>.<rule-id>`
  - `short_id(check_id: str) -> str`
  - `asvs_key(req_id: str) -> tuple[int, ...]`
  - `related_requirements(cwes: set[str], asvs_ids: set[str], by_cwe: dict, by_id: dict) -> set[str]`

- [ ] **Step 1: Download the ASVS JSON**

```bash
mkdir -p semgrep_asvs/asvs
curl -sSfL "https://raw.githubusercontent.com/OWASP/ASVS/v4.0.3/4.0/docs_en/OWASP%20Application%20Security%20Verification%20Standard%204.0.3-en.flat.json" -o semgrep_asvs/asvs/asvs-4.0.3.flat.json
.venv/bin/python -c "import json;d=json.load(open('semgrep_asvs/asvs/asvs-4.0.3.flat.json'))['requirements'];print(len(d),sum(1 for r in d if r['cwe']))"
```
Expected: `286 268`.

- [ ] **Step 2: Write `overrides.yaml`**

```yaml
# Vendor rules the CWE join misses: <short rule id>: [ASVS ids]
# Short id = path under semgrep_asvs/rules joined with dots + rule id (no file name).
# Every key must match exactly one loaded rule; test_semgrep_asvs enforces this.
vendor.python.flask.security.audit.debug-enabled: [V14.3.2]
vendor.php.laravel.security.laravel-active-debug-code: [V14.3.2]
vendor.go.lang.security.audit.net.pprof-debug-exposure: [V14.3.2]
vendor.javascript.lang.best-practice.javascript-debugger: [V14.3.2]
vendor.go.lang.security.audit.crypto.math-random-used: [V3.2.2, V3.2.4]
vendor.php.lang.security.file-inclusion: [V5.3.9]
```

- [ ] **Step 3: Append failing tests**

Append to `test_semgrep_asvs.py` (above the `if __name__` block):
```python
import semgrep_asvs as sa  # noqa: E402  (after path constants on purpose)


class MappingTest(unittest.TestCase):
    def test_load_asvs_shape(self):
        reqs = sa.load_asvs()
        self.assertEqual(len(reqs), 286)
        by_id = {r["id"]: r for r in reqs}
        self.assertEqual(by_id["V2.1.1"]["levels"], {"L1", "L2", "L3"})
        self.assertEqual(by_id["V2.1.1"]["cwes"], {"521"})
        self.assertEqual(by_id["V6.2.8"]["levels"], {"L3"})
        self.assertNotIn("([C", by_id["V2.1.1"]["description"])

    def test_load_overrides(self):
        ov = sa.load_overrides()
        self.assertEqual(ov["vendor.python.flask.security.audit.debug-enabled"], ["V14.3.2"])
        self.assertEqual(ov["vendor.go.lang.security.audit.crypto.math-random-used"], ["V3.2.2", "V3.2.4"])

    def test_load_overrides_rejects_garbage(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write("ok.rule: [V1.1.1]\nbroken line\n")
        with self.assertRaises(sa.ToolError):
            sa.load_overrides(Path(f.name))

    def test_short_id(self):
        self.assertEqual(sa.short_id("Users.me.x.semgrep_asvs.rules.vendor.go.lang.foo"), "vendor.go.lang.foo")
        self.assertEqual(sa.short_id("semgrep_asvs.rules.custom.php.bar"), "custom.php.bar")
        self.assertEqual(sa.short_id("unrelated.rule"), "unrelated.rule")

    def test_asvs_key_sorts_numerically(self):
        self.assertEqual(sorted(["V10.1.1", "V2.10.1", "V2.9.3"], key=sa.asvs_key), ["V2.9.3", "V2.10.1", "V10.1.1"])

    def test_related_requirements(self):
        reqs = sa.load_asvs()
        by_id = {r["id"]: r for r in reqs}
        by_cwe = sa.index_by_cwe(reqs)
        rel = sa.related_requirements({"521"}, {"V14.3.2"}, by_cwe, by_id)
        self.assertIn("V2.1.1", rel)
        self.assertIn("V14.3.2", rel)
        self.assertEqual(sa.related_requirements({"999999"}, set(), by_cwe, by_id), set())
```

- [ ] **Step 4: Run to verify they fail**

```bash
.venv/bin/python -m unittest -v test_semgrep_asvs.MappingTest
```
Expected: errors (`AttributeError: module 'semgrep_asvs' has no attribute 'load_asvs'`).

- [ ] **Step 5: Replace `semgrep_asvs/__init__.py` with loaders and mapping**

```python
"""semgrep-asvs: run Semgrep with a curated rule set and report against OWASP ASVS 4.0.3."""
from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from importlib import metadata as importlib_metadata
from pathlib import Path
import json

PKG = Path(__file__).resolve().parent
RULES_DIR = PKG / "rules"
ASVS_JSON = PKG / "asvs" / "asvs-4.0.3.flat.json"
OVERRIDES_FILE = PKG / "asvs" / "overrides.yaml"
LEVELS = ("L1", "L2", "L3")
SEVERITIES = ("ERROR", "WARNING", "INFO")
_RULE_ID_MARKER = re.compile(r"(?:^|\.)semgrep_asvs\.rules\.")
_CWE = re.compile(r"CWE-(\d+)")


class ToolError(Exception):
    """Fatal tool error; message goes to stderr, exit code 2."""


def version() -> str:
    try:
        return importlib_metadata.version("semgrep-asvs")
    except importlib_metadata.PackageNotFoundError:
        return "0.0.0+uninstalled"


# ---------- ASVS data ----------

def load_asvs(path: Path = ASVS_JSON) -> list[dict]:
    raw = json.loads(path.read_text(encoding="utf-8"))["requirements"]
    reqs = []
    for r in raw:
        reqs.append({
            "id": r["req_id"],
            "chapter": r["chapter_id"],
            "chapter_name": r["chapter_name"],
            "description": re.sub(r"\s*\(\[C\d+\]\([^)]*\)\)", "", r["req_description"]).strip(),
            "levels": {lvl for lvl, key in zip(LEVELS, ("level1", "level2", "level3")) if r[key]},
            "cwes": set(re.findall(r"\d+", r["cwe"] or "")),
        })
    return reqs


def index_by_cwe(reqs: list[dict]) -> dict[str, list[dict]]:
    by_cwe: dict[str, list[dict]] = defaultdict(list)
    for r in reqs:
        for c in r["cwes"]:
            by_cwe[c].append(r)
    return by_cwe


def asvs_key(req_id: str) -> tuple[int, ...]:
    return tuple(int(x) for x in req_id[1:].split("."))


# ---------- rule → ASVS mapping inputs ----------

def load_overrides(path: Path = OVERRIDES_FILE) -> dict[str, list[str]]:
    """Flat `rule-id: [V1.2.3, V4.5.6]` lines; `#` comments and blank lines are skipped."""
    out: dict[str, list[str]] = {}
    if not path.exists():
        return out
    for n, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.fullmatch(r"([\w./-]+)\s*:\s*\[([^\]]*)\]", line)
        if not m:
            raise ToolError(f"{path}:{n}: expected `rule-id: [V1.2.3, ...]`, got: {line}")
        out[m.group(1)] = [v.strip() for v in m.group(2).split(",") if v.strip()]
    return out


def custom_asvs_by_rule(rules_dir: Path = RULES_DIR) -> dict[str, set[str]]:
    """Read `- id:` and `asvs: [...]` lines from rules/custom/**/*.yaml. Key = short rule id."""
    out: dict[str, set[str]] = {}
    custom = rules_dir / "custom"
    for f in sorted(custom.rglob("*.y*ml")):
        prefix = ".".join(f.parent.relative_to(rules_dir).parts)
        current = None
        for raw in f.read_text(encoding="utf-8").splitlines():
            m_id = re.match(r"\s*-\s*id:\s*([\w.-]+)\s*$", raw)
            if m_id:
                current = f"{prefix}.{m_id.group(1)}"
                continue
            m_asvs = re.match(r"\s*asvs:\s*\[([^\]]*)\]", raw)
            if m_asvs and current:
                out[current] = {v.strip() for v in m_asvs.group(1).split(",") if v.strip()}
    return out


def short_id(check_id: str) -> str:
    """Semgrep prefixes rule ids with the dotted config path; keep only what follows `semgrep_asvs.rules.`."""
    parts = _RULE_ID_MARKER.split(check_id, maxsplit=1)
    return parts[1] if len(parts) == 2 else check_id


def cwes_from(values) -> set[str]:
    if not values:
        return set()
    if isinstance(values, str):
        values = [values]
    return {m for v in values for m in _CWE.findall(str(v))}


def related_requirements(cwes: set[str], asvs_ids: set[str], by_cwe: dict, by_id: dict) -> set[str]:
    ids = {i for i in asvs_ids if i in by_id}
    for c in cwes:
        ids.update(r["id"] for r in by_cwe.get(c, []))
    return ids


# ---------- CLI ----------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="semgrep-asvs", description=__doc__)
    parser.add_argument("--version", action="version", version=f"semgrep-asvs {version()}")
    parser.parse_args(argv)
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 6: Run the mapping tests**

```bash
.venv/bin/python -m unittest -v test_semgrep_asvs.MappingTest
```
Expected: 6 tests OK.

- [ ] **Step 7: Commit**

```bash
git add semgrep_asvs/asvs semgrep_asvs/__init__.py test_semgrep_asvs.py
git commit -m "feat: ASVS 4.0.3 data, overrides file and CWE-to-ASVS mapping core"
```

---

### Task 4: Six custom rules with Semgrep unit tests

**Files:**
- Create: `semgrep_asvs/rules/custom/python/constant-time-compare.yaml` + `.py`, `semgrep_asvs/rules/custom/python/django-password-min-length.yaml` + `.py`, `semgrep_asvs/rules/custom/php/constant-time-compare.yaml` + `.php`, `semgrep_asvs/rules/custom/php/laravel-password-min-length.yaml` + `.php`, `semgrep_asvs/rules/custom/javascript/constant-time-compare.yaml` + `.js`, `semgrep_asvs/rules/custom/go/constant-time-compare.yaml` + `.go`
- Delete: `semgrep_asvs/rules/custom/.gitkeep`
- Modify: `test_semgrep_asvs.py` (append)

**Interfaces:**
- Produces short ids: `custom.python.constant-time-compare`, `custom.python.django-password-min-length`, `custom.php.constant-time-compare`, `custom.php.laravel-password-min-length`, `custom.javascript.constant-time-compare`, `custom.go.constant-time-compare`.

- [ ] **Step 1: Append the failing metadata test**

```python
class CustomRulesTest(unittest.TestCase):
    def test_every_custom_rule_declares_valid_asvs_ids(self):
        by_rule = sa.custom_asvs_by_rule()
        self.assertEqual(len(by_rule), 6, sorted(by_rule))
        valid = {r["id"] for r in sa.load_asvs()}
        for rule, ids in by_rule.items():
            self.assertTrue(ids, f"{rule} has no asvs ids")
            self.assertTrue(ids <= valid, f"{rule}: unknown ASVS ids {ids - valid}")

    def test_custom_rule_unit_tests_pass(self):
        custom = RULES_DIR / "custom"
        p = run([SEMGREP, "--test", "--json", "--metrics=off", "--config", custom, custom])
        data = json.loads(p.stdout)
        self.assertEqual(data["config_with_errors"], [])
        failing = {rule for res in data["results"].values() for rule, chk in res["checks"].items() if not chk["passed"]}
        self.assertEqual(failing, set())
        self.assertEqual(len(data["results"]), 6, "expected one test file per custom rule")
```

- [ ] **Step 2: Run to verify it fails**

```bash
.venv/bin/python -m unittest -v test_semgrep_asvs.CustomRulesTest
```
Expected: FAIL (0 rules found).

- [ ] **Step 3: Write the Python rules and tests**

`semgrep_asvs/rules/custom/python/constant-time-compare.yaml`:
```yaml
rules:
- id: constant-time-compare
  languages: [python]
  severity: WARNING
  message: >-
    HMAC digest compared with ==/!=, which is not constant-time and leaks timing information.
    Use hmac.compare_digest(expected, received).
  metadata:
    asvs: [V6.2.8]
    cwe: ["CWE-385: Covert Timing Channel"]
    category: security
    technology: [python]
    references:
    - https://docs.python.org/3/library/hmac.html#hmac.compare_digest
  patterns:
  - pattern-either:
    - pattern: $A == $B
    - pattern: $A != $B
  - metavariable-pattern:
      metavariable: $A
      pattern-either:
      - pattern: hmac.new(...).hexdigest()
      - pattern: hmac.new(...).digest()
      - pattern: hmac.HMAC(...).hexdigest()
      - pattern: hmac.HMAC(...).digest()
```

`semgrep_asvs/rules/custom/python/constant-time-compare.py`:
```python
import hmac


def verify(k, m, sig):
    # ruleid: constant-time-compare
    if hmac.new(k, m, "sha256").hexdigest() == sig:
        return True
    # ruleid: constant-time-compare
    if sig != hmac.new(k, m, "sha256").digest():
        return False
    # ok: constant-time-compare
    return hmac.compare_digest(hmac.new(k, m, "sha256").hexdigest(), sig)
```

`semgrep_asvs/rules/custom/python/django-password-min-length.yaml`:
```yaml
rules:
- id: django-password-min-length
  languages: [python]
  severity: WARNING
  message: >-
    Django MinimumLengthValidator allows passwords shorter than 12 characters (default is 8).
    ASVS V2.1.1 requires at least 12. Set OPTIONS {"min_length": 12}.
  metadata:
    asvs: [V2.1.1]
    cwe: ["CWE-521: Weak Password Requirements"]
    category: security
    technology: [django]
    references:
    - https://docs.djangoproject.com/en/stable/topics/auth/passwords/#enabling-password-validation
  pattern-either:
  - patterns:
    - pattern: |
        {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": $N}}
    - metavariable-comparison:
        metavariable: $N
        comparison: $N < 12
  - pattern: |
      {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"}
```

`semgrep_asvs/rules/custom/python/django-password-min-length.py`:
```python
AUTH_PASSWORD_VALIDATORS = [
    # ruleid: django-password-min-length
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 8}},
    # ruleid: django-password-min-length
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    # ok: django-password-min-length
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 12}},
    # ok: django-password-min-length
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
]
```

- [ ] **Step 4: Write the PHP rules and tests**

`semgrep_asvs/rules/custom/php/constant-time-compare.yaml`:
```yaml
rules:
- id: constant-time-compare
  languages: [php]
  severity: WARNING
  message: >-
    HMAC compared with ==/===, which is not constant-time and leaks timing information.
    Use hash_equals($expected, $received).
  metadata:
    asvs: [V6.2.8]
    cwe: ["CWE-385: Covert Timing Channel"]
    category: security
    technology: [php]
    references:
    - https://www.php.net/manual/en/function.hash-equals.php
  patterns:
  - pattern-either:
    - pattern: $A == $B
    - pattern: $A === $B
    - pattern: $A != $B
    - pattern: $A !== $B
  - metavariable-pattern:
      metavariable: $A
      pattern: hash_hmac(...)
```

`semgrep_asvs/rules/custom/php/constant-time-compare.php`:
```php
<?php
// ruleid: constant-time-compare
if (hash_hmac('sha256', $m, $k) === $sig) {}
// ruleid: constant-time-compare
if (hash_hmac('sha256', $m, $k) != $sig) {}
// ok: constant-time-compare
if (hash_equals(hash_hmac('sha256', $m, $k), $sig)) {}
```

`semgrep_asvs/rules/custom/php/laravel-password-min-length.yaml`:
```yaml
rules:
- id: laravel-password-min-length
  languages: [php]
  severity: WARNING
  message: >-
    Laravel Password rule allows passwords shorter than 12 characters. ASVS V2.1.1 requires at least 12.
    Use Password::min(12).
  metadata:
    asvs: [V2.1.1]
    cwe: ["CWE-521: Weak Password Requirements"]
    category: security
    technology: [laravel]
    references:
    - https://laravel.com/docs/validation#validating-passwords
  patterns:
  - pattern: Password::min($N)
  - metavariable-comparison:
      metavariable: $N
      comparison: $N < 12
```

`semgrep_asvs/rules/custom/php/laravel-password-min-length.php`:
```php
<?php
use Illuminate\Validation\Rules\Password;
// ruleid: laravel-password-min-length
$weak = Password::min(8);
// ok: laravel-password-min-length
$strong = Password::min(12)->mixedCase()->numbers();
```

- [ ] **Step 5: Write the JavaScript rule and test**

`semgrep_asvs/rules/custom/javascript/constant-time-compare.yaml`:
```yaml
rules:
- id: constant-time-compare
  languages: [javascript, typescript]
  severity: WARNING
  message: >-
    HMAC digest compared with ==/===, which is not constant-time and leaks timing information.
    Use crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(received)).
  metadata:
    asvs: [V6.2.8]
    cwe: ["CWE-385: Covert Timing Channel"]
    category: security
    technology: [node.js]
    references:
    - https://nodejs.org/api/crypto.html#cryptotimingsafeequala-b
  patterns:
  - pattern-either:
    - pattern: $A == $B
    - pattern: $A === $B
    - pattern: $A != $B
    - pattern: $A !== $B
  - metavariable-pattern:
      metavariable: $A
      pattern-either:
      - pattern: $C.createHmac(...). ... .digest(...)
      - pattern: crypto.createHmac(...). ... .digest(...)
```

`semgrep_asvs/rules/custom/javascript/constant-time-compare.js`:
```javascript
const crypto = require('crypto');
function verify(k, m, sig) {
  // ruleid: constant-time-compare
  if (crypto.createHmac('sha256', k).update(m).digest('hex') === sig) return true;
  // ruleid: constant-time-compare
  if (crypto.createHmac('sha256', k).update(m).digest('hex') != sig) return false;
  // ok: constant-time-compare
  const expected = Buffer.from(crypto.createHmac('sha256', k).update(m).digest('hex'));
  return crypto.timingSafeEqual(expected, Buffer.from(sig));
}
```

- [ ] **Step 6: Write the Go rule and test**

`semgrep_asvs/rules/custom/go/constant-time-compare.yaml`:
```yaml
rules:
- id: constant-time-compare
  languages: [go]
  severity: WARNING
  message: >-
    HMAC compared with bytes.Equal or ==, which is not constant-time and leaks timing information.
    Use hmac.Equal(expected, received).
  metadata:
    asvs: [V6.2.8]
    cwe: ["CWE-385: Covert Timing Channel"]
    category: security
    technology: [go]
    references:
    - https://pkg.go.dev/crypto/hmac#Equal
  patterns:
  - pattern-either:
    - pattern: bytes.Equal($M.Sum(...), $B)
    - pattern: bytes.Equal($B, $M.Sum(...))
    - pattern: hex.EncodeToString($M.Sum(...)) == $B
    - pattern: $B == hex.EncodeToString($M.Sum(...))
    - pattern: string($M.Sum(...)) == $B
    - pattern: $B == string($M.Sum(...))
  - pattern-inside: |
      $M := hmac.New(...)
      ...
```

`semgrep_asvs/rules/custom/go/constant-time-compare.go`:
```go
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

func verify(k, m, sig []byte, hexsig string) bool {
	mac := hmac.New(sha256.New, k)
	mac.Write(m)
	// ruleid: constant-time-compare
	if bytes.Equal(mac.Sum(nil), sig) {
		return true
	}
	// ruleid: constant-time-compare
	if hex.EncodeToString(mac.Sum(nil)) == hexsig {
		return true
	}
	// ok: constant-time-compare
	return hmac.Equal(mac.Sum(nil), sig)
}
```

- [ ] **Step 7: Run the custom rule tests and the full vendor validation**

```bash
rm -f semgrep_asvs/rules/custom/.gitkeep
.venv/bin/python -m unittest -v test_semgrep_asvs.CustomRulesTest
.venv/bin/semgrep --validate --metrics=off --config semgrep_asvs/rules
```
Expected: 2 tests OK; validate reports `0 configuration error(s)` and `736 rule(s)`.

- [ ] **Step 8: Commit**

```bash
git add semgrep_asvs/rules/custom test_semgrep_asvs.py
git commit -m "feat: six custom ASVS rules (constant-time compare x4, password min length x2)"
```

---

### Task 5: `scan` command with text output, fixtures and exit codes

**Files:**
- Create: `fixtures/python/settings.py`, `fixtures/python/verify.py`, `fixtures/php/app.php`, `fixtures/javascript/app.js`, `fixtures/go/main.go`
- Modify: `semgrep_asvs/__init__.py` (add runner, report builder, text renderer, CLI), `test_semgrep_asvs.py` (append)

**Interfaces:**
- Produces (in `semgrep_asvs`):
  - `run_semgrep(targets: list[str], out_dir: Path) -> tuple[dict, dict]` returns (semgrep JSON, SARIF) and writes `semgrep.json`, `semgrep.sarif` into `out_dir`
  - `build_inventory(sarif: dict, overrides: dict, custom_asvs: dict) -> dict[str, dict]` short id → `{"cwes": set, "asvs": set}`
  - `build_report(sem_json: dict, sarif: dict, targets: list[str]) -> dict` with keys `asvs, by_id, inventory, req_rules, findings, req_findings, targets, semgrep_version, errors, n_vendor, n_custom`
  - `render_text(report: dict) -> str`
  - `shorten_ids(sem_json: dict, sarif: dict) -> None` (in place)
  - `cmd_scan(args) -> int`, `main(argv) -> int`

- [ ] **Step 1: Write the fixtures**

`fixtures/python/settings.py`:
```python
import hashlib

DEBUG = True

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 8}},
]


def legacy_hash(password: bytes) -> str:
    return hashlib.md5(password).hexdigest()
```

`fixtures/python/verify.py`:
```python
import hmac


def verify(key, message, signature):
    return hmac.new(key, message, "sha256").hexdigest() == signature
```

`fixtures/php/app.php`:
```php
<?php
use Illuminate\Validation\Rules\Password;

putenv("APP_DEBUG=true");

function verify($k, $m, $sig) {
    return hash_hmac('sha256', $m, $k) === $sig;
}

$rule = Password::min(8);
```

`fixtures/javascript/app.js`:
```javascript
const crypto = require('crypto');

function handler(req) {
  const result = eval(req.query.expr);
  return result;
}

function verify(k, m, sig) {
  return crypto.createHmac('sha256', k).update(m).digest('hex') === sig;
}
```

`fixtures/go/main.go`:
```go
package main

import (
	"bytes"
	"crypto/des"
	"crypto/hmac"
	"crypto/sha256"
)

func weak(key []byte) {
	_, _ = des.NewCipher(key)
}

func verify(k, m, sig []byte) bool {
	mac := hmac.New(sha256.New, k)
	mac.Write(m)
	return bytes.Equal(mac.Sum(nil), sig)
}
```

- [ ] **Step 2: Append failing scan tests**

```python
import tempfile  # noqa: E402

FIXTURES = REPO / "fixtures"


def scan(*args, out=None):
    """Run the CLI in-process from the repo root so paths print as fixtures/...; returns (exit_code, stdout, out_dir)."""
    import contextlib
    import io
    import os
    os.chdir(REPO)
    out = out or Path(tempfile.mkdtemp())
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = sa.main(["scan", "--out", str(out), *args, "fixtures"])
    return code, buf.getvalue(), out


class ScanTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.code, cls.text, cls.out = scan("--format", "text,json")

    def test_exit_zero_without_strict(self):
        self.assertEqual(self.code, 0)

    def test_text_groups_by_chapter_and_shows_levels(self):
        self.assertIn("== V6 Stored Cryptography", self.text)
        self.assertRegex(self.text, r"V6\.2\.8 \[L3\] WARNING\s+custom\.go\.constant-time-compare\s+fixtures/go/main\.go:\d+")
        self.assertRegex(self.text, r"V6\.2\.8 \[L3\] WARNING\s+custom\.python\.constant-time-compare")
        self.assertRegex(self.text, r"V6\.2\.8 \[L3\] WARNING\s+custom\.php\.constant-time-compare")
        self.assertRegex(self.text, r"V6\.2\.8 \[L3\] WARNING\s+custom\.javascript\.constant-time-compare")
        self.assertRegex(self.text, r"V2\.1\.1 \[L1 L2 L3\] WARNING\s+custom\.python\.django-password-min-length")
        self.assertRegex(self.text, r"V2\.1\.1 \[L1 L2 L3\] WARNING\s+custom\.php\.laravel-password-min-length")

    def test_cwe_join_and_override_mapping(self):
        self.assertRegex(self.text, r"V6\.2\.2 \[L2 L3\] \w+\s+vendor\.python\.lang\.security\.insecure-hash-algorithm-md5")
        self.assertRegex(self.text, r"V5\.2\.4 \[L1 L2 L3\] \w+\s+vendor\.javascript\.browser\.security\.eval-detected")
        self.assertRegex(self.text, r"V14\.3\.2 \[L1 L2 L3\] \w+\s+vendor\.php\.laravel\.security\.laravel-active-debug-code")
        self.assertRegex(self.text, r"V6\.2\.2 \[L2 L3\] \w+\s+vendor\.go\.lang\.security\.audit\.crypto\.use-of-DES")

    def test_summary_lines(self):
        self.assertRegex(self.text, r"-- \d+ findings: ERROR \d+, WARNING \d+, INFO \d+")
        self.assertRegex(self.text, r"-- requirements with findings: L1 \d+, L2 \d+, L3 \d+")

    def test_json_written_with_short_ids(self):
        data = json.loads((self.out / "semgrep.json").read_text())
        ids = {r["check_id"] for r in data["results"]}
        self.assertIn("custom.go.constant-time-compare", ids)
        self.assertFalse(any("semgrep_asvs.rules" in i for i in ids), ids)
        self.assertFalse((self.out / "semgrep.sarif").exists(), "sarif not requested")
        self.assertFalse((self.out / "coverage.md").exists(), "md not requested")

    def test_strict_exits_one_on_error_severity(self):
        code, text, _ = scan("--format", "text", "--strict")
        self.assertEqual(code, 1)

    def test_text_only_creates_no_out_dir(self):
        out = Path(tempfile.mkdtemp()) / "never"
        code, _, _ = scan("--format", "text", out=out)
        self.assertEqual(code, 0)
        self.assertFalse(out.exists())

    def test_overrides_match_exactly_one_loaded_rule(self):
        _, sarif = sa.run_semgrep([str(FIXTURES / "go")], Path(tempfile.mkdtemp()))
        loaded = {sa.short_id(r["id"]) for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
        for key in sa.load_overrides():
            self.assertIn(key, loaded, f"override key matches no loaded rule: {key}")

    def test_tool_error_when_semgrep_missing(self):
        import os
        env = {**os.environ, "PATH": "/nonexistent"}
        p = subprocess.run([sys.executable, "-m", "semgrep_asvs", "scan", "--format", "text", str(FIXTURES)],
                           text=True, capture_output=True, cwd=REPO, env=env)
        self.assertEqual(p.returncode, 2)
        self.assertIn("semgrep not found", p.stderr)
```

- [ ] **Step 3: Run to verify they fail**

```bash
.venv/bin/python -m unittest -v test_semgrep_asvs.ScanTest
```
Expected: errors (`main` rejects `scan`, or attribute errors).

- [ ] **Step 4: Add runner, report and text renderer to `semgrep_asvs/__init__.py`**

Add these imports at the top (keep existing ones):
```python
import shutil
import subprocess
import tempfile
from collections import Counter
from datetime import datetime, timezone
```

Add after `related_requirements` and before the CLI section:
```python
# ---------- semgrep ----------

DEFAULT_OUT = "semgrep-asvs-out"
FORMATS = ("text", "md", "sarif", "json")


def semgrep_command(targets: list[str], json_out: Path, sarif_out: Path) -> list[str]:
    exe = shutil.which("semgrep")
    if not exe:
        req = next((r for r in importlib_metadata.requires("semgrep-asvs") or [] if r.startswith("semgrep")), "semgrep")
        raise ToolError(f"semgrep not found on PATH; install it with: pip install '{req}'")
    return [
        exe, "scan", "--metrics=off", "--disable-version-check", "--quiet",
        "--config", str(RULES_DIR / "vendor"), "--config", str(RULES_DIR / "custom"),
        f"--json-output={json_out}", f"--sarif-output={sarif_out}", *targets,
    ]


def run_semgrep(targets: list[str], out_dir: Path) -> tuple[dict, dict]:
    """Run Semgrep once; returns (json, sarif). Files land in out_dir as semgrep.json / semgrep.sarif."""
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path, sarif_path = out_dir / "semgrep.json", out_dir / "semgrep.sarif"
    proc = subprocess.run(semgrep_command(targets, json_path, sarif_path), text=True, capture_output=True)
    if proc.returncode not in (0, 1):
        raise ToolError(f"semgrep exited {proc.returncode}\n{proc.stderr.strip()}")
    try:
        return (json.loads(json_path.read_text(encoding="utf-8")),
                json.loads(sarif_path.read_text(encoding="utf-8")))
    except (OSError, ValueError) as e:
        raise ToolError(f"could not read semgrep output: {e}") from e


def shorten_ids(sem_json: dict, sarif: dict) -> None:
    for r in sem_json.get("results", []):
        r["check_id"] = short_id(r["check_id"])
    run = sarif["runs"][0]
    for rule in run["tool"]["driver"]["rules"]:
        rule["id"] = short_id(rule["id"])
        if "name" in rule:
            rule["name"] = short_id(rule["name"])
    for res in run.get("results", []):
        res["ruleId"] = short_id(res["ruleId"])


# ---------- report model ----------

def build_inventory(sarif: dict, overrides: dict, custom_asvs: dict) -> dict[str, dict]:
    """Every loaded rule (SARIF lists all rules, not only those with findings)."""
    inv: dict[str, dict] = {}
    for rule in sarif["runs"][0]["tool"]["driver"]["rules"]:
        sid = short_id(rule["id"])
        tags = rule.get("properties", {}).get("tags", [])
        inv[sid] = {"cwes": cwes_from(tags), "asvs": set(overrides.get(sid, [])) | custom_asvs.get(sid, set())}
    return inv


def build_report(sem_json: dict, sarif: dict, targets: list[str]) -> dict:
    asvs = load_asvs()
    by_id = {r["id"]: r for r in asvs}
    by_cwe = index_by_cwe(asvs)
    inventory = build_inventory(sarif, load_overrides(), custom_asvs_by_rule())

    req_rules: dict[str, set[str]] = defaultdict(set)
    for sid, entry in inventory.items():
        for rid in related_requirements(entry["cwes"], entry["asvs"], by_cwe, by_id):
            req_rules[rid].add(sid)

    findings = []
    for r in sem_json.get("results", []):
        sid = short_id(r["check_id"])
        entry = inventory.get(sid) or {"cwes": cwes_from(r["extra"].get("metadata", {}).get("cwe")), "asvs": set()}
        findings.append({
            "rule": sid,
            "path": r["path"],
            "line": r["start"]["line"],
            "severity": r["extra"]["severity"],
            "message": r["extra"]["message"].strip().splitlines()[0] if r["extra"]["message"].strip() else "",
            "asvs": sorted(related_requirements(entry["cwes"], entry["asvs"], by_cwe, by_id), key=asvs_key),
        })
    findings.sort(key=lambda f: (f["path"], f["line"], f["rule"]))

    req_findings: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        for rid in f["asvs"]:
            req_findings[rid].append(f)

    return {
        "asvs": asvs, "by_id": by_id, "inventory": inventory, "req_rules": req_rules,
        "findings": findings, "req_findings": req_findings, "targets": targets,
        "semgrep_version": sem_json.get("version", "?"), "errors": sem_json.get("errors", []),
        "n_vendor": sum(1 for s in inventory if s.startswith("vendor.")),
        "n_custom": sum(1 for s in inventory if s.startswith("custom.")),
    }


def levels_str(report: dict, rid: str) -> str:
    return " ".join(lvl for lvl in LEVELS if lvl in report["by_id"][rid]["levels"])


# ---------- renderers ----------

def render_text(report: dict) -> str:
    lines: list[str] = []
    by_chapter: dict[str, list] = defaultdict(list)
    unmapped = []
    for f in report["findings"]:
        if not f["asvs"]:
            unmapped.append(f)
        for rid in f["asvs"]:
            by_chapter[rid.split(".")[0]].append((rid, f))
    for ch in sorted(by_chapter, key=lambda c: int(c[1:])):
        name = next(r["chapter_name"] for r in report["asvs"] if r["chapter"] == ch)
        lines.append(f"== {ch} {name}")
        for rid, f in sorted(by_chapter[ch], key=lambda x: (asvs_key(x[0]), x[1]["path"], x[1]["line"])):
            lines.append(f"{rid} [{levels_str(report, rid)}] {f['severity']:<7} {f['rule']}  {f['path']}:{f['line']}  {f['message']}")
    if unmapped:
        lines.append("== No ASVS mapping")
        for f in unmapped:
            lines.append(f"-        {f['severity']:<7} {f['rule']}  {f['path']}:{f['line']}  {f['message']}")
    sev = Counter(f["severity"] for f in report["findings"])
    lines.append(f"-- {len(report['findings'])} findings: " + ", ".join(f"{s} {sev.get(s, 0)}" for s in SEVERITIES))
    touched = {rid for f in report["findings"] for rid in f["asvs"]}
    lines.append("-- requirements with findings: " + ", ".join(
        f"{lvl} {sum(1 for rid in touched if lvl in report['by_id'][rid]['levels'])}" for lvl in LEVELS))
    if report["errors"]:
        lines.append(f"-- semgrep reported {len(report['errors'])} error(s); see semgrep.json")
    return "\n".join(lines) + "\n"
```

Replace the CLI section with:
```python
# ---------- CLI ----------

def cmd_scan(args) -> int:
    formats = [f.strip() for f in args.format.split(",") if f.strip()]
    bad = [f for f in formats if f not in FORMATS]
    if bad:
        raise ToolError(f"unknown --format {bad}; choose from {', '.join(FORMATS)}")
    targets = args.paths or ["."]
    with tempfile.TemporaryDirectory(prefix="semgrep-asvs-") as tmp:
        sem_json, sarif = run_semgrep(targets, Path(tmp))
    shorten_ids(sem_json, sarif)
    report = build_report(sem_json, sarif, targets)

    out = Path(args.out)
    if any(f in formats for f in ("json", "sarif", "md")):
        out.mkdir(parents=True, exist_ok=True)
    if "json" in formats:
        (out / "semgrep.json").write_text(json.dumps(sem_json, indent=1), encoding="utf-8")
    if "sarif" in formats:
        (out / "semgrep.sarif").write_text(json.dumps(tag_sarif(sarif, report), indent=1), encoding="utf-8")
    if "md" in formats:
        (out / "coverage.md").write_text(render_markdown(report), encoding="utf-8")
    if "text" in formats:
        sys.stdout.write(render_text(report))
    if args.strict and any(f["severity"] == "ERROR" for f in report["findings"]):
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="semgrep-asvs", description=__doc__)
    parser.add_argument("--version", action="version", version=f"semgrep-asvs {version()}")
    sub = parser.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan paths and report findings against ASVS 4.0.3")
    s.add_argument("paths", nargs="*", help="files or directories (default: .)")
    s.add_argument("--out", default=DEFAULT_OUT, help=f"output directory for json/sarif/md (default: {DEFAULT_OUT})")
    s.add_argument("--format", default="text,md,sarif,json", help="comma list of text,md,sarif,json")
    s.add_argument("--strict", action="store_true", help="exit 1 if any ERROR-severity finding")
    args = parser.parse_args(argv)
    try:
        return cmd_scan(args)
    except ToolError as e:
        print(f"semgrep-asvs: {e}", file=sys.stderr)
        return 2
```

Add temporary stubs so the module imports (replaced in Task 6):
```python
def tag_sarif(sarif: dict, report: dict) -> dict:
    return sarif


def render_markdown(report: dict) -> str:
    return "# ASVS 4.0.3 coverage report\n"
```

- [ ] **Step 5: Run the scan tests**

```bash
.venv/bin/python -m unittest -v test_semgrep_asvs.ScanTest
```
Expected: 9 tests OK. If `test_cwe_join_and_override_mapping` fails on the Go DES line, run `.venv/bin/semgrep-asvs scan --format text fixtures/go` and use whichever vendor CWE-327 rule fired (e.g. `use-of-rc4` after switching the fixture to `rc4.NewCipher(key)`); the assertion must name a real firing rule.

- [ ] **Step 6: Commit**

```bash
git add fixtures semgrep_asvs/__init__.py test_semgrep_asvs.py
git commit -m "feat: scan command with ASVS-grouped text output, fixtures and exit codes"
```

---

### Task 6: Markdown coverage report and ASVS-tagged SARIF

**Files:**
- Modify: `semgrep_asvs/__init__.py` (replace the two stubs), `test_semgrep_asvs.py` (append)

**Interfaces:**
- Produces: `render_markdown(report) -> str`, `tag_sarif(sarif, report) -> dict`, `render_requirement_map(report) -> str`, `render_gaps(report) -> str`.

- [ ] **Step 1: Append failing tests**

```python
class OutputsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.code, cls.text, cls.out = scan("--format", "md,sarif")
        cls.md = (cls.out / "coverage.md").read_text()
        cls.sarif = json.loads((cls.out / "semgrep.sarif").read_text())

    def test_markdown_sections(self):
        for h in ("# ASVS 4.0.3 coverage report", "## Summary by level", "## Findings by requirement",
                  "## Requirement map", "## Gaps"):
            self.assertIn(h, self.md)
        self.assertNotIn("verified", self.md.lower())
        self.assertNotIn("compliant", self.md.lower())

    def test_markdown_summary_table(self):
        self.assertRegex(self.md, r"\| L1 \| 128 \| \d+ \| \d+ \|")
        self.assertRegex(self.md, r"\| L2 \| 259 \| \d+ \| \d+ \|")
        self.assertRegex(self.md, r"\| L3 \| 278 \| \d+ \| \d+ \|")

    def test_markdown_findings_rows(self):
        self.assertRegex(self.md, r"\| V6\.2\.8 \| L3 \| WARNING \| `custom\.go\.constant-time-compare` \| `fixtures/go/main\.go:\d+` \|")
        self.assertRegex(self.md, r"\| V14\.3\.2 \| L1 L2 L3 \| \w+ \| `vendor\.php\.laravel\.security\.laravel-active-debug-code` \|")

    def test_markdown_requirement_map_and_gaps(self):
        self.assertIn("<details><summary>V10 Malicious Code", self.md)
        self.assertRegex(self.md, r"\| V6\.2\.8 \|  \|  \| x \| 385 \| 4 \| \d+ \|")
        self.assertIn("V10.3.1", self.md.split("## Gaps")[1])
        self.assertRegex(self.md.split("## Gaps")[1], r"without a CWE \(18\)[^\n]*V1\.1\.1")

    def test_sarif_rule_tags(self):
        rules = {r["id"]: r for r in self.sarif["runs"][0]["tool"]["driver"]["rules"]}
        tags = rules["custom.go.constant-time-compare"]["properties"]["tags"]
        self.assertIn("asvs/V6.2.8", tags)
        self.assertIn("asvs-level/L3", tags)
        self.assertIn("cwe/385", tags)
        tags = rules["vendor.php.laravel.security.laravel-active-debug-code"]["properties"]["tags"]
        self.assertIn("asvs/V14.3.2", tags)
        self.assertIn("asvs-level/L1", tags)
        self.assertTrue(all("semgrep_asvs.rules" not in r["ruleId"] for r in self.sarif["runs"][0]["results"]))
```

- [ ] **Step 2: Run to verify they fail**

```bash
.venv/bin/python -m unittest -v test_semgrep_asvs.OutputsTest
```
Expected: FAIL on sections/tags.

- [ ] **Step 3: Replace the stubs**

```python
def tag_sarif(sarif: dict, report: dict) -> dict:
    for rule in sarif["runs"][0]["tool"]["driver"]["rules"]:
        sid = short_id(rule["id"])
        entry = report["inventory"].get(sid)
        if not entry:
            continue
        rids = sorted((rid for rid, rules in report["req_rules"].items() if sid in rules), key=asvs_key)
        tags = rule.setdefault("properties", {}).setdefault("tags", [])
        new = [f"asvs/{rid}" for rid in rids]
        new += [f"asvs-level/{lvl}" for lvl in LEVELS if any(lvl in report["by_id"][rid]["levels"] for rid in rids)]
        new += [f"cwe/{c}" for c in sorted(entry["cwes"], key=int)]
        tags.extend(t for t in new if t not in tags)
    return sarif


def _md_cell(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def render_requirement_map(report: dict) -> str:
    lines = ["## Requirement map", "",
             "All 286 requirements. \"Related rules\" counts rules whose CWE or explicit mapping matches; it is not a verification.", ""]
    chapters: dict[str, list[dict]] = defaultdict(list)
    for r in report["asvs"]:
        chapters[r["chapter"]].append(r)
    for ch in sorted(chapters, key=lambda c: int(c[1:])):
        reqs = chapters[ch]
        with_rules = sum(1 for r in reqs if report["req_rules"].get(r["id"]))
        lines.append(f"<details><summary>{ch} {reqs[0]['chapter_name']} — {with_rules}/{len(reqs)} requirements with related rules</summary>")
        lines.append("")
        lines.append("| ASVS | L1 | L2 | L3 | CWE | Related rules | Findings |")
        lines.append("|---|---|---|---|---|---|---|")
        for r in sorted(reqs, key=lambda r: asvs_key(r["id"])):
            lv = [("x" if lvl in r["levels"] else "") for lvl in LEVELS]
            lines.append(f"| {r['id']} | {lv[0]} | {lv[1]} | {lv[2]} | {', '.join(sorted(r['cwes'], key=int))} "
                         f"| {len(report['req_rules'].get(r['id'], ()))} | {len(report['req_findings'].get(r['id'], ()))} |")
        lines.append("")
        lines.append("</details>")
        lines.append("")
    return "\n".join(lines)


def render_gaps(report: dict) -> str:
    no_rule = [r["id"] for r in report["asvs"] if r["cwes"] and not report["req_rules"].get(r["id"])]
    no_cwe = [r["id"] for r in report["asvs"] if not r["cwes"]]
    unmapped = sum(1 for f in report["findings"] if not f["asvs"])
    return "\n".join([
        "## Gaps", "",
        f"- Requirements with a CWE but no related rule ({len(no_rule)}): " + ", ".join(no_rule),
        f"- Requirements without a CWE ({len(no_cwe)}), not mappable by this tool: " + ", ".join(no_cwe),
        f"- Findings with no ASVS relation: {unmapped}", "",
    ])


def render_markdown(report: dict) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = ["# ASVS 4.0.3 coverage report", "",
             f"Generated {now}, semgrep {report['semgrep_version']}, rules: {report['n_vendor']} vendor + {report['n_custom']} custom, "
             f"targets: {' '.join(report['targets'])}", "",
             "Findings are related to ASVS requirements through CWE identifiers and explicit mappings. "
             "A requirement with related rules and zero findings has not been verified; it has merely not been contradicted by static analysis.", "",
             "## Summary by level", "", "| Level | Requirements | With related rules | With findings |", "|---|---|---|---|"]
    for lvl in LEVELS:
        reqs = [r for r in report["asvs"] if lvl in r["levels"]]
        lines.append(f"| {lvl} | {len(reqs)} | {sum(1 for r in reqs if report['req_rules'].get(r['id']))} "
                     f"| {sum(1 for r in reqs if report['req_findings'].get(r['id']))} |")
    lines += ["", "## Findings by requirement", ""]
    if report["req_findings"]:
        lines += ["| ASVS | Levels | Severity | Rule | Location | Message |", "|---|---|---|---|---|---|"]
        for rid in sorted(report["req_findings"], key=asvs_key):
            for f in report["req_findings"][rid]:
                lines.append(f"| {rid} | {levels_str(report, rid)} | {f['severity']} | `{f['rule']}` | `{f['path']}:{f['line']}` | {_md_cell(f['message'])} |")
    else:
        lines.append("No findings related to an ASVS requirement.")
    unmapped = [f for f in report["findings"] if not f["asvs"]]
    if unmapped:
        lines += ["", f"{len(unmapped)} finding(s) have no ASVS relation; see semgrep.json."]
    lines += ["", render_requirement_map(report), render_gaps(report)]
    return "\n".join(lines)
```

- [ ] **Step 4: Run the output tests and the whole suite**

```bash
.venv/bin/python -m unittest -v test_semgrep_asvs.OutputsTest
.venv/bin/python -m unittest test_semgrep_asvs 2>&1 | tail -3
```
Expected: 5 OK; whole suite OK.

- [ ] **Step 5: Commit**

```bash
git add semgrep_asvs/__init__.py test_semgrep_asvs.py
git commit -m "feat: markdown coverage report and ASVS-tagged SARIF"
```

---

### Task 7: `coverage` command

**Files:**
- Modify: `semgrep_asvs/__init__.py` (add `cmd_coverage`, wire subparser), `test_semgrep_asvs.py` (append)

**Interfaces:**
- Produces: `cmd_coverage(args) -> int`; CLI `semgrep-asvs coverage [--format text|md]`.

- [ ] **Step 1: Append failing test**

```python
class CoverageTest(unittest.TestCase):
    def test_coverage_md_has_map_and_gaps_without_findings(self):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = sa.main(["coverage", "--format", "md"])
        out = buf.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("## Requirement map", out)
        self.assertIn("## Gaps", out)
        self.assertNotIn("## Findings by requirement", out)
        self.assertRegex(out, r"\| V6\.2\.8 \|  \|  \| x \| 385 \| 4 \| 0 \|")

    def test_coverage_text_lists_gap_ids(self):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = sa.main(["coverage"])
        out = buf.getvalue()
        self.assertEqual(code, 0)
        self.assertRegex(out, r"L1: \d+/128 requirements with related rules")
        self.assertIn("V10.3.1", out)
```

- [ ] **Step 2: Run to verify it fails**

```bash
.venv/bin/python -m unittest -v test_semgrep_asvs.CoverageTest
```
Expected: FAIL (argparse error: invalid choice 'coverage').

- [ ] **Step 3: Implement**

Add before `main`:
```python
def render_coverage_text(report: dict) -> str:
    lines = [f"semgrep {report['semgrep_version']}, rules: {report['n_vendor']} vendor + {report['n_custom']} custom"]
    for lvl in LEVELS:
        reqs = [r for r in report["asvs"] if lvl in r["levels"]]
        lines.append(f"{lvl}: {sum(1 for r in reqs if report['req_rules'].get(r['id']))}/{len(reqs)} requirements with related rules")
    no_rule = [r["id"] for r in report["asvs"] if r["cwes"] and not report["req_rules"].get(r["id"])]
    lines.append(f"no related rule ({len(no_rule)}): " + " ".join(no_rule))
    no_cwe = [r["id"] for r in report["asvs"] if not r["cwes"]]
    lines.append(f"no CWE ({len(no_cwe)}): " + " ".join(no_cwe))
    return "\n".join(lines) + "\n"


def cmd_coverage(args) -> int:
    with tempfile.TemporaryDirectory(prefix="semgrep-asvs-") as tmp:
        empty = Path(tmp) / "empty"
        empty.mkdir()
        sem_json, sarif = run_semgrep([str(empty)], Path(tmp))
    shorten_ids(sem_json, sarif)
    report = build_report(sem_json, sarif, [])
    if args.format == "md":
        sys.stdout.write("\n".join([render_requirement_map(report), render_gaps(report)]))
    else:
        sys.stdout.write(render_coverage_text(report))
    return 0
```

In `main`, after the `scan` subparser:
```python
    c = sub.add_parser("coverage", help="print which ASVS requirements have related rules (no scan of user code)")
    c.add_argument("--format", choices=["text", "md"], default="text")
```
and change the dispatch to:
```python
    try:
        return cmd_scan(args) if args.cmd == "scan" else cmd_coverage(args)
```

- [ ] **Step 4: Run tests**

```bash
.venv/bin/python -m unittest -v test_semgrep_asvs.CoverageTest
```
Expected: 2 OK.

- [ ] **Step 5: Commit**

```bash
git add semgrep_asvs/__init__.py test_semgrep_asvs.py
git commit -m "feat: coverage command (static requirement-to-rule map and gap list)"
```

---

### Task 8: pre-commit hook, README

**Files:**
- Create: `.pre-commit-hooks.yaml`
- Modify: `README.md` (replace), `test_semgrep_asvs.py` (append)

- [ ] **Step 1: Write the hook definition**

`.pre-commit-hooks.yaml`:
```yaml
- id: semgrep-asvs
  name: semgrep-asvs
  description: Semgrep with vendored rules, reported against OWASP ASVS 4.0.3 (report-only unless args include --strict)
  entry: semgrep-asvs scan --format text
  language: python
  types_or: [python, php, javascript, jsx, ts, tsx, go]
  require_serial: true
```

- [ ] **Step 2: Append a try-repo test (skipped when pre-commit is absent)**

```python
class PreCommitTest(unittest.TestCase):
    def test_try_repo_runs_hook(self):
        import shutil
        pc = shutil.which("pre-commit")
        if not pc:
            self.skipTest("pre-commit not installed")
        p = run([pc, "try-repo", ".", "semgrep-asvs", "--verbose", "--files",
                 FIXTURES / "python" / "verify.py", FIXTURES / "go" / "main.go"])
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("V6.2.8", p.stdout)
```
- [ ] **Step 3: Commit the hook file first (try-repo reads the committed tree), then run the test**

```bash
git add .pre-commit-hooks.yaml && git commit -m "feat: pre-commit hook definition"
pre-commit --version || .venv/bin/pip install -q pre-commit
.venv/bin/python -m unittest -v test_semgrep_asvs.PreCommitTest
```
Expected: OK (first run builds the hook env: pip installs this repo with Semgrep, takes a minute).

- [ ] **Step 4: Write the README**

```markdown
# semgrep-asvs

Semgrep CE with vendored [opengrep-rules](https://github.com/opengrep/opengrep-rules) plus a few custom rules,
reported against **OWASP ASVS 4.0.3** requirements and levels (L1/L2/L3). Report-only by default; blocking is opt-in.

Languages: Python, PHP, JavaScript, TypeScript, Go.

## What it does, honestly

Findings are related to ASVS requirements through CWE identifiers (rule metadata → ASVS CWE column), a small
overrides file, and explicit `asvs:` metadata on custom rules. A requirement with related rules and zero findings
is **not verified**; static analysis has merely not contradicted it. Chapters V10 and V11 always show zero rules.
Run `semgrep-asvs coverage` for the gap list.

## Use

### CLI
```bash
pip install git+https://github.com/<org>/semgrep-asvs@v0.1.0
semgrep-asvs scan                          # text to stdout + semgrep-asvs-out/{semgrep.json,semgrep.sarif,coverage.md}
semgrep-asvs scan --format text src/       # print only
semgrep-asvs scan --strict                 # exit 1 on any ERROR-severity finding
semgrep-asvs coverage --format md          # requirement map + gaps, no scan
```

### pre-commit
```yaml
repos:
  - repo: https://github.com/<org>/semgrep-asvs
    rev: v0.1.0
    hooks:
      - id: semgrep-asvs
        # args: [--strict]   # uncomment to block commits on ERROR-severity findings
```

### GitHub Actions
```yaml
permissions:
  contents: read
  security-events: write   # for the SARIF upload
steps:
  - uses: actions/checkout@v5
  - uses: <org>/semgrep-asvs@v0.1.0
    with:
      strict: "false"        # "true" fails the job on ERROR-severity findings
      upload-sarif: "true"   # findings appear in the Security tab, tagged asvs/Vx.y.z
```
The action appends `coverage.md` to the job summary and uploads JSON, SARIF and Markdown as an artifact.

## Suppressing findings
Standard Semgrep mechanisms: `# nosemgrep: <rule-id>` comments and a `.semgrepignore` file in your repo.

## Versions
- Semgrep: pinned once in `pyproject.toml` (Renovate bumps it; CI proves the rules still pass).
- Vendor rules: `semgrep_asvs/rules/vendor/VENDOR-COMMIT`; a weekly workflow re-syncs and opens a PR.
- ASVS: 4.0.3 (`semgrep_asvs/asvs/asvs-4.0.3.flat.json`).

## Develop
```bash
make install && make test      # venv, validate rules, run rule tests + self-tests
make scan PATHS=fixtures       # try it
make sync                      # re-vendor opengrep-rules at the pinned commit
```

## Licences
Our code: EUPL-1.2 (`LICENSE`). `semgrep_asvs/rules/vendor/`: LGPL 2.1 + Commons Clause, unmodified, see its `LICENSE`.
Semgrep's own registry rules are deliberately **not** included: their licence forbids redistribution.
```

- [ ] **Step 5: Commit**

```bash
git add README.md test_semgrep_asvs.py
git commit -m "feat: README and pre-commit try-repo test"
```

---

### Task 9: GitHub Action, CI, weekly rule sync, Renovate

**Files:**
- Create: `action.yml`, `.github/workflows/ci.yml`, `.github/workflows/sync-rules.yml`, `renovate.json`

- [ ] **Step 1: Resolve current action versions**

```bash
for r in actions/checkout actions/setup-python actions/upload-artifact github/codeql-action peter-evans/create-pull-request; do
  printf '%s ' "$r"; curl -s "https://api.github.com/repos/$r/releases/latest" | .venv/bin/python -c "import sys,json;print(json.load(sys.stdin)['tag_name'])"
done
```
Use the major version of each result (e.g. `v5`) in the files below in place of the `vN` shown. Do not guess.

- [ ] **Step 2: Write `action.yml`**

```yaml
name: semgrep-asvs
description: Semgrep with vendored rules, reported against OWASP ASVS 4.0.3 (report-only unless strict)
inputs:
  paths:
    description: Files or directories to scan
    default: "."
  strict:
    description: Fail the job on any ERROR-severity finding
    default: "false"
  upload-sarif:
    description: Upload SARIF to GitHub code scanning (needs security-events write)
    default: "true"
  python-version:
    description: Python version to run the tool with
    default: "3.12"
runs:
  using: composite
  steps:
    - uses: actions/setup-python@vN
      with:
        python-version: ${{ inputs.python-version }}
    - shell: bash
      run: python -m pip install -q "$GITHUB_ACTION_PATH"
    - id: scan
      shell: bash
      continue-on-error: true
      run: |
        strict=""
        if [ "${{ inputs.strict }}" = "true" ]; then strict="--strict"; fi
        semgrep-asvs scan --out semgrep-asvs-out $strict ${{ inputs.paths }}
    - shell: bash
      if: always()
      run: cat semgrep-asvs-out/coverage.md >> "$GITHUB_STEP_SUMMARY"
    - if: always() && inputs.upload-sarif == 'true'
      uses: github/codeql-action/upload-sarif@vN
      with:
        sarif_file: semgrep-asvs-out/semgrep.sarif
        category: semgrep-asvs
    - if: always()
      uses: actions/upload-artifact@vN
      with:
        name: semgrep-asvs
        path: semgrep-asvs-out
    - shell: bash
      if: always() && steps.scan.outcome == 'failure'
      run: |
        echo "semgrep-asvs: strict mode found ERROR-severity findings (or the tool failed); see the job summary" >&2
        exit 1
```

- [ ] **Step 3: Write `.github/workflows/ci.yml`**

```yaml
name: ci
on:
  push:
    branches: [main]
  pull_request:
  workflow_dispatch:
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@vN
      - uses: actions/setup-python@vN
        with:
          python-version: "3.12"
      - run: python -m venv .venv && .venv/bin/pip install -q -e . pre-commit
      - run: make test
      - name: wheel contains rules but not vendor test sources
        run: |
          .venv/bin/pip install -q build && .venv/bin/python -m build -q --wheel
          .venv/bin/python - <<'EOF'
          import glob, zipfile
          names = zipfile.ZipFile(glob.glob("dist/*.whl")[0]).namelist()
          assert any(n.endswith("rules/vendor/php/lang/security/weak-crypto.yaml") for n in names), "vendor yaml missing"
          assert any(n.endswith("rules/custom/go/constant-time-compare.yaml") for n in names), "custom yaml missing"
          assert not any(n.endswith(".go") or n.endswith(".php") for n in names), "test sources leaked into wheel"
          assert any(n.endswith("asvs/asvs-4.0.3.flat.json") for n in names)
          EOF
  dogfood:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@vN
      - uses: ./
        with:
          paths: fixtures
          upload-sarif: "false"
      - run: grep -q "V6.2.8" semgrep-asvs-out/coverage.md
  dogfood-strict-fails:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@vN
      - id: strict
        uses: ./
        continue-on-error: true
        with:
          paths: fixtures
          strict: "true"
          upload-sarif: "false"
      - run: test "${{ steps.strict.outcome }}" = "failure"
```

- [ ] **Step 4: Write `.github/workflows/sync-rules.yml`**

```yaml
name: sync-rules
on:
  schedule:
    - cron: "0 5 * * 1"
  workflow_dispatch:
permissions:
  contents: write
  pull-requests: write
jobs:
  sync:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@vN
      - name: re-vendor opengrep-rules at upstream main
        run: |
          sha=$(git ls-remote https://github.com/opengrep/opengrep-rules.git refs/heads/main | cut -f1)
          sed -i "s/^OPENGREP_RULES_COMMIT=.*/OPENGREP_RULES_COMMIT=$sha/" scripts/sync-rules.sh
          scripts/sync-rules.sh
      - uses: peter-evans/create-pull-request@vN
        with:
          commit-message: "chore: sync opengrep-rules"
          title: "chore: sync opengrep-rules"
          body: "Automated re-vendor from opengrep-rules main. CI runs the rule tests; update known-failures.txt if needed."
          branch: chore/sync-rules
          delete-branch: true
```

- [ ] **Step 5: Write `renovate.json`**

```json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": ["config:recommended", "helpers:pinGitHubActionDigests"],
  "pep621": { "enabled": true },
  "packageRules": [
    { "matchPackageNames": ["semgrep"], "rangeStrategy": "pin", "groupName": "semgrep" }
  ]
}
```

- [ ] **Step 6: Validate the YAML and the composite action shape locally**

```bash
.venv/bin/python - <<'EOF'
from ruamel.yaml import YAML   # ships with semgrep; dev-only use
y = YAML(typ="safe")
for f in ("action.yml", ".github/workflows/ci.yml", ".github/workflows/sync-rules.yml", ".pre-commit-hooks.yaml"):
    d = y.load(open(f))
    print(f, "ok", list(d)[:3] if isinstance(d, dict) else len(d))
a = y.load(open("action.yml"))
assert a["runs"]["using"] == "composite" and all("shell" in s or "uses" in s for s in a["runs"]["steps"])
EOF
grep -n "@vN" action.yml .github/workflows/*.yml && echo "UNRESOLVED VERSIONS" || echo "versions resolved"
```
Expected: four `ok` lines and `versions resolved`.

- [ ] **Step 7: Run the full suite one last time and commit**

```bash
make test 2>&1 | tail -3
git add action.yml .github renovate.json
git commit -m "feat: composite GitHub Action, CI, weekly rule sync, Renovate"
```

---

### Task 10: Release tag and final check

- [ ] **Step 1: Verify the working tree is clean and the wheel builds**

```bash
git status --short
.venv/bin/python -m build -q --wheel && ls dist/
```
Expected: no output from `git status`; `semgrep_asvs-0.1.0-py3-none-any.whl` listed.

- [ ] **Step 2: Smoke-test the wheel in a fresh venv, from another directory**

```bash
python3 -m venv /tmp/sa-smoke && /tmp/sa-smoke/bin/pip install -q dist/semgrep_asvs-0.1.0-py3-none-any.whl
cd fixtures && /tmp/sa-smoke/bin/semgrep-asvs scan --format text . | tail -3; cd ..
```
Expected: the two `--` summary lines with non-zero finding counts.

- [ ] **Step 3: Tag**

```bash
git tag -a v0.1.0 -m "semgrep-asvs 0.1.0"
git tag
```
