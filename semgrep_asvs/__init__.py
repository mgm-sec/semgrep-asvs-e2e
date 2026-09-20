"""semgrep-asvs: run Semgrep with a curated rule set and report against OWASP ASVS 4.0.3."""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from importlib import metadata as importlib_metadata
from pathlib import Path

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


# ---------- rule -> ASVS mapping inputs ----------

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
