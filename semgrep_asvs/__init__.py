"""semgrep-asvs: run Semgrep with a curated rule set and report against OWASP ASVS 4.0.3."""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from importlib import metadata as importlib_metadata
from pathlib import Path

PKG = Path(__file__).resolve().parent
RULES_DIR = PKG / "rules"
ASVS_JSON = PKG / "asvs" / "asvs-4.0.3.flat.json"
OVERRIDES_FILE = PKG / "asvs" / "overrides.yaml"
LEVELS = ("L1", "L2", "L3")
SEVERITIES = ("ERROR", "WARNING", "INFO")
FORMATS = ("text", "md", "sarif", "json")
DEFAULT_OUT = "semgrep-asvs-out"
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


# ---------- semgrep ----------

def find_semgrep(bin_dir: Path | None = None) -> tuple[str, dict]:
    """Prefer the semgrep installed next to this interpreter (our pinned dependency) and put that
    directory first on the child's PATH: the semgrep wrapper execs `pysemgrep`/`semgrep-core` from
    PATH, so a stale global install would otherwise silently take over."""
    bin_dir = bin_dir or Path(sys.executable).parent
    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
    exe = shutil.which("semgrep", path=env["PATH"])
    if not exe:
        req = next((r for r in importlib_metadata.requires("semgrep-asvs") or [] if r.startswith("semgrep")), "semgrep")
        raise ToolError(f"semgrep not found on PATH; install it with: pip install '{req}'")
    return exe, env


def semgrep_command(exe: str, targets: list[str], json_out: Path, sarif_out: Path) -> list[str]:
    return [
        exe, "scan", "--metrics=off", "--disable-version-check", "--quiet",
        "--config", str(RULES_DIR / "vendor"), "--config", str(RULES_DIR / "custom"),
        f"--json-output={json_out}", f"--sarif-output={sarif_out}", *targets,
    ]


def run_semgrep(targets: list[str], out_dir: Path) -> tuple[dict, dict]:
    """Run Semgrep once; returns (json, sarif). Files land in out_dir as semgrep.json / semgrep.sarif."""
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path, sarif_path = out_dir / "semgrep.json", out_dir / "semgrep.sarif"
    exe, env = find_semgrep()
    proc = subprocess.run(semgrep_command(exe, targets, json_path, sarif_path), text=True, capture_output=True, env=env)
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
        message = r["extra"].get("message", "").strip()
        findings.append({
            "rule": sid,
            "path": r["path"],
            "line": r["start"]["line"],
            "severity": r["extra"]["severity"],
            "message": message.splitlines()[0] if message else "",
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


def tag_sarif(sarif: dict, report: dict) -> dict:  # replaced in Task 6
    return sarif


def render_markdown(report: dict) -> str:  # replaced in Task 6
    return "# ASVS 4.0.3 coverage report\n"


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


if __name__ == "__main__":
    sys.exit(main())
