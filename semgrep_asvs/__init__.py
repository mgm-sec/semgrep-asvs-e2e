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
GITLEAKS_VERSION = "8.30.1"  # rewritten by scripts/bump-gitleaks.sh (together with install-gitleaks.sh)
GITLEAKS_INSTALLER = PKG / "install-gitleaks.sh"
SECRETS_MODES = ("dir", "git", "none")
SECRETS_RULE = "secrets.gitleaks"
SECRETS_ASVS = ("V2.10.4", "V6.4.1")  # both CWE-798 in ASVS 4.0.3
SECRETS_CWE = "798"
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
    """Explicit ids (custom rule metadata or overrides) win; the CWE join is the fallback, because a
    CWE such as 521 fans out to nine V2.1.x requirements while the rule author meant one."""
    ids = {i for i in asvs_ids if i in by_id}
    if ids:
        return ids
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


# ---------- gitleaks (secrets gate) ----------

def gitleaks_cache_dir() -> Path:
    base = os.environ.get("SEMGREP_ASVS_CACHE") or os.path.join(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache", "semgrep-asvs")
    return Path(base) / f"gitleaks-{GITLEAKS_VERSION}"


def find_gitleaks(path: str | None = None, cache: Path | None = None) -> str:
    """gitleaks from PATH, else from our cache, else auto-install the pinned release there (SHA-256 verified)."""
    exe = shutil.which("gitleaks", path=path)
    if exe:
        return exe
    cache = cache or gitleaks_cache_dir()
    cached = cache / "gitleaks"
    if cached.is_file():
        return str(cached)
    proc = subprocess.run(["bash", str(GITLEAKS_INSTALLER), str(cache)], text=True, capture_output=True)
    if proc.returncode != 0 or not cached.is_file():
        raise ToolError(
            f"gitleaks not found on PATH and auto-install of v{GITLEAKS_VERSION} into {cache} failed "
            f"(pass --secrets none to skip the gate):\n{proc.stderr.strip()}")
    return str(cached)


def _empty_gitleaks_run() -> dict:
    return {"tool": {"driver": {"name": "gitleaks", "rules": []}}, "results": []}


def run_gitleaks(mode: str, targets: list[str], out_dir: Path) -> dict:
    """Run gitleaks (`dir` per target, or `git` on the repo at cwd); returns one merged SARIF run.
    A `.gitleaks.toml` in the working directory is passed explicitly: gitleaks does not auto-load it in dir mode."""
    exe = find_gitleaks()
    base = [exe, mode, "--no-banner", "--redact", "--exit-code", "0", "-f", "sarif"]
    cfg = Path.cwd() / ".gitleaks.toml"
    if cfg.exists():
        base += ["-c", str(cfg)]
    merged = _empty_gitleaks_run()
    for i, target in enumerate(targets if mode == "dir" else ["."]):
        report = out_dir / f"gitleaks-{i}.sarif"
        proc = subprocess.run([*base, "-r", str(report), target], text=True, capture_output=True)
        if proc.returncode != 0:
            raise ToolError(f"gitleaks exited {proc.returncode}\n{proc.stderr.strip()}")
        if not report.exists():
            continue
        run = json.loads(report.read_text(encoding="utf-8"))["runs"][0]
        merged["tool"] = run["tool"]
        merged["results"].extend(run.get("results", []))
    return merged


def secrets_findings(gl_run: dict) -> list[dict]:
    out = []
    for res in gl_run.get("results", []):
        loc = res["locations"][0]["physicalLocation"]
        message = res.get("message", {}).get("text", "").strip()
        out.append({
            "rule": f"secrets.{res['ruleId']}",
            "path": loc["artifactLocation"]["uri"],
            "line": loc.get("region", {}).get("startLine", 0),
            "severity": "ERROR",
            "message": message.splitlines()[0] if message else "secret detected",
            "asvs": list(SECRETS_ASVS),
        })
    return out


# ---------- report model ----------

def build_inventory(sarif: dict, overrides: dict, custom_asvs: dict) -> dict[str, dict]:
    """Every loaded rule (SARIF lists all rules, not only those with findings)."""
    inv: dict[str, dict] = {}
    for rule in sarif["runs"][0]["tool"]["driver"]["rules"]:
        sid = short_id(rule["id"])
        tags = rule.get("properties", {}).get("tags", [])
        inv[sid] = {"cwes": cwes_from(tags), "asvs": set(overrides.get(sid, [])) | custom_asvs.get(sid, set())}
    inv[SECRETS_RULE] = {"cwes": {SECRETS_CWE}, "asvs": set(SECRETS_ASVS)}  # the gitleaks gate is part of the package
    return inv


def build_report(sem_json: dict, sarif: dict, targets: list[str], gl_run: dict | None = None) -> dict:
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
    if gl_run is not None:
        findings.extend(secrets_findings(gl_run))
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
        "secrets": gl_run,
        "n_secrets": sum(1 for f in findings if f["rule"].startswith("secrets.")),
    }


def levels_str(report: dict, rid: str) -> str:
    return " ".join(lvl for lvl in LEVELS if lvl in report["by_id"][rid]["levels"])


# ---------- renderers ----------

def finding_levels(report: dict, f: dict) -> str:
    return " ".join(lvl for lvl in LEVELS if any(lvl in report["by_id"][rid]["levels"] for rid in f["asvs"]))


def render_text(report: dict) -> str:
    """One line per finding, grouped under the chapter of its first (lowest) related requirement."""
    lines: list[str] = []
    by_chapter: dict[str, list] = defaultdict(list)
    unmapped = []
    for f in report["findings"]:
        if f["asvs"]:
            by_chapter[f["asvs"][0].split(".")[0]].append(f)
        else:
            unmapped.append(f)
    for ch in sorted(by_chapter, key=lambda c: int(c[1:])):
        name = next(r["chapter_name"] for r in report["asvs"] if r["chapter"] == ch)
        lines.append(f"== {ch} {name}")
        for f in sorted(by_chapter[ch], key=lambda f: (asvs_key(f["asvs"][0]), f["path"], f["line"])):
            lines.append(f"{','.join(f['asvs'])} [{finding_levels(report, f)}] {f['severity']:<7} {f['rule']}  {f['path']}:{f['line']}  {f['message']}")
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
    if report.get("secrets") is None:
        lines.append("-- secrets gate: skipped")
    else:
        lines.append(f"-- secrets gate: {report['n_secrets']} secret(s) found" + (" (BLOCKING)" if report["n_secrets"] else ""))
    return "\n".join(lines) + "\n"


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
    if report.get("secrets") is not None:
        gl = json.loads(json.dumps(report["secrets"]))  # copy; the gitleaks run becomes runs[1]
        gl_tags = [f"asvs/{rid}" for rid in SECRETS_ASVS]
        gl_tags += [f"asvs-level/{lvl}" for lvl in LEVELS if any(lvl in report["by_id"][rid]["levels"] for rid in SECRETS_ASVS)]
        gl_tags.append(f"cwe/{SECRETS_CWE}")
        for rule in gl["tool"]["driver"].get("rules", []):
            tags = rule.setdefault("properties", {}).setdefault("tags", [])
            tags.extend(t for t in gl_tags if t not in tags)
        sarif["runs"].append(gl)
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
             f"targets: {' '.join(report['targets'])}. Secrets gate (gitleaks): "
             + ("skipped" if report.get("secrets") is None else f"{report['n_secrets']} secret(s) found") + ".", "",
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


# ---------- CLI ----------

def cmd_scan(args) -> int:
    formats = [f.strip() for f in args.format.split(",") if f.strip()]
    bad = [f for f in formats if f not in FORMATS]
    if bad:
        raise ToolError(f"unknown --format {bad}; choose from {', '.join(FORMATS)}")
    targets = args.paths or ["."]
    with tempfile.TemporaryDirectory(prefix="semgrep-asvs-") as tmp:
        sem_json, sarif = run_semgrep(targets, Path(tmp))
        gl_run = run_gitleaks(args.secrets, targets, Path(tmp)) if args.secrets != "none" else None
    shorten_ids(sem_json, sarif)
    report = build_report(sem_json, sarif, targets, gl_run)

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
    if report["n_secrets"]:
        return 1  # secrets always block, independent of --strict
    if args.strict and any(f["severity"] == "ERROR" for f in report["findings"]):
        return 1
    return 0


def cmd_secrets_hook(args) -> int:
    """pre-commit entry: gitleaks over the staged changes; its exit code is the verdict (1 = secrets found)."""
    cmd = [find_gitleaks(), "git", "--pre-commit", "--staged", "--redact", "--verbose", "--no-banner"]
    cfg = Path.cwd() / ".gitleaks.toml"
    if cfg.exists():
        cmd += ["-c", str(cfg)]
    return subprocess.call(cmd)


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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="semgrep-asvs", description=__doc__)
    parser.add_argument("--version", action="version", version=f"semgrep-asvs {version()}")
    sub = parser.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan paths and report findings against ASVS 4.0.3")
    s.add_argument("paths", nargs="*", help="files or directories (default: .)")
    s.add_argument("--out", default=DEFAULT_OUT, help=f"output directory for json/sarif/md (default: {DEFAULT_OUT})")
    s.add_argument("--format", default="text,md,sarif,json", help="comma list of text,md,sarif,json")
    s.add_argument("--strict", action="store_true", help="exit 1 if any ERROR-severity finding")
    s.add_argument("--secrets", choices=SECRETS_MODES, default="dir",
                   help="secrets gate via gitleaks: dir = scan the given paths, git = full history of the repo at cwd, "
                        "none = skip (default: dir). Any secret found exits 1 regardless of --strict")
    c = sub.add_parser("coverage", help="print which ASVS requirements have related rules (no scan of user code)")
    c.add_argument("--format", choices=["text", "md"], default="text")
    sub.add_parser("secrets-hook", help="pre-commit entry: gitleaks on staged changes, exit 1 on any secret")
    args = parser.parse_args(argv)
    try:
        return {"scan": cmd_scan, "coverage": cmd_coverage, "secrets-hook": cmd_secrets_hook}[args.cmd](args)
    except ToolError as e:
        print(f"semgrep-asvs: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
