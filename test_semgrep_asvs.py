"""Self-tests for semgrep-asvs. Run: .venv/bin/python -m unittest -v test_semgrep_asvs"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent
VENV_BIN = Path(sys.executable).parent
SEMGREP = VENV_BIN / "semgrep"
RULES_DIR = REPO / "semgrep_asvs" / "rules"
KNOWN_FAILURES = REPO / "known-failures.txt"
# The semgrep wrapper execs `pysemgrep`/`semgrep-core` from PATH; put our env first so a stale global install is never used.
ENV = {**os.environ, "PATH": f"{VENV_BIN}{os.pathsep}{os.environ.get('PATH', '')}"}


def run(cmd: list, **kw) -> subprocess.CompletedProcess:
    return subprocess.run([str(c) for c in cmd], text=True, capture_output=True, cwd=REPO, env=ENV, **kw)


class VendorRulesTest(unittest.TestCase):
    def test_semgrep_version_matches_pin(self):
        pin = re.search(r'"semgrep==([\d.]+)"', (REPO / "pyproject.toml").read_text()).group(1)
        p = run([SEMGREP, "--version"])
        self.assertEqual(p.stdout.strip().splitlines()[-1], pin, p.stdout + p.stderr)

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


import semgrep_asvs as sa  # noqa: E402


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


import tempfile  # noqa: E402

FIXTURES = REPO / "fixtures"


def scan(*args, out=None):
    """Run the CLI in-process from the repo root so paths print as fixtures/...; returns (exit_code, stdout, out_dir)."""
    import contextlib
    import io
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
        self.assertRegex(self.text, r"V6\.2\.2\b[^\[\n]*\[L2 L3\] \w+\s+vendor\.python\.lang\.security\.insecure-hash-algorithm-md5")
        self.assertRegex(self.text, r"V5\.2\.4\b[^\[\n]*\[L1 L2 L3\] \w+\s+vendor\.javascript\.browser\.security\.eval-detected")
        self.assertRegex(self.text, r"V14\.3\.2 \[L1 L2 L3\] \w+\s+vendor\.php\.laravel\.security\.laravel-active-debug-code")
        self.assertRegex(self.text, r"V6\.2\.2\b[^\[\n]*\[L2 L3\] \w+\s+vendor\.go\.lang\.security\.audit\.crypto\.use-of-DES")
        self.assertEqual(self.text.count("custom.python.django-password-min-length"), 1, "explicit asvs mapping must replace the CWE fan-out")

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

    def test_overrides_match_a_loaded_rule(self):
        _, sarif = sa.run_semgrep([str(FIXTURES / "go")], Path(tempfile.mkdtemp()))
        loaded = {sa.short_id(r["id"]) for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
        for key in sa.load_overrides():
            self.assertIn(key, loaded, f"override key matches no loaded rule: {key}")

    def test_tool_error_when_semgrep_missing(self):
        from unittest import mock
        with mock.patch.dict(os.environ, {"PATH": "/nonexistent"}):
            with self.assertRaises(sa.ToolError) as ctx:
                sa.find_semgrep(Path("/nonexistent"))
        self.assertIn("semgrep not found", str(ctx.exception))
        self.assertIn("semgrep==", str(ctx.exception))

    def test_find_semgrep_prefers_sibling_of_interpreter(self):
        exe, env = sa.find_semgrep()
        self.assertEqual(Path(exe).parent, VENV_BIN)
        self.assertTrue(env["PATH"].startswith(str(VENV_BIN)))


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
        self.assertNotIn("verified", self.md.lower().replace("not been verified", ""))
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
        gaps = self.md.split("## Gaps")[1]
        self.assertIn("V10.3.1", gaps)
        self.assertRegex(gaps, r"without a CWE \(18\)[^\n]*V1\.1\.1")

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


class CoverageTest(unittest.TestCase):
    def _run(self, *args):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = sa.main(["coverage", *args])
        return code, buf.getvalue()

    def test_coverage_md_has_map_and_gaps_without_findings(self):
        code, out = self._run("--format", "md")
        self.assertEqual(code, 0)
        self.assertIn("## Requirement map", out)
        self.assertIn("## Gaps", out)
        self.assertNotIn("## Findings by requirement", out)
        self.assertRegex(out, r"\| V6\.2\.8 \|  \|  \| x \| 385 \| 4 \| 0 \|")

    def test_coverage_text_lists_gap_ids(self):
        code, out = self._run()
        self.assertEqual(code, 0)
        self.assertRegex(out, r"L1: \d+/128 requirements with related rules")
        self.assertIn("V10.3.1", out)


if __name__ == "__main__":
    unittest.main()
