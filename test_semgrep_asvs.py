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


if __name__ == "__main__":
    unittest.main()
