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
semgrep-asvs scan --format text src/       # print only, writes nothing
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
pre-commit installs this package, and with it the pinned Semgrep, in its own environment.

### GitHub Actions
```yaml
permissions:
  contents: read
  security-events: write   # for the SARIF upload
steps:
  - uses: actions/checkout@v7
  - uses: <org>/semgrep-asvs@v0.1.0
    with:
      strict: "false"        # "true" fails the job on ERROR-severity findings
      upload-sarif: "true"   # findings appear in the Security tab, tagged asvs/Vx.y.z and asvs-level/Ln
```
The action appends `coverage.md` to the job summary and uploads JSON, SARIF and Markdown as an artifact.

## Suppressing findings
Standard Semgrep mechanisms: `# nosemgrep: <rule-id>` comments and a `.semgrepignore` file in your repo.

## Versions
- Semgrep: pinned once in `pyproject.toml` (Renovate bumps it; CI proves the rules still validate and pass their tests).
- Vendor rules: `semgrep_asvs/rules/vendor/VENDOR-COMMIT`; a weekly workflow re-syncs from upstream `main` and opens a PR.
- ASVS: 4.0.3 (`semgrep_asvs/asvs/asvs-4.0.3.flat.json`).

The tool always runs the Semgrep installed next to its own interpreter, so a stale Semgrep elsewhere on PATH is never used.

## Develop
```bash
make install && make test      # venv, validate rules, run rule tests + self-tests (several minutes)
make scan PATHS=fixtures       # try it on the deliberately vulnerable fixtures
make coverage                  # which requirements have related rules, and the gaps
make sync                      # re-vendor opengrep-rules at the commit pinned in scripts/sync-rules.sh
```
Adding a custom rule: put `<rule>.yaml` plus a test file with the same stem under `semgrep_asvs/rules/custom/<lang>/`,
with `metadata.asvs: [Vx.y.z]` and `metadata.cwe`. Explicit `asvs` ids replace the CWE join for that rule.
Mapping a vendor rule the CWE join misses: add a line to `semgrep_asvs/asvs/overrides.yaml`.

## Licences
Our code: EUPL-1.2 (`LICENSE`). `semgrep_asvs/rules/vendor/`: LGPL 2.1 + Commons Clause, unmodified, see its `LICENSE`.
Semgrep's own registry rules are deliberately **not** included: their licence forbids redistribution.
