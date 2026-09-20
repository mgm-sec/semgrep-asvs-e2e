# semgrep-asvs — design

Date: 2026-09-20. Status: approved design, pre-implementation.

## Goal

A small, self-contained package that runs Semgrep with a curated rule set and reports
findings against OWASP ASVS 4.0.3 requirements and levels (L1/L2/L3), usable as a
pre-commit hook, a GitHub Action, and a plain CLI. Report-only by default; blocking is
opt-in per surface.

## Decisions (with reasons)

| Decision | Choice | Why |
|---|---|---|
| ASVS version | 4.0.3, pinned copy of OWASP's `*.flat.json` (286 requirements, 268 with a CWE) | User scope: "ASVS4". 5.0 is a later swap of one JSON file. |
| Rule source | `opengrep/opengrep-rules` (LGPL 2.1 + Commons Clause), vendored and pinned to a commit | Semgrep's own registry rules are under Semgrep Rules License v1.0: internal use only, no redistribution. GitLab `sast-rules` (MIT) has no PHP. opengrep-rules is redistributable, has Python/PHP/JS/TS/Go with CWE metadata, and all 730 rules validate on Semgrep 1.177.0 (728/730 rule tests pass). |
| Engine | Semgrep CE, pinned `semgrep==1.177.0` (latest, 2026-09-10) | Largest ecosystem, official pre-commit/Action patterns. Rules stay Opengrep-compatible (no Pro-only syntax) so the engine can be swapped later. |
| Version pin | One pin in `pyproject.toml`; Renovate bumps it; CI proves rules still pass | Never baseline on an old Semgrep. |
| Rule freshness | Weekly workflow re-syncs from opengrep-rules `main`, opens a PR if changed | opengrep-rules is a snapshot (last push 2025-11); the licence forces this trade, automation keeps it as fresh as possible. |
| ASVS mapping | Side-map at report time: rule CWE → ASVS CWE, plus `overrides.yaml` and `metadata.asvs` on custom rules | Vendor files stay untouched (clean re-sync, no LGPL modification notices). |
| Enforcement | All rules always run; every finding is reported with its ASVS IDs and levels; exit 0 unless `--strict` | User choice: report-only default, opt-in blocking. |
| Outputs | Semgrep JSON, SARIF (ASVS-tagged), `coverage.md`, terminal text | GitHub Security tab, compliance evidence, downstream tools, developers. |
| Languages | Python, PHP, JavaScript, TypeScript, Go | User choice. |
| Distribution | Git repo + tags (`repo:` in pre-commit, `uses:` in Actions) | No registry, no publishing step. |
| Licence | EUPL-1.2 for our code; `rules/vendor/` keeps the opengrep-rules LICENSE | User choice; EUPL is compatible with LGPL vendor content. |

## Honesty rule

CWE is coarse: one CWE-287 rule "relates to" eight ASVS requirements. Every report says
**related rules**, never "verified" or "compliant". Requirements with no CWE (18) and
requirements with a CWE but no rule are listed explicitly as gaps. SAST evidence supports
an ASVS assessment; it does not constitute one.

## Repository layout

```
semgrep-asvs/
  pyproject.toml                 # hatchling; name semgrep-asvs; dependencies = ["semgrep==1.177.0"]; script semgrep-asvs
  semgrep_asvs/
    __init__.py                  # the whole tool, stdlib only (subprocess, json, argparse, pathlib, re, datetime)
    __main__.py                  # `python -m semgrep_asvs`
    asvs/
      asvs-4.0.3.flat.json       # OWASP source, unmodified
      overrides.yaml             # rule-id suffix -> [ASVS ids]  (see Mapping)
    rules/
      vendor/
        LICENSE                  # from opengrep-rules
        VENDOR-COMMIT            # sha the snapshot was taken from
        python/ php/ javascript/ typescript/ go/   # verbatim copies incl. their test files
      custom/
        python/ php/ javascript/ go/               # our rules, one .yaml + one test file each
  fixtures/                      # tiny vulnerable files per language for the self-test (not packaged)
  test_semgrep_asvs.py           # one test file, stdlib unittest
  known-failures.txt             # vendor rule ids whose upstream tests fail on the pinned Semgrep
  .pre-commit-hooks.yaml
  action.yml
  Makefile
  scripts/sync-rules.sh
  .github/workflows/ci.yml
  .github/workflows/sync-rules.yml
  renovate.json
  README.md
  LICENSE                        # EUPL-1.2
```

Rules and the ASVS JSON live inside the package directory so the same path works from a
checkout and from a pip install (pre-commit installs the repo into its own env). The wheel
excludes everything under `rules/` that is not `*.yaml`/`*.yml`, so vendor test sources are
not installed. `overrides.yaml` is parsed with a 20-line stdlib parser (flat `key: [a, b]`
lines only); no PyYAML dependency. Rule metadata is read from Semgrep's JSON output, never
from the YAML files.

## The tool: `semgrep-asvs`

### `scan [PATHS...] [--out DIR] [--format LIST] [--strict]`

1. Run once:
   `semgrep scan --metrics=off --disable-version-check --quiet --config <pkg>/rules/vendor --config <pkg>/rules/custom --json-output=OUT/semgrep.json --sarif-output=OUT/semgrep.sarif [PATHS]`
   (`PATHS` default `.`; pre-commit passes staged files.)
2. Load ASVS JSON; build `cwe -> [requirement]`. Parse every digit-run in a requirement's
   `cwe` field as a CWE number.
3. For every finding, ASVS IDs = union of
   - `extra.metadata.asvs` (custom rules),
   - `overrides.yaml[key]` where `check_id` ends with `.` + key (or equals key),
   - requirements whose CWE appears in `extra.metadata.cwe` (parse `CWE-(\d+)`).
   Levels come from the requirement (`level1/2/3` non-empty).
4. Write outputs selected by `--format` (default `text,md,sarif,json`; `--out` default
   `semgrep-asvs-out`):
   - `json`: Semgrep's JSON, untouched.
   - `sarif`: Semgrep's SARIF with `runs[0].tool.driver.rules[*].properties.tags` extended
     with `asvs/V6.2.8`, `asvs-level/L1`, `cwe/385` for each rule that has findings.
   - `md`: `coverage.md` (structure below).
   - `text`: printed to stdout, never a file. Findings grouped by ASVS chapter:
     `V6.2.8 [L2 L3] ERROR  custom.go.constant-time-compare  app/auth.go:42  message`,
     then unmapped findings (rule has no ASVS relation) under "No ASVS mapping", then a
     summary: findings per severity, requirements touched per level.
5. Exit code: 0. With `--strict`: 1 if any finding has severity ERROR. 2 on tool errors
   (Semgrep missing, Semgrep exit code ≥ 2, unparsable output); Semgrep's stderr is passed
   through.

`coverage.md`:

```
# ASVS 4.0.3 coverage report
Generated <ISO date>, semgrep <version>, rules: <n> vendor + <m> custom, targets: <paths>

## Summary by level
| Level | Requirements | With related rules | With findings |

## Findings by requirement            (only requirements with findings)
| ASVS | Levels | Severity | Rule | Location | Message |

## Requirement map                    (all 286, grouped by chapter, collapsible <details>)
| ASVS | L1 | L2 | L3 | CWE | Related rules | Findings |

## Gaps
- Requirements with a CWE but no related rule: <list>
- Requirements without a CWE: <list>
- Findings with no ASVS relation: <count>
```

### `coverage [--format md|text]`

No scan. Loads the rule set via `semgrep --validate --json`? No: `--validate` does not
emit metadata. Instead runs `semgrep scan --config ... --json-output` against an empty
temp directory to obtain the loaded rule list with metadata, then prints the Requirement
map and Gaps sections. This is the input for deciding which custom rules to write next.

## Mapping files

`overrides.yaml` (flat, one line per rule; key is a `check_id` suffix, unique enough to
disambiguate same-named rules across languages):

```yaml
# rule-id suffix: [ASVS ids]   — vendor rules the CWE join misses
python.django.security.audit.debug-enabled: [V14.3.2]
php.laravel.security.laravel-active-debug-code: [V14.3.2]
go.net.pprof-debug-exposure: [V14.3.2]
javascript.lang.security.audit.javascript-debugger: [V14.3.2]
python.lang.security.audit.insecure-random: [V3.2.2, V3.2.4]   # exact ids fixed during implementation
php.lang.security.include-injection: [V5.3.9]
```

Custom rule metadata (required on every custom rule; the self-test enforces it):

```yaml
metadata:
  asvs: [V6.2.8]
  cwe: ["CWE-385: Covert Timing Channel"]
  category: security
  technology: [go]
  references: [https://owasp.org/www-project-application-security-verification-standard/]
```

## Custom starter set (6 rules, each with a test file)

| Rule id | Lang | ASVS | CWE | Pattern | Fix advice |
|---|---|---|---|---|---|
| `constant-time-compare` | python | V6.2.8 | 385 | `hmac.new(...).hexdigest()`/`.digest()` compared with `==`/`!=` | `hmac.compare_digest` |
| `constant-time-compare` | php | V6.2.8 | 385 | `hash_hmac(...)` compared with `==`/`===`/`!=`/`!==` | `hash_equals` |
| `constant-time-compare` | javascript (+typescript) | V6.2.8 | 385 | `crypto.createHmac(...).update(...).digest(...)` compared with `==`/`===`/`!=`/`!==` | `crypto.timingSafeEqual` |
| `constant-time-compare` | go | V6.2.8 | 385 | `bytes.Equal($M, $X)` or `string($M) == $X` where `$M` is `hmac...Sum(...)` | `hmac.Equal` |
| `django-password-min-length` | python | V2.1.1 | 521 | `MinimumLengthValidator` entry with `min_length` < 12, or without `OPTIONS` (default 8) | set `min_length: 12` |
| `laravel-password-min-length` | php | V2.1.1 | 521 | `Password::min($N)` with `$N` < 12 | `Password::min(12)` |

Chosen from the L1/L2 gap list where a static check has low false-positive risk.

## Consumer surfaces

### pre-commit (`.pre-commit-hooks.yaml`)

```yaml
- id: semgrep-asvs
  name: semgrep-asvs
  entry: semgrep-asvs scan --format text
  language: python
  types_or: [python, php, javascript, jsx, ts, tsx, go]
  require_serial: true
```

Consumer config: `repo: <this repo>`, `rev: v1.x`, optional `args: [--strict]`.
pre-commit installs this package (and thereby the pinned Semgrep) in its own environment.

### GitHub Action (`action.yml`, composite)

Inputs: `paths` (default `.`), `strict` (default `false`), `upload-sarif` (default
`true`), `python-version` (default `3.12`).
Steps: `actions/setup-python`; `pip install "$GITHUB_ACTION_PATH"`; run
`semgrep-asvs scan --out semgrep-asvs-out [--strict] <paths>` with `continue-on-error`
and `id: scan`; append `coverage.md` to `$GITHUB_STEP_SUMMARY`; `upload-sarif` via
`github/codeql-action/upload-sarif` (needs `security-events: write`, documented in
README); `actions/upload-artifact` with the out dir; final step fails the job if
`steps.scan.outcome == 'failure'`. All post-scan steps run `if: always()`.

### Makefile

`install` (`pip install -e .`), `scan` (`semgrep-asvs scan`), `coverage`, `test`
(validate + rule tests + unittest), `sync` (`scripts/sync-rules.sh`).

## Testing

- **Rule validity**: `semgrep --validate --config semgrep_asvs/rules` on the pinned version.
- **Rule tests**: `semgrep --test --json --config semgrep_asvs/rules semgrep_asvs/rules`.
  The failing set must be a subset of `known-failures.txt` (currently
  `avoid-query-set-extra`, `unsafe-argon2-config`, both upstream misses). New failures
  fail CI; fixed ones are removed from the file by hand.
- **Tool test** (`test_semgrep_asvs.py`): runs `scan` on `fixtures/`; asserts each
  language's fixture produces V6.2.8 in `coverage.md` and the SARIF rule tags; asserts a
  vendor-covered finding maps via CWE; asserts `--strict` exits 1 and default exits 0;
  asserts every custom rule has `metadata.asvs` and `metadata.cwe` with IDs present in the
  ASVS JSON; asserts every override key matches exactly one loaded rule.
- **Dogfood**: CI runs `uses: ./` on `fixtures/` with `upload-sarif: false`, and
  `pre-commit try-repo . semgrep-asvs --files fixtures/*`.

## Keeping current

- `renovate.json`: `config:recommended`; the built-in pep621 manager bumps `semgrep==`
  in `pyproject.toml`; github-actions manager pins/bumps action SHAs. CI on the bot PR
  is the proof that the new Semgrep still validates and passes the rule tests.
- `sync-rules.yml` (weekly, `workflow_dispatch`): resolve opengrep-rules `main` HEAD,
  write it to `scripts/sync-rules.sh`'s `OPENGREP_RULES_COMMIT=`, run the sync, open a PR
  via `peter-evans/create-pull-request` if the tree changed.
- `scripts/sync-rules.sh`: shallow-clone the pinned commit, replace the five language
  dirs and `LICENSE` under `rules/vendor/`, write `VENDOR-COMMIT`. Never edits files.

## Error handling

- Semgrep not on PATH → exit 2, message names the pin and `pip install`.
- Semgrep exit ≥ 2 → pass stderr through, exit 2.
- Partial-parse errors inside Semgrep's JSON (`errors[]`) → listed in the text summary,
  do not change the exit code.
- Unknown `--format` token → argparse error.

## Out of scope (v1)

ASVS 5.0; GitLab CI template; PyPI or container distribution; baseline/diff-aware
blocking; a config file; per-rule enable/disable flags (consumers use `.semgrepignore`
and `// nosemgrep`); full custom coverage of ASVS.
