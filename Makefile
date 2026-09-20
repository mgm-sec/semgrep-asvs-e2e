export PATH := $(CURDIR)/.venv/bin:$(PATH)
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
