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
