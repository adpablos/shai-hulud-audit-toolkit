# Changelog

## v0.1.0 - 2025-09-17

- Initial public release of the Shai-Hulud Audit Toolkit
- Command-line flow `audit.py` (fetch + scan), plus standalone `fetch.py` and
  `scan.py`, each with consistent `run()` entry points and documented console
  scripts
- Fetch advisories from multiple vendors, consolidate into
  `data/compromised_shaihulud.json`, and summarise source success/failure
- Scan the home directory by default, including `node_modules` trees and global
  npm packages; provide `--skip-*` toggles (`--skip-fetch`, `--skip-scan`,
  `--skip-node-modules`, `--skip-global`) and `--json` output
- Configurable advisory sources with parser hints (`--show-parsers`) and strict
  validation for unknown keys/values
- Tests (pytest) and GitHub Actions CI workflow running lint (`ruff`) and tests
- Comprehensive documentation in `README.md` and `docs/USAGE.md`
