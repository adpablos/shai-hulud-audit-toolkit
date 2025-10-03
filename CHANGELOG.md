# Changelog

## Unreleased

- Enhance PyPI discoverability with expanded keywords, comprehensive classifiers,
  and complete project URLs in package metadata (#16)
- Add ANSI color-coded terminal output with automatic TTY detection, `--no-color`
  flag, and NO_COLOR environment variable support for improved readability (#10)
- Add emoji-based risk indicators (🚨 critical, ⚠️ warning, ✅ clean) with
  `--no-emoji` flag and automatic terminal compatibility detection (#11)
- Add structured summary report with multi-section layout (scan scope, coverage,
  findings, detailed findings, recommendations) via `--format` flag supporting
  `structured`, `compact`, and `json` output formats with TTY auto-detection (#12)
- Add script and workflow IOC detection for known Shai-Hulud indicators (suspicious
  lifecycle hooks, GitHub workflows with malicious patterns) with `--detect-iocs`
  and `--no-detect-iocs` flags. Adds `severity` field to Finding dataclass for
  enhanced triage capabilities (#6)
- Add extended suspicious code pattern detection for JavaScript files including
  eval usage, child process execution, network calls, credential access, code
  obfuscation, file system access, and command injection patterns. Controlled via
  `--detect-patterns`, `--pattern-severity`, and `--pattern-categories` flags.
  Includes minified file detection and configurable severity filtering (#13)
- Add data exfiltration pattern detection scanning for suspicious domains, webhook
  endpoints (Discord, Slack, Telegram), credential access patterns, and network
  transmission indicators with smart severity scoring (critical when credential
  access combined with network calls). Controlled via `--detect-exfiltration` and
  `--exfiltration-allowlist` flags (#14)

## v0.2.0 - 2025-10-03

- Inspect cached npm tarballs by default and expose `--skip-cache` /
  `--npm-cache-dir` controls, surfacing compromised cache hits in JSON
  output and logs (#9)
- Add hash-based IOC detection for known malicious Shai-Hulud payload files,
  scanning for SHA-256 hashes in bundle.js, index.js, and install scripts.
  Enabled by default with `--no-hash-iocs` flag to disable (#8)

## v0.1.1 - 2025-09-17

- Ensure the `config` package ships in the distribution and add a regression test
  covering finding detection paths (#2)
- Document contributor workflow conventions and clarify expected scan output in
  the usage guide (#3)
- Reorganise and expand audit/fetch/scan tests, introduce coverage tooling, and
  enforce an 80% coverage gate in CI (#4)

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
