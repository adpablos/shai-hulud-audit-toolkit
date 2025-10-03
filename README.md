# Shai-Hulud Audit Toolkit

[![CI](https://github.com/adpablos/shai-hulud-audit-toolkit/workflows/CI/badge.svg)](https://github.com/adpablos/shai-hulud-audit-toolkit/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

Pull the latest Shai-Hulud npm compromise advisories and check your machine for
matching package versions.

## Background

In September 2025 the "Shai-Hulud" supply-chain attack poisoned hundreds of
npm packages with credential-stealing payloads. The campaign automated
credential discovery, exfiltration, and worm-like replication through CI/CD
pipelines, making it difficult for engineering teams to maintain a trustworthy
dependency graph. This toolkit helps teams pull the latest public advisories
and audit their local environments for any compromised package versions.

## Features at a Glance

| Feature | Status | Notes |
|---------|--------|-------|
| 🔍 Multi-source advisory aggregation | ✅ | JFrog, Semgrep, Socket, OX Security, Wiz, StepSecurity |
| 🎯 IOC hash detection | ✅ | SHA-256 scanning for known malicious payloads |
| 💾 NPM cache scanning | ✅ | Scans ~/.npm/_cacache for compromised tarballs |
| 🌍 Global package inspection | ✅ | Checks globally installed npm packages |
| 📦 Lockfile analysis | ✅ | npm, yarn, pnpm support |
| 🔍 Script & workflow IOCs | ✅ | package.json hooks, GitHub Actions workflows |
| ⚠️ Namespace warnings | ✅ | Alerts on compromised maintainer scopes |
| 🔒 Suspicious pattern detection | ✅ | eval, child_process, network calls (optional) |
| 🚨 Exfiltration detection | ✅ | Webhook endpoints, credential transmission (optional) |
| 📊 Structured reports | ✅ | Multi-section layout with recommendations |
| 🎨 Color-coded output | ✅ | ANSI colors with auto-detection |
| 😃 Visual indicators | ✅ | Emoji-based risk markers |
| 📋 JSON output | ✅ | Machine-readable findings |
| ✅ 80% test coverage | ✅ | Pytest with coverage gating |
| 🐍 Python 3.10+ | ✅ | Cross-platform support |

## Why This Tool?

- **Comprehensive Coverage**: Multi-source advisory aggregation from 6+ security vendors
- **Beyond Versions**: Detects compromised packages via hash-based IOC scanning
- **Cache Aware**: Finds hidden threats in npm cache that other tools miss
- **Well Tested**: 80% test coverage with CI/CD enforcement
- **Extensible**: Easy to add new advisory sources via JSON configuration
- **Production Ready**: Designed for continuous monitoring in production environments

## Highlights

- **Single command audit** – `audit.py` fetches advisories and
  scans your home directory (including `node_modules` and global npm packages).
- **Broad source coverage** – JFrog, Semgrep, Socket, OX Security, Wiz,
  StepSecurity (and easy to extend).
- **Structured advisories** – writes `data/compromised_shaihulud.json` with every
  compromised `package@version` plus the confirming source URLs.
- **IOC detection** – multi-layered detection including:
  - Hash-based: scans for known malicious SHA-256 hashes in suspicious files
  - Script-based: detects malicious patterns in package.json lifecycle hooks
  - Workflow-based: identifies suspicious GitHub Actions workflows
- **Advanced threat detection** – optional scanning for:
  - Suspicious code patterns: eval usage, child processes, network calls, credential access
  - Data exfiltration: webhook endpoints, suspicious domains, credential transmission
- **Structured summary reports** – multi-section layout with scan scope, coverage stats,
  findings summary, detailed findings, and recommendations (auto-detects TTY for format).
- **Color-coded output** – ANSI color support with automatic terminal detection for
  improved readability (disable with `--no-color` or `NO_COLOR` environment variable).
- **Emoji risk indicators** – visual severity markers (🚨 critical, ⚠️ warning, ✅ clean)
  for quick scanning (disable with `--no-emoji`).
- **Concise logging** – per-source fetch logs and per-path scan stats saved under
  `logs/`.

> **Transparency**: This toolkit is built collaboratively by AI agents (Codex/Claude Code)
> with human-in-the-loop review. Code is primarily written by AI assistants following
> structured guidelines in [`AGENTS.md`](AGENTS.md) and [`CLAUDE.md`](CLAUDE.md), with a
> human maintainer reviewing, directing, and approving all changes. Quality is maintained
> through automated testing (80% coverage), linting, and CI checks.

## Requirements

- Python 3.10+
- Network access when fetching advisories (`--skip-fetch` skips the fetch stage)
- `npm` on your `PATH` if you scan the global package tree (default behaviour;
  disable via `--skip-global`)

## Installation

```bash
pip install .            # standard install
# or for development
pip install -r requirements-dev.txt
pip install -e .
```

This registers console scripts:

- `shai-hulud-audit`
- `shai-hulud-fetch`
- `shai-hulud-scan`

Each mirrors the corresponding script under `scripts/`.

## Quick Start

```bash
# Fetch advisories and scan your home directory (node_modules + global npm)
shai-hulud-audit
```

### Example Output

**Clean scan:**
```bash
$ shai-hulud-audit
[fetch] Consolidated 847 items across 421 packages. Log: logs/fetch/...
[scan] ✅ No compromised packages or IOCs detected.
INFO: Scan completed successfully.
```

**With findings:**
```bash
$ shai-hulud-audit /project
[fetch] Consolidated 847 items across 421 packages. Log: logs/fetch/...
[scan] ⚠️ Detected compromised dependencies:
WARNING: 📦 example@1.0.0 (package-lock.json) -> packages entry: node_modules/example
WARNING: ⚠️ Total findings: 1 (Dependencies: 1, IOCs: 0)
```

**Structured report format** (default for terminal):
```bash
======================================================================
📊 SHAI-HULUD AUDIT REPORT
======================================================================

🔍 SCAN SCOPE
----------------------------------------------------------------------
   • /home/user/project

📊 COVERAGE
----------------------------------------------------------------------
   Manifests scanned:     3
   Node modules scanned:  15
   Lockfiles analyzed:    1× package-lock.json

🔍 FINDINGS
----------------------------------------------------------------------
   ⚠️ Total Issues:        2
      • Dependencies:      2
      • IOC Matches:       0

⚠️ DETAILED FINDINGS
----------------------------------------------------------------------
   Compromised Dependencies:
   📦 example@1.0.0
      Location: package-lock.json
      Evidence: packages entry: node_modules/example

💡 RECOMMENDATIONS
----------------------------------------------------------------------
   1. Review detailed findings above
   2. Check advisory sources for remediation guidance
   3. Update or remove compromised packages
   4. Re-scan after remediation
======================================================================
```

### Common Usage Patterns

Useful modifiers (see [docs/USAGE.md](docs/USAGE.md) for more examples):

- `--skip-node-modules` – ignore installed node_modules trees
- `--skip-global` – skip global npm inspection
- `--skip-cache` – skip cached npm tarballs (cache inspection runs by default; override the location with `--npm-cache-dir`)
- `--no-hash-iocs` – disable hash-based IOC detection (enabled by default)
- `--no-detect-iocs` – disable script and workflow IOC detection (enabled by default)
- `--no-warn-namespaces` – disable warnings for compromised namespace scopes (enabled by default)
- `--detect-patterns` – enable suspicious code pattern detection (disabled by default)
- `--detect-exfiltration` – enable data exfiltration pattern detection (disabled by default)
- `--exfiltration-allowlist domains` – comma-separated list of domains to exclude from exfiltration checks
- `--no-color` – disable color output (also respects `NO_COLOR` environment variable)
- `--no-emoji` – disable emoji indicators (auto-disabled for non-TTY terminals)
- `--format [structured|compact|json]` – output format: `structured` (multi-section report, default for TTY), `compact` (legacy format, default for pipes), or `json`
- `--skip-scan` – fetch advisories but do not run the scanner
- `--skip-fetch --advisory path/to/file.json` – reuse a previously generated
  advisory instead of fetching
- `--json` – emit findings to stdout as JSON (alias for `--format json`)
- `paths…` – override the default scan target (`$HOME`)

Log files land in:

- `logs/fetch/` – advisory fetch results
- `logs/scan/` – scan summaries and findings

## Other Workflows

- Fetch only:
  ```bash
  shai-hulud-audit --skip-scan
  ```
- Scan with an existing advisory:
  ```bash
  shai-hulud-audit --skip-fetch --advisory data/compromised_shaihulud.json /project
  ```
- Combine multiple targets while skipping node_modules:
  ```bash
  shai-hulud-audit --skip-node-modules /project /another
  ```
- JSON output for automation:
  ```bash
  shai-hulud-audit --json > findings.json
  ```

## Configuration

`config/shai_hulud_sources.json` lists the advisory URLs. Each entry can include
an optional parser hint (view the supported list any time with
`shai-hulud-fetch --show-parsers`):

```json
{
  "sources": [
    { "url": "https://…", "parser": "ox_table" }
  ]
}
```

Supported hints: `stepsecurity_table`, `ox_table`, `wiz_list`. Omit the hint to
let the fetcher auto-detect or fall back to regex extraction.

## Logging

- Fetch logs include HTTP status, selected parser, and package/version counts
  per source. Scan logs record manifests, node_modules manifests, and lockfiles
  inspected, plus aggregate totals.
- Adjust verbosity with `--log-level`; prune files under `logs/` periodically
  if you keep the toolkit running on a schedule.
- Known malformed fixtures (for example the `resolve` package’s test fixtures)
  are suppressed at debug level—any warning that appears in the log deserves
  attention.

## Tests

The project ships a small pytest suite. Run it with:

```bash
pytest
```

See [`docs/TESTING.md`](docs/TESTING.md) for a detailed map of the suite and
guidance on where to add new coverage.

To include a coverage summary:

```bash
pytest --cov --cov-report=term-missing
```

Our GitHub Actions workflow runs the tests on every push and pull request.

For linting and formatting checks:

```bash
ruff check .
```

## Extending

- Add new advisory sources in `config/shai_hulud_sources.json` and, if needed,
  register a parser in `scripts/fetch.py`.
- Wrap `scripts/audit.py` (or the installed `shai-hulud-audit`
  console script) in a shell alias for bespoke combinations of skip flags or log
  destinations.

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines on:
- Setting up your development environment
- Code standards and quality requirements
- Testing and documentation requirements
- Branching strategy and PR process

For comprehensive development guidance, see [AGENTS.md](AGENTS.md).

## Updates & Versioning

- Current version: `v0.2.0` - see [CHANGELOG.md](CHANGELOG.md) for release history
- Updates are published as new advisories surface and features are added
- Check the changelog to stay current with the latest improvements

## License

Released under the MIT License. See `LICENSE` for details.
