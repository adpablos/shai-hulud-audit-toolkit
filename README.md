# Shai-Hulud Audit Toolkit

Pull the latest Shai-Hulud npm compromise advisories and check your machine for
matching package versions.

## Background

In September 2025 the "Shai-Hulud" supply-chain attack poisoned hundreds of
npm packages with credential-stealing payloads. The campaign automated
credential discovery, exfiltration, and worm-like replication through CI/CD
pipelines, making it difficult for engineering teams to maintain a trustworthy
dependency graph. This toolkit helps teams pull the latest public advisories
and audit their local environments for any compromised package versions.

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

> Transparency: the toolkit is built collaboratively by a Codex agent with
> human-in-the-loop review. See [`AGENTS.md`](AGENTS.md) for the shared
> engineering guide.

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
python3 scripts/audit.py
```

Useful modifiers (see [docs/USAGE.md](docs/USAGE.md) for more examples):

- `--skip-node-modules` – ignore installed node_modules trees
- `--skip-global` – skip global npm inspection
- `--skip-cache` – skip cached npm tarballs (cache inspection runs by default; override the location with `--npm-cache-dir`)
- `--no-hash-iocs` – disable hash-based IOC detection (enabled by default)
- `--no-detect-iocs` – disable script and workflow IOC detection (enabled by default)
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
  python3 scripts/audit.py --skip-scan
  ```
- Scan with an existing advisory:
  ```bash
  python3 scripts/audit.py --skip-fetch --advisory data/compromised_shaihulud.json /project
  ```
- Combine multiple targets while skipping node_modules:
  ```bash
  python3 scripts/audit.py --skip-node-modules /project /another
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

## Updates & Contributing

- Versioning starts at `v0.1.0`; see [`CHANGELOG.md`](CHANGELOG.md) for the
  release history.
- Issue reports and pull requests are welcome, especially for new advisory
  sources or parser improvements. Please include relevant log snippets when
  filing issues.
- Updates are published on a best-effort basis as new advisories surface; check
  the changelog to stay current.

## License

Released under the MIT License. See `LICENSE` for details.
