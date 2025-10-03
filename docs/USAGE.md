# Shai-Hulud Audit Toolkit – Usage Guide

This document expands on the quick-start instructions in the README. It covers
common task-based workflows, configuration knobs, and troubleshooting tips.

## Table of Contents

1. [Common Workflows](#common-workflows)
2. [Configuration & Parser Hints](#configuration--parser-hints)
3. [Operational Tips](#operational-tips)
4. [Interpreting Scan Output](#interpreting-scan-output)
5. [Troubleshooting](#troubleshooting)

## Common Workflows

### Fetch + Scan (default)
```bash
shai-hulud-audit
```
Runs a full audit against your home directory. Equivalent to:
```bash
python3 scripts/audit.py
```

### Fetch only
```bash
shai-hulud-audit --skip-scan
```
Fetches the latest advisories and exits after writing
`data/compromised_shaihulud.json`.

### Scan using an existing advisory
```bash
shai-hulud-audit --skip-fetch --advisory path/to/advisory.json
```
Reuse an advisory file that was generated previously (for example from CI).

### Targeted scan
```bash
shai-hulud-audit --skip-node-modules --skip-global /srv/app /tmp/build
```
Scans only the specified paths, ignoring `node_modules` subtrees and the global
npm install tree.

### Skip cached npm tarballs
```bash
shai-hulud-audit --skip-cache
```
Cache inspection runs by default. Use this flag if the cache directory is
unavailable or expensive to mount. Override the cache root when needed with
`--npm-cache-dir /custom/cache` (useful on CI or when scanning a mounted home
directory snapshot).

### Disable hash-based IOC detection
```bash
shai-hulud-audit --no-hash-iocs
```
Hash-based IOC (Indicator of Compromise) detection runs by default, scanning
files like `bundle.js`, `index.js`, and install scripts for known malicious
Shai-Hulud payload SHA-256 hashes. Use this flag to disable hash checking if
it causes performance issues or false positives.

### Disable color output
```bash
shai-hulud-audit --no-color
```
Terminal output includes ANSI color codes by default for improved readability
(error messages in red, warnings in yellow, etc.). Colors are automatically
disabled when output is piped or redirected to a file. Use `--no-color` to
explicitly disable colors, or set the `NO_COLOR` environment variable per
https://no-color.org/.

## Configuration & Parser Hints

Advisory sources are defined in `config/shai_hulud_sources.json`:
```json
{
  "sources": [
    { "url": "https://example.com/advisory", "parser": "ox_table" }
  ]
}
```
- `parser` is optional. Supported values are `stepsecurity_table`, `ox_table`,
  and `wiz_list`. Omit it to let the fetcher auto-detect based on the domain or
  fall back to regex matching.
- Run `shai-hulud-fetch --show-parsers` to list the available parser hints.
- Providing an unknown parser hint now raises a validation error so typos are
  caught early.

## Operational Tips

- Logs are written to `logs/fetch/` and `logs/scan/`. Rotate or clean these
  folders periodically in long-running environments.
- The scanner suppresses warnings for known malformed fixtures (such as the
  `resolve` package tests). Any new warnings indicate real issues.
- Use `--json` to capture findings in machine-readable form for follow-up
  automation.
- Cache inspection runs by default. Combine `--skip-cache` with `--npm-cache-dir`
  to point at a temporary cache snapshot without touching the live cache when
  needed.
- Hash-based IOC detection runs by default, checking files for known malicious
  Shai-Hulud payload hashes. Files larger than 10MB are skipped for performance.
  Use `--no-hash-iocs` to disable if needed.

## Interpreting Scan Output

### Clean run (exit code `0`)

```
INFO: Detailed execution log: /tmp/.../logs/shai_hulud_scan_YYYYMMDD_HHMMSS.log
INFO: Loading advisory data from /tmp/.../advisory.json
INFO: Indexed 1 packages covering 1 compromised versions.
INFO: Scanning /tmp/.../workspace
INFO: Summary for /tmp/.../workspace: 1 manifests (0 within node_modules); lockfiles: none.
INFO: Aggregate summary: 1 manifests scanned (0 within node_modules); lockfiles: none.
INFO: No compromised packages detected.
INFO: Scan completed successfully. Log retained at /tmp/.../logs/shai_hulud_scan_YYYYMMDD_HHMMSS.log
```

No matches were found and the process exited with status `0`.

### Findings present (exit code `1`)

```
INFO: Detailed execution log: /tmp/.../logs/shai_hulud_scan_YYYYMMDD_HHMMSS.log
INFO: Loading advisory data from /tmp/.../advisory.json
INFO: Indexed 1 packages covering 1 compromised versions.
INFO: Scanning /tmp/.../workspace
INFO: Summary for /tmp/.../workspace: 1 manifests (0 within node_modules); lockfiles: 1× package-lock.json.
INFO: Aggregate summary: 1 manifests scanned (0 within node_modules); lockfiles: 1× package-lock.json.
WARNING: Detected compromised dependencies:
WARNING: - example@1.0.0 (package-lock.json) -> packages entry: node_modules/example
WARNING: - example@1.0.0 (package.json) -> dependencies -> example = 1.0.0
WARNING: Total findings: 2 (Dependencies: 2, IOCs: 0)
WARNING: Findings recorded in /tmp/.../logs/shai_hulud_scan_YYYYMMDD_HHMMSS.log
```

If IOC hash matches are found, they will be reported separately:

```
WARNING: Detected IOC hash matches (known malicious files):
WARNING: - bundle.js (node_modules/@ctrl/tinycolor/bundle.js) -> SHA-256: de0e25a3e6c1e1e5998b306b7141b3dc4c0088da9d7bb47c1c00c91e6e4f85d6
WARNING: Total findings: 3 (Dependencies: 2, IOCs: 1)
```

The scanner elevates to `WARNING` level for each finding and terminates with
status `1`. Review the referenced log file for the full trace and consider
rerunning with `--json` to capture the findings programmatically.

## Troubleshooting

| Symptom | Likely Cause | Resolution |
| --- | --- | --- |
| Fetch fails with `403 Forbidden` | Source requires a browser user-agent | The fetcher already sends one; re-run and ensure network access is allowed |
| Fetch fails entirely | Lack of network egress | Provide `--skip-fetch --advisory existing.json` or run from a host with internet access |
| Global scan skipped with warning | `npm` not on `PATH` | Install Node/npm or pass `--skip-global` |
| "Nothing to do" error | Both fetch and scan disabled | Run without `--skip-fetch` and `--skip-scan` together |

For additional help, file an issue on the project repository with the relevant
log excerpts.
