# Shai-Hulud Audit Toolkit – Usage Guide

This document expands on the quick-start instructions in the README. It covers
common task-based workflows, configuration knobs, and troubleshooting tips.

## Table of Contents

1. [Common Workflows](#common-workflows)
2. [Configuration & Parser Hints](#configuration--parser-hints)
3. [Operational Tips](#operational-tips)
4. [Troubleshooting](#troubleshooting)

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

## Troubleshooting

| Symptom | Likely Cause | Resolution |
| --- | --- | --- |
| Fetch fails with `403 Forbidden` | Source requires a browser user-agent | The fetcher already sends one; re-run and ensure network access is allowed |
| Fetch fails entirely | Lack of network egress | Provide `--skip-fetch --advisory existing.json` or run from a host with internet access |
| Global scan skipped with warning | `npm` not on `PATH` | Install Node/npm or pass `--skip-global` |
| "Nothing to do" error | Both fetch and scan disabled | Run without `--skip-fetch` and `--skip-scan` together |

For additional help, file an issue on the project repository with the relevant
log excerpts.
