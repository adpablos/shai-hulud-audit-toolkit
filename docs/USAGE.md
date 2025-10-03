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

### Disable script and workflow IOC detection
```bash
shai-hulud-audit --no-detect-iocs
```
Script and workflow IOC detection runs by default, identifying:
- **Script IOCs**: Suspicious patterns in package.json lifecycle hooks (curl, wget, webhook.site, known Shai-Hulud UUIDs)
- **Workflow IOCs**: Malicious GitHub Actions workflow files (shai-hulud-workflow.yml, shai-hulud.yml)

Use this flag to disable these detections if they cause false positives in your environment.

### Disable color output
```bash
shai-hulud-audit --no-color
```
Terminal output includes ANSI color codes by default for improved readability
(error messages in red, warnings in yellow, etc.). Colors are automatically
disabled when output is piped or redirected to a file. Use `--no-color` to
explicitly disable colors, or set the `NO_COLOR` environment variable per
https://no-color.org/.

### Disable emoji indicators
```bash
shai-hulud-audit --no-emoji
```
By default, scan results include emoji-based risk indicators for quick visual
assessment:
- 🚨 CRITICAL: 10+ findings or any IOC detections
- ⚠️ WARNING: 3-9 findings
- ✅ CLEAN: No compromised packages or IOCs detected
- 📦 Package indicator for dependency findings
- 📄 File indicator for IOC hash matches

Emojis are automatically disabled when output is piped to a file or the terminal
doesn't support them (e.g., `TERM=dumb`). Use `--no-emoji` to explicitly disable
emoji output while keeping colors enabled.

### Output formats
```bash
# Structured report (default for TTY)
shai-hulud-audit --format structured

# Compact report (default when piped)
shai-hulud-audit --format compact

# JSON output
shai-hulud-audit --format json
# or use the --json alias
shai-hulud-audit --json
```

The `--format` flag controls the scan output format:

- **`structured`** (default for terminal output): Multi-section report with clear
  visual hierarchy including:
  - Scan Scope: Paths that were scanned
  - Coverage: Statistics on manifests, node modules, and lockfiles analyzed
  - Findings: Summary counts of issues detected
  - Detailed Findings: Individual package/IOC details with location and evidence
  - Recommendations: Remediation steps (shown only when findings exist)

- **`compact`** (default when output is piped): Legacy single-stream format that
  logs findings inline without section headers. Suitable for grep/awk processing.

- **`json`**: Machine-readable JSON array of finding objects. Each finding includes
  `package`, `version`, `source`, `evidence`, and `category` fields.

Format auto-detection: When `--format` is not specified, the tool detects whether
stdout is a TTY. Interactive terminals get `structured` format, while pipes and
redirects get `compact` format for easier parsing.

### Advanced threat detection

#### Suspicious code pattern detection
```bash
# Enable pattern detection (disabled by default)
shai-hulud-audit --detect-patterns

# Filter by severity
shai-hulud-audit --detect-patterns --pattern-severity high

# Detect specific pattern categories
shai-hulud-audit --detect-patterns --pattern-categories eval_usage,child_process
```

Pattern detection scans JavaScript files for suspicious code patterns:
- **eval_usage**: Dynamic code evaluation (`eval()`, `Function()`)
- **child_process**: Shell command execution
- **network_calls**: HTTP/HTTPS requests, WebSocket connections
- **credential_access**: Environment variable access, file reads
- **obfuscation**: String concatenation, hex/base64 encoding
- **file_system**: File write operations, directory traversal
- **command_injection**: Shell metacharacters in command arguments

Minified files are automatically skipped to reduce false positives.

#### Data exfiltration detection
```bash
# Enable exfiltration detection (disabled by default)
shai-hulud-audit --detect-exfiltration

# Allowlist legitimate domains
shai-hulud-audit --detect-exfiltration --exfiltration-allowlist ngrok.io,localhost
```

Exfiltration detection scans JavaScript files for data theft indicators:
- **Webhook endpoints**: Discord, Slack, Telegram bot webhooks
- **Suspicious domains**: Pastebin, ngrok, temp file sharing services
- **Credential transmission**: SSH keys, AWS credentials, API tokens
- **IP addresses**: Direct connections to IP addresses

**Smart severity scoring**:
- **Critical**: Credential access combined with network transmission in same file
- **High**: Webhook endpoints detected
- **Medium**: Suspicious domains without credential access
- **Low**: Potential indicators requiring manual review

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

The scanner produces different output formats depending on the `--format` flag
(or auto-detection based on TTY). Examples below show both compact and structured
formats.

### Clean run (exit code `0`)

**Compact format** (default when piped, or `--format compact`):
```
INFO: Detailed execution log: /tmp/.../logs/shai_hulud_scan_YYYYMMDD_HHMMSS.log
INFO: Loading advisory data from /tmp/.../advisory.json
INFO: Indexed 1 packages covering 1 compromised versions.
INFO: Scanning /tmp/.../workspace
INFO: Summary for /tmp/.../workspace: 1 manifests (0 within node_modules); lockfiles: none.
INFO: Aggregate summary: 1 manifests scanned (0 within node_modules); lockfiles: none.
INFO: ✅ No compromised packages or IOCs detected.
INFO: Scan completed successfully. Log retained at /tmp/.../logs/shai_hulud_scan_YYYYMMDD_HHMMSS.log
```

**Structured format** (default for TTY, or `--format structured`):
```
======================================================================
📊 SHAI-HULUD AUDIT REPORT
======================================================================

🔍 SCAN SCOPE
----------------------------------------------------------------------
   • /tmp/.../workspace

📊 COVERAGE
----------------------------------------------------------------------
   Manifests scanned:     1
   Node modules scanned:  0
   Lockfiles analyzed:    none

🔍 FINDINGS
----------------------------------------------------------------------
   ✅ No compromised packages or IOCs detected

======================================================================
```

No matches were found and the process exited with status `0`.

### Findings present (exit code `1`)

**Compact format**:
```
INFO: Detailed execution log: /tmp/.../logs/shai_hulud_scan_YYYYMMDD_HHMMSS.log
INFO: Loading advisory data from /tmp/.../advisory.json
INFO: Indexed 1 packages covering 1 compromised versions.
INFO: Scanning /tmp/.../workspace
INFO: Summary for /tmp/.../workspace: 1 manifests (0 within node_modules); lockfiles: 1× package-lock.json.
INFO: Aggregate summary: 1 manifests scanned (0 within node_modules); lockfiles: 1× package-lock.json.
WARNING: ⚠️ Detected compromised dependencies:
WARNING: 📦 example@1.0.0 (package-lock.json) -> packages entry: node_modules/example
WARNING: 📦 example@1.0.0 (package.json) -> dependencies -> example = 1.0.0
WARNING: ⚠️ Total findings: 2 (Dependencies: 2, IOCs: 0)
WARNING: Findings recorded in /tmp/.../logs/shai_hulud_scan_YYYYMMDD_HHMMSS.log
```

**Structured format**:
```
======================================================================
📊 SHAI-HULUD AUDIT REPORT
======================================================================

🔍 SCAN SCOPE
----------------------------------------------------------------------
   • /tmp/.../workspace

📊 COVERAGE
----------------------------------------------------------------------
   Manifests scanned:     1
   Node modules scanned:  0
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
   📦 example@1.0.0
      Location: package.json
      Evidence: dependencies -> example = 1.0.0

💡 RECOMMENDATIONS
----------------------------------------------------------------------
   1. Review detailed findings above
   2. Check advisory sources for remediation guidance
   3. Update or remove compromised packages
   4. Re-scan after remediation

======================================================================
```

If IOC hash matches are found, they appear in a separate subsection:

```
   IOC Hash Matches (Known Malicious Files):
   📄 bundle.js
      Location: node_modules/@ctrl/tinycolor/bundle.js
      Evidence: SHA-256: de0e25a3e6c1e1e5998b306b7141b3dc4c0088da9d7bb47c1c00c91e6e4f85d6
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
