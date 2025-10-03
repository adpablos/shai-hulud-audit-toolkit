# Shai-Hulud Audit Toolkit – Usage Guide

This document expands on the quick-start instructions in the README. It covers
common task-based workflows, configuration knobs, and troubleshooting tips.

## Table of Contents

1. [Common Workflows](#common-workflows)
2. [Configuration & Parser Hints](#configuration--parser-hints)
3. [Operational Tips](#operational-tips)
4. [Interpreting Scan Output](#interpreting-scan-output)
5. [Troubleshooting](#troubleshooting)
6. [CI/CD Integration](#cicd-integration)

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

### Disable namespace warnings
```bash
shai-hulud-audit --no-warn-namespaces
```
Namespace compromise warnings run by default, alerting when dependencies use scoped packages from compromised maintainer namespaces. For example, if the advisory lists `@malicious-scope/bad-package`, the scanner will warn about ANY package from `@malicious-scope/*`, even if the specific package isn't compromised.

This helps identify supply chain risk exposure when a maintainer account is hijacked. Use `--no-warn-namespaces` to disable these warnings if you have many false positives from legitimately-used namespaces.

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

## CI/CD Integration

### GitHub Actions

Basic workflow for pull requests and pushes:

```yaml
name: Shai-Hulud Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.10'
      - name: Install scanner
        run: pip install shai-hulud-audit-toolkit
      - name: Run security scan
        run: shai-hulud-audit --json > findings.json
      - name: Upload findings
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: security-findings
          path: findings.json
```

Advanced workflow with matrix scanning:

```yaml
name: Multi-Project Security Scan
on:
  schedule:
    - cron: '0 8 * * *'  # Daily at 8am UTC
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        project: [frontend, backend, shared-libs]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.10'
      - name: Install scanner
        run: pip install shai-hulud-audit-toolkit
      - name: Scan ${{ matrix.project }}
        run: |
          shai-hulud-audit --format structured ./${{ matrix.project }} \
            --skip-global --skip-cache
      - name: Export JSON findings
        if: always()
        run: shai-hulud-audit --json ./${{ matrix.project }} > ${{ matrix.project }}-findings.json
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: ${{ matrix.project }}-findings
          path: ${{ matrix.project }}-findings.json
```

### GitLab CI

Basic `.gitlab-ci.yml`:

```yaml
security_scan:
  stage: test
  image: python:3.10
  script:
    - pip install shai-hulud-audit-toolkit
    - shai-hulud-audit --json > findings.json
  artifacts:
    when: on_failure
    paths:
      - findings.json
    expire_in: 30 days
```

Advanced with caching and manual review:

```yaml
security_scan:
  stage: test
  image: python:3.10
  before_script:
    - pip install shai-hulud-audit-toolkit
  script:
    - shai-hulud-audit --format structured
    - shai-hulud-audit --json > findings.json
  artifacts:
    when: always
    reports:
      junit: findings.json  # GitLab can parse JSON for review
    paths:
      - findings.json
      - logs/
    expire_in: 30 days
  cache:
    key: ${CI_COMMIT_REF_SLUG}
    paths:
      - data/compromised_shaihulud.json
  allow_failure: false
```

### Jenkins

Jenkinsfile example:

```groovy
pipeline {
    agent any

    stages {
        stage('Setup') {
            steps {
                sh 'pip install shai-hulud-audit-toolkit'
            }
        }

        stage('Security Scan') {
            steps {
                script {
                    def exitCode = sh(
                        script: 'shai-hulud-audit --json > findings.json',
                        returnStatus: true
                    )

                    if (exitCode != 0) {
                        archiveArtifacts artifacts: 'findings.json', fingerprint: true
                        error('Security scan detected compromised packages')
                    }
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'logs/**/*', allowEmptyArchive: true
        }
    }
}
```

### CircleCI

`.circleci/config.yml`:

```yaml
version: 2.1

jobs:
  security-scan:
    docker:
      - image: cimg/python:3.10
    steps:
      - checkout
      - run:
          name: Install scanner
          command: pip install shai-hulud-audit-toolkit
      - run:
          name: Run scan
          command: |
            shai-hulud-audit --format structured
            shai-hulud-audit --json > findings.json
      - store_artifacts:
          path: findings.json
          destination: security-findings
      - store_artifacts:
          path: logs
          destination: scan-logs

workflows:
  version: 2
  security-checks:
    jobs:
      - security-scan
```

### Docker Integration

Dockerfile for scanning in containers:

```dockerfile
FROM python:3.10-slim

WORKDIR /scan

# Install scanner
RUN pip install --no-cache-dir shai-hulud-audit-toolkit

# Copy project files
COPY package.json package-lock.json ./
COPY node_modules/ ./node_modules/

# Run scan
CMD ["shai-hulud-audit", "--skip-global", "--skip-cache", "--json"]
```

Build and run:

```bash
docker build -t project-scanner .
docker run --rm project-scanner > findings.json
```

### Pre-commit Hook

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: shai-hulud-scan
        name: Shai-Hulud Security Scan
        entry: shai-hulud-audit
        args: ['--skip-fetch', '--advisory', 'data/compromised_shaihulud.json', '--json']
        language: system
        pass_filenames: false
        stages: [commit]
```

Or create a git hook in `.git/hooks/pre-commit`:

```bash
#!/bin/bash
shai-hulud-audit --skip-fetch --advisory data/compromised_shaihulud.json
if [ $? -ne 0 ]; then
    echo "Security scan failed. Commit aborted."
    exit 1
fi
```

### Best Practices for CI/CD

1. **Caching**: Cache `data/compromised_shaihulud.json` between runs to avoid re-fetching
2. **Fail fast**: Run security scans early in the pipeline
3. **Artifacts**: Always save `findings.json` and logs for review
4. **Scheduling**: Run scheduled scans (daily/weekly) to catch new advisories
5. **Notifications**: Integrate with Slack/email for critical findings
6. **Skip options**: Use `--skip-global` and `--skip-cache` in containers where these don't apply
7. **Format choice**: Use `--format structured` for human review, `--json` for automation
