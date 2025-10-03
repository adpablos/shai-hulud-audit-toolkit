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
