import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import scripts.scan as scanner  # noqa: E402


def _write_json(path: Path, content: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(content, indent=2), encoding="utf-8")


def test_run_reports_findings_across_sources(tmp_path, capsys):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    manifest = {
        "name": "shai-hulud-fixture",
        "version": "0.0.1",
        "dependencies": {
            "example": "1.0.0",
            "harmless": "2.0.0",
        },
    }
    _write_json(workspace / "package.json", manifest)

    package_lock = {
        "name": "shai-hulud-fixture",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "dependencies": {
                    "example": "1.0.0",
                }
            },
            "node_modules/example": {
                "name": "example",
                "version": "1.0.0",
            },
        },
    }
    _write_json(workspace / "package-lock.json", package_lock)

    module_manifest = {
        "name": "example",
        "version": "1.0.0",
    }
    _write_json(workspace / "node_modules" / "example" / "package.json", module_manifest)

    advisory = {
        "items": [
            {"package": "example", "version": "1.0.0"},
            {"package": "example", "version": "1.0.0"},
        ]
    }
    advisory_path = tmp_path / "advisory.json"
    _write_json(advisory_path, advisory)

    log_dir = tmp_path / "logs"
    exit_code = scanner.run(
        [
            "--include-node-modules",
            "--json",
            "--advisory-file",
            str(advisory_path),
            "--log-dir",
            str(log_dir),
            str(workspace),
        ]
    )

    assert exit_code == 1

    captured = capsys.readouterr()
    findings = json.loads(captured.out)
    assert len(findings) == 3
    assert {finding["package"] for finding in findings} == {"example"}
    assert all(finding["package"] != "harmless" for finding in findings)

    sources = {finding["source"] for finding in findings}
    assert str(workspace / "package.json") in sources
    assert str(workspace / "package-lock.json") in sources
    assert str(workspace / "node_modules" / "example" / "package.json") in sources

    evidence = {finding["evidence"] for finding in findings}
    assert any("dependencies -> example" in item for item in evidence)
    assert any("packages entry: node_modules/example" in item for item in evidence)
    assert "installed module package.json" in evidence

    log_files = list(log_dir.rglob("*.log"))
    assert log_files
    log_contents = log_files[0].read_text(encoding="utf-8")
    assert "Findings recorded" in log_contents
    assert "Aggregate summary" in captured.err
    assert "Summary for" in captured.err

    plain_log_dir = tmp_path / "logs_plain"
    exit_code_plain = scanner.run(
        [
            "--include-node-modules",
            "--advisory-file",
            str(advisory_path),
            "--log-dir",
            str(plain_log_dir),
            str(workspace),
        ]
    )

    assert exit_code_plain == 1

    plain_capture = capsys.readouterr()
    assert plain_capture.out.strip() == ""
    assert "Detected compromised dependencies" in plain_capture.err
    assert "- example@1.0.0 (package.json)" in plain_capture.err
    assert "- example@1.0.0 (package-lock.json)" in plain_capture.err
    assert "- example@1.0.0 (node_modules/example/package.json)" in plain_capture.err
    assert "Findings recorded" in plain_capture.err
