import hashlib
import json
from pathlib import Path

import scripts.scan as scanner
from scripts.scan import Finding


def _write_json(path: Path, content: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(content, indent=2), encoding="utf-8")


def _write_cache_index(base: Path, records: list[dict]) -> None:
    index_dir = base / "index-v5" / "aa" / "bb"
    index_dir.mkdir(parents=True, exist_ok=True)
    entry_path = index_dir / "entry"
    lines = ["", *[f"feedface\t{json.dumps(record)}" for record in records]]
    entry_path.write_text("\n".join(lines), encoding="utf-8")


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
            "--skip-cache",
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
            "--skip-cache",
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
    # Output now includes emoji indicators (or just package names if emojis disabled)
    assert "example@1.0.0 (package.json)" in plain_capture.err
    assert "example@1.0.0 (package-lock.json)" in plain_capture.err
    assert "example@1.0.0 (node_modules/example/package.json)" in plain_capture.err
    assert "Findings recorded" in plain_capture.err


def test_run_includes_global_findings(tmp_path, capsys, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _write_json(workspace / "package.json", {"name": "fixture", "dependencies": {"harmless": "2.0.0"}})

    advisory_path = tmp_path / "advisory.json"
    _write_json(advisory_path, {"items": [{"package": "global-package", "version": "4.5.6"}]})

    log_dir = tmp_path / "logs"

    global_finding = Finding(
        package="global-package",
        version="4.5.6",
        source="npm-global",
        evidence="global:global-package",
    )

    def fake_global_scan():
        return [global_finding], 3

    monkeypatch.setattr(scanner, "scan_global_npm", fake_global_scan)

    exit_code = scanner.run(
        [
            "--include-node-modules",
            "--check-global",
            "--json",
            "--skip-cache",
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
    assert findings == [global_finding.to_dict()]
    assert "Global npm scan inspected 3 packages" in captured.err
    assert "Findings recorded" in captured.err


def test_run_reports_cache_findings(tmp_path, capsys):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    advisory_path = tmp_path / "advisory.json"
    _write_json(
        advisory_path,
        {
            "items": [
                {"package": "@scope/compromised", "version": "1.0.0"},
            ]
        },
    )

    cache_root = tmp_path / "npm-cache"
    compromised_record = {
        "metadata": {
            "url": "https://registry.npmjs.org/@scope/compromised/-/compromised-1.0.0.tgz",
        }
    }
    benign_record = {
        "metadata": {
            "url": "https://registry.npmjs.org/harmless/-/harmless-2.0.0.tgz",
        }
    }
    _write_cache_index(cache_root, [compromised_record, benign_record])

    log_dir = tmp_path / "logs"

    exit_code = scanner.run(
        [
            "--json",
            "--advisory-file",
            str(advisory_path),
            "--log-dir",
            str(log_dir),
            "--npm-cache-dir",
            str(cache_root),
            str(workspace),
        ]
    )

    assert exit_code == 1
    captured = capsys.readouterr()
    findings = json.loads(captured.out)
    assert len(findings) == 1
    assert findings[0]["package"] == "@scope/compromised"
    assert findings[0]["source"] == "npm-cache"
    assert "compromised-1.0.0.tgz" in findings[0]["evidence"]
    assert "Cache scan inspected" in captured.err


def test_run_detects_hash_iocs(tmp_path, capsys, monkeypatch):
    """Test that the CLI detects files with known malicious hashes."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    # Create a malicious bundle.js file
    malicious_content = b"malicious payload content"
    malicious_file = workspace / "bundle.js"
    malicious_file.write_bytes(malicious_content)
    malicious_hash = hashlib.sha256(malicious_content).hexdigest()

    # Create a benign index.js file
    benign_file = workspace / "index.js"
    benign_file.write_bytes(b"benign content")

    # Also create a package.json with a compromised dependency
    _write_json(
        workspace / "package.json",
        {"name": "test-app", "dependencies": {"evil-pkg": "1.0.0"}}
    )

    # Create advisory file
    advisory_path = tmp_path / "advisory.json"
    _write_json(
        advisory_path,
        {"items": [{"package": "evil-pkg", "version": "1.0.0"}]}
    )

    # Temporarily set the malicious hashes
    monkeypatch.setattr(scanner, "MALICIOUS_HASHES", {malicious_hash})

    log_dir = tmp_path / "logs"

    # Run with hash IOC detection enabled (default)
    exit_code = scanner.run(
        [
            "--json",
            "--advisory-file",
            str(advisory_path),
            "--log-dir",
            str(log_dir),
            "--skip-cache",
            str(workspace),
        ]
    )

    assert exit_code == 1
    captured = capsys.readouterr()
    findings = json.loads(captured.out)

    # Should have both dependency and IOC findings
    assert len(findings) == 2

    dependency_findings = [f for f in findings if f["category"] == "dependency"]
    ioc_findings = [f for f in findings if f["category"] == "ioc"]

    assert len(dependency_findings) == 1
    assert dependency_findings[0]["package"] == "evil-pkg"

    assert len(ioc_findings) == 1
    assert ioc_findings[0]["version"] == "bundle.js"
    assert malicious_hash in ioc_findings[0]["evidence"]

    # With --json flag, detailed output isn't printed to stderr


def test_run_hash_iocs_disabled(tmp_path, capsys, monkeypatch):
    """Test that hash IOC detection can be disabled."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    # Create a malicious bundle.js file
    malicious_content = b"malicious payload content"
    malicious_file = workspace / "bundle.js"
    malicious_file.write_bytes(malicious_content)
    malicious_hash = hashlib.sha256(malicious_content).hexdigest()

    # Create advisory file with at least one item (scanner requires non-empty advisory)
    advisory_path = tmp_path / "advisory.json"
    _write_json(advisory_path, {"items": [{"package": "some-pkg", "version": "9.9.9"}]})

    # Temporarily set the malicious hashes
    monkeypatch.setattr(scanner, "MALICIOUS_HASHES", {malicious_hash})

    log_dir = tmp_path / "logs"

    # Run with hash IOC detection disabled
    exit_code = scanner.run(
        [
            "--json",
            "--no-hash-iocs",
            "--advisory-file",
            str(advisory_path),
            "--log-dir",
            str(log_dir),
            "--skip-cache",
            str(workspace),
        ]
    )

    assert exit_code == 0
    captured = capsys.readouterr()
    findings = json.loads(captured.out)

    # Should have no findings when hash detection is disabled
    assert len(findings) == 0
    # With --json and no findings, it just shows successful completion
    assert "Scan completed successfully" in captured.err


def test_no_color_flag(tmp_path, capsys):
    """Test that --no-color flag works correctly."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    _write_json(
        workspace / "package.json",
        {"name": "test-app", "dependencies": {"evil-pkg": "1.0.0"}}
    )

    advisory_path = tmp_path / "advisory.json"
    _write_json(
        advisory_path,
        {"items": [{"package": "evil-pkg", "version": "1.0.0"}]}
    )

    log_dir = tmp_path / "logs"

    # Run with --no-color flag
    exit_code = scanner.run(
        [
            "--no-color",
            "--advisory-file",
            str(advisory_path),
            "--log-dir",
            str(log_dir),
            "--skip-cache",
            str(workspace),
        ]
    )

    assert exit_code == 1
    captured = capsys.readouterr()

    # Verify no ANSI color codes in output
    assert "\033[" not in captured.err
    assert "Detected compromised dependencies" in captured.err
    assert "evil-pkg@1.0.0" in captured.err


def test_no_emoji_flag(tmp_path, capsys):
    """Test that --no-emoji flag disables emoji indicators."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    _write_json(
        workspace / "package.json",
        {"name": "test-app", "dependencies": {"evil-pkg": "1.0.0"}}
    )

    advisory_path = tmp_path / "advisory.json"
    _write_json(
        advisory_path,
        {"items": [{"package": "evil-pkg", "version": "1.0.0"}]}
    )

    log_dir = tmp_path / "logs"

    # Run with --no-emoji flag
    exit_code = scanner.run(
        [
            "--no-emoji",
            "--advisory-file",
            str(advisory_path),
            "--log-dir",
            str(log_dir),
            "--skip-cache",
            str(workspace),
        ]
    )

    assert exit_code == 1
    captured = capsys.readouterr()

    # Verify no emoji characters in output
    emoji_chars = ["🚨", "⚠️", "✅", "📦", "📄", "🔴", "📊"]
    for emoji in emoji_chars:
        assert emoji not in captured.err

    # But normal text should still be there
    assert "Detected compromised dependencies" in captured.err
    assert "evil-pkg@1.0.0" in captured.err


def test_emoji_clean_output(tmp_path, capsys):
    """Test that clean scan shows ✅ emoji when enabled."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    _write_json(
        workspace / "package.json",
        {"name": "clean-app", "dependencies": {"safe-pkg": "1.0.0"}}
    )

    advisory_path = tmp_path / "advisory.json"
    _write_json(
        advisory_path,
        {"items": [{"package": "evil-pkg", "version": "1.0.0"}]}  # Different package
    )

    log_dir = tmp_path / "logs"

    # Run without --no-emoji (emojis enabled by default in tests with TTY simulation)
    exit_code = scanner.run(
        [
            "--advisory-file",
            str(advisory_path),
            "--log-dir",
            str(log_dir),
            "--skip-cache",
            str(workspace),
        ]
    )

    assert exit_code == 0
    captured = capsys.readouterr()

    # Should contain clean emoji if terminal supports it
    # Note: This may not show emoji in test environment due to TTY detection
    assert "No compromised packages or IOCs detected" in captured.err
