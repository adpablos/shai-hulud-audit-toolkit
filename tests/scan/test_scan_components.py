import hashlib
import json
from collections import Counter
from pathlib import Path

import pytest

import scripts.scan as scanner


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _cache_entry(url: str) -> dict:
    return {
        "metadata": {
            "url": url,
        }
    }


def test_load_advisory_index_handles_varied_schemas(tmp_path: Path) -> None:
    path = tmp_path / "advisory_items.json"
    _write_json(
        path,
        {
            "items": [
                {"package": "alpha", "version": "v1.2.3"},
                {"package": "alpha", "version": "=1.2.3"},
            ]
        },
    )
    mapping_items = scanner.load_advisory_index(path)
    assert mapping_items == {"alpha": {"1.2.3"}}

    path_map = tmp_path / "advisory_map.json"
    _write_json(path_map, {"beta": ["1.0.0", "1.0.0"]})
    mapping_map = scanner.load_advisory_index(path_map)
    assert mapping_map == {"beta": {"1.0.0"}}

    path_list = tmp_path / "advisory_list.json"
    _write_json(path_list, [{"package": "gamma", "version": "1.5.0;"}])
    mapping_list = scanner.load_advisory_index(path_list)
    assert mapping_list == {"gamma": {"1.5.0"}}

    empty_path = tmp_path / "empty.json"
    _write_json(empty_path, {"items": []})
    with pytest.raises(ValueError):
        scanner.load_advisory_index(empty_path)


def test_scan_yarn_and_pnpm_lock_detect_versions(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(scanner, "COMPROMISED_PACKAGES", {"example": {"2.3.4", "1.2.3"}})

    yarn_lock = tmp_path / "yarn.lock"
    _write(
        yarn_lock,
        'example@^2.3.4:\n  version "2.3.4"\n  resolved "https://example"\n',
    )
    yarn_findings = scanner.scan_yarn_lock(yarn_lock)
    assert [(f.package, f.version, f.evidence) for f in yarn_findings] == [
        ("example", "2.3.4", "lock entry for example")
    ]

    pnpm_lock = tmp_path / "pnpm-lock.yaml"
    _write(
        pnpm_lock,
        "lockfileVersion: '6.0'\npackages:\n  /example/1.2.3:\n    resolution: {integrity: sha512}\n",
    )
    pnpm_findings = scanner.scan_pnpm_lock(pnpm_lock)
    assert [(f.package, f.version) for f in pnpm_findings] == [("example", "1.2.3")]


def test_gather_findings_respects_node_module_toggle(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(scanner, "COMPROMISED_PACKAGES", {"example": {"1.0.0"}})

    workspace = tmp_path / "workspace"
    workspace.mkdir()

    _write_json(
        workspace / "package.json",
        {"name": "fixture", "dependencies": {"example": "1.0.0"}},
    )
    _write_json(
        workspace / "node_modules" / "example" / "package.json",
        {"name": "example", "version": "1.0.0"},
    )

    findings_skip, stats_skip = scanner.gather_findings(workspace, include_node_modules=False)
    assert [(f.package, f.source) for f in findings_skip] == [
        ("example", str(workspace / "package.json"))
    ]
    assert stats_skip.manifests == 1
    assert stats_skip.node_module_manifests == 0
    assert stats_skip.lockfiles == Counter()

    findings_full, stats_full = scanner.gather_findings(workspace, include_node_modules=True)
    assert {(f.package, f.source) for f in findings_full} == {
        ("example", str(workspace / "package.json")),
        ("example", str(workspace / "node_modules" / "example" / "package.json")),
    }
    assert stats_full.manifests == 1
    assert stats_full.node_module_manifests == 1
    assert stats_full.lockfiles == Counter()


def test_parse_cache_entry_handles_scoped_packages() -> None:
    entry = _cache_entry("https://registry.npmjs.org/@scope/example/-/example-1.2.3.tgz")
    package, version, url = scanner.parse_cache_entry(entry)
    assert package == "@scope/example"
    assert version == "1.2.3"
    assert url.endswith("example-1.2.3.tgz")


def test_parse_cache_entry_normalises_version() -> None:
    entry = _cache_entry("https://registry.npmjs.org/example/-/example-v0.9.0.tar.gz")
    package, version, _ = scanner.parse_cache_entry(entry)
    assert package == "example"
    assert version == "0.9.0"


def test_scan_npm_cache_deduplicates_entries(tmp_path: Path, monkeypatch) -> None:
    index_dir = tmp_path / "index-v5" / "aa" / "bb"
    index_dir.mkdir(parents=True, exist_ok=True)
    entry_path = index_dir / "entry"

    record = _cache_entry("https://registry.npmjs.org/example/-/example-1.0.0.tgz")
    duplicate = _cache_entry("https://registry.npmjs.org/example/-/example-1.0.0.tgz")
    other = _cache_entry("https://registry.npmjs.org/other/-/other-2.0.0.tgz")

    payloads = [record, duplicate, other]
    content_lines = ["", *[f"deadbeef\t{json.dumps(item)}" for item in payloads]]
    entry_path.write_text("\n".join(content_lines), encoding="utf-8")

    monkeypatch.setattr(scanner, "COMPROMISED_PACKAGES", {"example": {"1.0.0"}, "other": {"3.0.0"}})

    findings, inspected = scanner.scan_npm_cache(tmp_path / "index-v5")
    assert inspected == 2
    assert [(finding.package, finding.version) for finding in findings] == [("example", "1.0.0")]


def test_compute_file_hash() -> None:
    """Test SHA-256 hash computation."""
    from tempfile import NamedTemporaryFile
    with NamedTemporaryFile(delete=False) as tmp:
        tmp.write(b"test content")
        tmp_path = Path(tmp.name)

    try:
        file_hash = scanner.compute_file_hash(tmp_path)
        expected_hash = hashlib.sha256(b"test content").hexdigest()
        assert file_hash == expected_hash
    finally:
        tmp_path.unlink()


def test_scan_file_for_iocs_positive_match(tmp_path: Path, monkeypatch) -> None:
    """Test IOC detection with known malicious hash."""
    # Create a file with known content
    test_file = tmp_path / "bundle.js"
    test_content = b"malicious content"
    test_file.write_bytes(test_content)

    # Calculate its hash
    test_hash = hashlib.sha256(test_content).hexdigest()

    # Add it to the malicious hashes set
    monkeypatch.setattr(scanner, "MALICIOUS_HASHES", {test_hash})

    finding = scanner.scan_file_for_iocs(test_file)
    assert finding is not None
    assert finding.category == "ioc"
    assert finding.version == "bundle.js"
    assert test_hash in finding.evidence


def test_scan_file_for_iocs_negative_match(tmp_path: Path, monkeypatch) -> None:
    """Test IOC detection with benign file."""
    test_file = tmp_path / "bundle.js"
    test_file.write_bytes(b"benign content")

    # Set malicious hashes that don't match
    monkeypatch.setattr(scanner, "MALICIOUS_HASHES", {"deadbeef" * 8})

    finding = scanner.scan_file_for_iocs(test_file)
    assert finding is None


def test_gather_findings_with_hash_detection(tmp_path: Path, monkeypatch) -> None:
    """Test that gather_findings detects IOCs when enabled."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    # Create a malicious file
    malicious_file = workspace / "bundle.js"
    malicious_content = b"malicious payload"
    malicious_file.write_bytes(malicious_content)
    malicious_hash = hashlib.sha256(malicious_content).hexdigest()

    # Also create a package.json with compromised dependency
    _write_json(
        workspace / "package.json",
        {"name": "test-app", "dependencies": {"evil-pkg": "1.0.0"}}
    )

    monkeypatch.setattr(scanner, "MALICIOUS_HASHES", {malicious_hash})
    monkeypatch.setattr(scanner, "COMPROMISED_PACKAGES", {"evil-pkg": {"1.0.0"}})

    findings, stats = scanner.gather_findings(workspace, include_node_modules=False, check_hashes=True)

    # Should find both the dependency and the IOC
    assert len(findings) == 2
    dependency_findings = [f for f in findings if f.category == "dependency"]
    ioc_findings = [f for f in findings if f.category == "ioc"]

    assert len(dependency_findings) == 1
    assert dependency_findings[0].package == "evil-pkg"

    assert len(ioc_findings) == 1
    assert ioc_findings[0].version == "bundle.js"
    assert malicious_hash in ioc_findings[0].evidence


def test_gather_findings_hash_detection_disabled(tmp_path: Path, monkeypatch) -> None:
    """Test that hash detection can be disabled."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    # Create a malicious file
    malicious_file = workspace / "bundle.js"
    malicious_content = b"malicious payload"
    malicious_file.write_bytes(malicious_content)
    malicious_hash = hashlib.sha256(malicious_content).hexdigest()

    monkeypatch.setattr(scanner, "MALICIOUS_HASHES", {malicious_hash})
    monkeypatch.setattr(scanner, "COMPROMISED_PACKAGES", {})

    findings, stats = scanner.gather_findings(workspace, include_node_modules=False, check_hashes=False)

    # Should not find any IOCs when disabled
    assert len(findings) == 0
