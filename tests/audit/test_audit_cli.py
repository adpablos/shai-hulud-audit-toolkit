import json
from pathlib import Path

import scripts.audit as audit


class DummyFetchResult(dict):
    def __init__(self, output_path: Path):
        super().__init__(
            output_path=output_path,
            log_path=output_path,
            counts={"items": 1, "packages": 1},
        )


def _setup_home(monkeypatch, home: Path) -> None:
    home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(home))


def test_skip_both_fetch_and_scan_is_rejected(tmp_path, monkeypatch):
    _setup_home(monkeypatch, tmp_path / "home")
    result = audit.run(["--skip-fetch", "--skip-scan"])
    assert result == 2


def test_skip_fetch_still_runs_scan(monkeypatch, tmp_path):
    home = tmp_path / "home"
    _setup_home(monkeypatch, home)

    advisory = tmp_path / "data" / "advisory.json"
    advisory.parent.mkdir(parents=True)
    advisory.write_text(json.dumps({"items": []}), encoding="utf-8")

    called = {}

    def fake_scan(argv):
        called["scan"] = argv
        return 0

    monkeypatch.setattr("scripts.scan.run", fake_scan)

    result = audit.run(
        [
            "--skip-fetch",
            "--advisory",
            str(advisory),
            "--skip-node-modules",
            "--skip-global",
        ]
    )

    assert result == 0
    assert "scan" in called


def test_fetch_only_with_skip_scan(monkeypatch, tmp_path):
    home = tmp_path / "home"
    _setup_home(monkeypatch, home)

    output = tmp_path / "data" / "advisory.json"

    def fake_fetch_sources(**kwargs):
        kwargs["output_path"].parent.mkdir(parents=True, exist_ok=True)
        kwargs["output_path"].write_text(json.dumps({"items": []}), encoding="utf-8")
        return DummyFetchResult(kwargs["output_path"])

    monkeypatch.setattr(audit, "fetch_sources", fake_fetch_sources)

    result = audit.run(["--skip-scan", "--advisory", str(output)])
    assert result == 0


def test_full_run_invokes_fetch_and_scan(monkeypatch, tmp_path):
    home = tmp_path / "home"
    _setup_home(monkeypatch, home)

    output = tmp_path / "data" / "advisory.json"

    def fake_fetch_sources(**kwargs):
        kwargs["output_path"].parent.mkdir(parents=True, exist_ok=True)
        kwargs["output_path"].write_text(
            json.dumps(
                {
                    "items": [
                        {
                            "package": "example",
                            "version": "1.0.0",
                            "source_links": ["https://example.com"],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        return DummyFetchResult(kwargs["output_path"])

    scan_calls = {}

    def fake_scan(argv):
        scan_calls["argv"] = argv
        return 0

    monkeypatch.setattr(audit, "fetch_sources", fake_fetch_sources)
    monkeypatch.setattr("scripts.scan.run", fake_scan)

    result = audit.run(["--skip-node-modules", "--skip-global", "--advisory", str(output)])
    assert result == 0
    assert "argv" in scan_calls
