import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import scripts.audit as runner  # noqa: E402


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
    result = runner.run(["--skip-fetch", "--skip-scan"])
    assert result == 2


def test_skip_fetch_still_runs_scan(monkeypatch, tmp_path):
    home = tmp_path / "home"
    _setup_home(monkeypatch, home)

    advisory = tmp_path / "data" / "advisory.json"
    advisory.parent.mkdir(parents=True)
    advisory.write_text(json.dumps({"items": []}))

    called = {}

    def fake_scan(argv):
        called["scan"] = argv
        return 0

    monkeypatch.setattr("scripts.scan.run", fake_scan)

    result = runner.run([
        "--skip-fetch",
        "--advisory",
        str(advisory),
        "--skip-node-modules",
        "--skip-global",
    ])

    assert result == 0
    assert "scan" in called


def test_fetch_only_with_skip_scan(monkeypatch, tmp_path):
    home = tmp_path / "home"
    _setup_home(monkeypatch, home)

    output = tmp_path / "data" / "advisory.json"

    def fake_fetch_sources(**kwargs):
        kwargs["output_path"].parent.mkdir(parents=True, exist_ok=True)
        kwargs["output_path"].write_text(json.dumps({"items": []}))
        return DummyFetchResult(kwargs["output_path"])

    monkeypatch.setattr(runner, "fetch_sources", fake_fetch_sources)

    result = runner.run(["--skip-scan", "--advisory", str(output)])
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
            )
        )
        return DummyFetchResult(kwargs["output_path"])

    scan_calls = {}

    def fake_scan(argv):
        scan_calls["argv"] = argv
        return 0

    monkeypatch.setattr(runner, "fetch_sources", fake_fetch_sources)
    monkeypatch.setattr("scripts.scan.run", fake_scan)

    result = runner.run(["--skip-node-modules", "--skip-global", "--advisory", str(output)])
    assert result == 0
    assert "argv" in scan_calls
