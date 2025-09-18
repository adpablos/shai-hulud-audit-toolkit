import json
from pathlib import Path

import pytest

import scripts.fetch as fetch


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_fetch_sources_writes_consolidated_payload(monkeypatch, tmp_path):
    config_path = tmp_path / "sources.json"
    _write_json(
        config_path,
        {
            "sources": [
                "https://auto.example.com/page",
                {"url": "https://wiz.example.com/list", "parser": "wiz_list"},
            ]
        },
    )

    output_path = tmp_path / "data" / "advisory.json"
    log_dir = tmp_path / "logs"

    def fake_setup_logging(target_log_dir: Path, level: str) -> Path:
        target_log_dir.mkdir(parents=True, exist_ok=True)
        log_file = target_log_dir / "fetch.log"
        log_file.write_text("stub log", encoding="utf-8")
        return log_file

    def fake_fetch_url(url: str, timeout: int):
        responses = {
            "https://auto.example.com/page": ("package-one@1.0.0", "200 OK", "2025-01-01T00:00:00Z"),
            "https://wiz.example.com/list": (
                '<ul><li><p class="my-0">package-two 2.0.0</p></li></ul>',
                "200 OK",
                "2025-01-01T00:00:01Z",
            ),
        }
        return responses[url]

    monkeypatch.setattr(fetch, "setup_logging", fake_setup_logging)
    monkeypatch.setattr(fetch, "fetch_url", fake_fetch_url)

    summary = fetch.fetch_sources(
        config_path=config_path,
        output_path=output_path,
        timeout=5,
        log_dir=log_dir,
        log_level="INFO",
    )

    payload = json.loads(output_path.read_text(encoding="utf-8"))

    assert summary["counts"] == {"items": 2, "packages": 2}
    assert payload["counts"] == {"items": 2, "packages": 2}

    items = {(item["package"], item["version"]) for item in payload["items"]}
    assert items == {("package-one", "1.0.0"), ("package-two", "2.0.0")}

    sources_meta = {entry["url"]: entry for entry in payload["sources"]}
    assert sources_meta["https://auto.example.com/page"]["parser"] == "auto"
    assert sources_meta["https://wiz.example.com/list"]["parser"] == "wiz_list"
    for entry in payload["items"]:
        if entry["package"] == "package-one":
            assert entry["source_links"] == ["https://auto.example.com/page"]
        if entry["package"] == "package-two":
            assert entry["source_links"] == ["https://wiz.example.com/list"]


def test_run_show_parsers_lists_supported_hints(capsys):
    exit_code = fetch.run(["--show-parsers"])
    assert exit_code == 0
    output = capsys.readouterr().out.splitlines()
    assert output[0] == "Supported parser hints:"
    for hint in fetch.SUPPORTED_PARSER_HINTS:
        assert f"- {hint}" in output


def test_load_sources_config_validates_entries(tmp_path):
    config_path = tmp_path / "sources.json"
    _write_json(
        config_path,
        {
            "sources": [
                {"url": "https://ok.example", "parser": "stepsecurity_table"},
                {"url": "https://bad.example", "parser": "unknown"},
            ]
        },
    )

    with pytest.raises(ValueError, match="Unsupported parser hint"):
        fetch.load_sources_config(config_path)


def test_fetch_sources_handles_failures(monkeypatch, tmp_path):
    config_path = tmp_path / "sources.json"
    _write_json(
        config_path,
        {
            "sources": [
                "https://ok.example.com",
                "https://fail.example.com",
            ]
        },
    )

    output_path = tmp_path / "out.json"
    log_dir = tmp_path / "logs"

    def fake_setup_logging(target_log_dir: Path, level: str) -> Path:
        target_log_dir.mkdir(parents=True, exist_ok=True)
        log_file = target_log_dir / "fetch.log"
        log_file.write_text("stub log", encoding="utf-8")
        return log_file

    def fake_fetch_url(url: str, timeout: int):
        if url == "https://ok.example.com":
            return ("package-three@3.0.0", "200 OK", "2025-01-01T00:00:02Z")
        return (None, "HTTPError:500", "2025-01-01T00:00:03Z")

    monkeypatch.setattr(fetch, "setup_logging", fake_setup_logging)
    monkeypatch.setattr(fetch, "fetch_url", fake_fetch_url)

    summary = fetch.fetch_sources(
        config_path=config_path,
        output_path=output_path,
        timeout=5,
        log_dir=log_dir,
        log_level="INFO",
    )

    assert summary["counts"] == {"items": 1, "packages": 1}
    status_mapping = {entry["url"]: entry for entry in summary["sources"]}
    assert status_mapping["https://ok.example.com"]["status"] == "200 OK"
    assert status_mapping["https://fail.example.com"]["status"].startswith("HTTPError")

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["counts"] == {"items": 1, "packages": 1}
    assert payload["items"][0]["package"] == "package-three"
