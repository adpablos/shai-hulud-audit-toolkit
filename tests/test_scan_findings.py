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
