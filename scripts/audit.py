#!/usr/bin/env python3
"""Fetch the latest Shai-Hulud advisory and scan local sources in one run."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import List, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts import scan
from scripts.fetch import CONFIG_DEFAULT_PATH, fetch_sources

DEFAULT_PATHS = [str(Path(os.environ.get("HOME", ".")).resolve())]


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fetch the latest Shai-Hulud advisory and scan specified paths."
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=list(DEFAULT_PATHS),
        help=f"Filesystem paths to scan (default: {DEFAULT_PATHS[0]}).",
    )
    parser.add_argument(
        "--config",
        default=str(CONFIG_DEFAULT_PATH),
        help="Path to the sources configuration file (default: config/shai_hulud_sources.json).",
    )
    parser.add_argument(
        "--advisory",
        default="data/compromised_shaihulud.json",
        help=(
            "Path to the advisory JSON. The file is overwritten unless you use "
            "--skip-fetch (default: data/compromised_shaihulud.json)."
        ),
    )
    parser.add_argument(
        "--log-dir",
        default="logs",
        help="Base directory for logs (default: logs).",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Log verbosity for both fetch and scan phases (default: INFO).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="HTTP timeout for fetching sources in seconds (default: 30).",
    )
    parser.add_argument(
        "--skip-fetch",
        action="store_true",
        help="Skip fetching and use the advisory JSON at --advisory as-is.",
    )
    parser.add_argument(
        "--skip-scan",
        action="store_true",
        help="Fetch advisories but do not run the scanner.",
    )
    parser.add_argument(
        "--skip-node-modules",
        action="store_true",
        help="Skip scanning node_modules trees (default: scan them).",
    )
    parser.add_argument(
        "--skip-global",
        action="store_true",
        help="Skip inspecting globally installed npm packages (default: inspect them).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit scan findings as JSON (stdout).",
    )
    return parser.parse_args(argv)


def run(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    source_config_path = Path(args.config).expanduser().resolve()
    output_path = Path(args.advisory).expanduser().resolve()
    base_log_dir = Path(args.log_dir).expanduser().resolve()
    log_level = args.log_level.upper()
    timeout = args.timeout

    paths: List[str] = [str(Path(p).expanduser().resolve()) for p in (args.paths or DEFAULT_PATHS)]
    include_node_modules = not args.skip_node_modules
    check_global = not args.skip_global
    emit_json = args.json

    if args.skip_fetch and args.skip_scan:
        print("[error] Nothing to do: both fetch and scan stages are disabled.")
        return 2

    fetch_log_dir = (base_log_dir / "fetch").resolve()
    scan_log_dir = (base_log_dir / "scan").resolve()

    if args.skip_fetch:
        print(f"[fetch] Skipping fetch. Using advisory at {output_path}")
        if not output_path.is_file():
            print(f"[error] Advisory file not found: {output_path}")
            return 2
        fetch_summary = {
            "output_path": output_path,
            "log_path": None,
            "counts": {"items": "unchanged", "packages": "unchanged"},
        }
    else:
        fetch_summary = fetch_sources(
            config_path=source_config_path,
            output_path=output_path,
            timeout=timeout,
            log_dir=fetch_log_dir,
            log_level=log_level,
        )

        print(
            f"[fetch] Consolidated {fetch_summary['counts']['items']} items across "
            f"{fetch_summary['counts']['packages']} packages. Log: {fetch_summary['log_path']}"
        )

        if fetch_summary["counts"]["items"] == 0:
            print("[fetch] No packages were extracted; skipping scan.")
            return 2

    if args.skip_scan:
        print("[scan] Skipped at user's request.")
        return 0

    scan_args: List[str] = list(paths if paths else DEFAULT_PATHS)
    if include_node_modules:
        scan_args.append("--include-node-modules")
    if check_global:
        scan_args.append("--check-global")
    if emit_json:
        scan_args.append("--json")

    scan_args.extend(["--advisory-file", str(fetch_summary["output_path"])])
    scan_args.extend(["--log-dir", str(scan_log_dir)])
    scan_args.extend(["--log-level", log_level])

    scan_exit = scan.run(scan_args)

    status = "clean" if scan_exit == 0 else "issues detected"
    print(f"[scan] Completed with status '{status}'. Review logs in {scan_log_dir} for details.")

    return scan_exit


if __name__ == "__main__":
    sys.exit(run())
