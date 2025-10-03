#!/usr/bin/env python3
"""Shai-Hulud compromise scanner for Node.js projects.

This script inspects project manifests, lockfiles, optional node_modules trees,
and globally installed npm packages to spot any dependency/version combination
that matches the Shai-Hulud supply-chain compromise advisory.
"""
from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Sequence

from scripts.scan_core.advisory import load_advisory_index, set_compromised_index
from scripts.scan_core import config
from scripts.scan_core.config import ENV_ADVISORY_PATH
from scripts.scan_core.models import Finding, ScanStats

# Re-export mutable references for test compatibility
MALICIOUS_HASHES = config.MALICIOUS_HASHES
from scripts.scan_core.reporting.compact import print_compact_report
from scripts.scan_core.reporting.formatters import ColoredFormatter, Colors, Emojis
from scripts.scan_core.reporting.json_output import print_json_output
from scripts.scan_core.reporting.structured import print_structured_report
from scripts.scan_core.scanner import collect_targets, gather_findings
from scripts.scan_core.scanners.cache import parse_cache_entry, resolve_cache_index_dir, scan_npm_cache
from scripts.scan_core.scanners.iocs import compute_file_hash, scan_file_for_iocs
from scripts.scan_core.scanners.lockfiles import scan_pnpm_lock, scan_yarn_lock
from scripts.scan_core.scanners.node_modules import scan_global_npm
from scripts.scan_core.utils import COMPROMISED_PACKAGES, resolve_advisory_path

LOGGER = logging.getLogger("shai-hulud")

# Re-export for backward compatibility with tests
__all__ = [
    "MALICIOUS_HASHES",
    "COMPROMISED_PACKAGES",
    "Finding",
    "ScanStats",
    "gather_findings",
    "scan_yarn_lock",
    "scan_pnpm_lock",
    "parse_cache_entry",
    "scan_npm_cache",
    "compute_file_hash",
    "scan_file_for_iocs",
]


def setup_logging(log_dir: Path, level: str, use_color: bool = True) -> Path:
    """Initialise console and file logging for the current execution."""
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"shai_hulud_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    LOGGER.handlers.clear()
    LOGGER.setLevel(numeric_level)
    LOGGER.propagate = False

    # File handler without colors (for parsing)
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    LOGGER.addHandler(file_handler)

    # Console handler with optional color support
    console_handler = logging.StreamHandler()
    console_handler.setLevel(numeric_level)
    if use_color and Colors.supports_color():
        console_handler.setFormatter(ColoredFormatter("%(levelname)s: %(message)s"))
    else:
        Colors.disable()
        console_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    LOGGER.addHandler(console_handler)

    return log_path


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Scan for Shai-Hulud compromised npm packages.")
    parser.add_argument(
        "paths",
        nargs="*",
        default=["."],
        help="Project directories to scan (default: current directory).",
    )
    parser.add_argument("--json", action="store_true", dest="json_output", help="Emit findings as JSON (alias for --format json).")
    parser.add_argument(
        "--format",
        choices=["structured", "compact", "json"],
        help="Output format: structured (detailed multi-section), compact (concise logger-based), or json. Auto-detects based on TTY.",
    )
    parser.add_argument(
        "--include-node-modules",
        action="store_true",
        help="Scan installed node_modules trees for resolved versions.",
    )
    parser.add_argument(
        "--check-global",
        action="store_true",
        help="Inspect globally installed npm packages via 'npm ls -g'.",
    )
    parser.add_argument(
        "--skip-cache",
        action="store_true",
        help="Skip inspecting the npm cache index (~/.npm/_cacache/index-v5).",
    )
    parser.add_argument(
        "--npm-cache-dir",
        help="Override the npm cache directory (defaults to $NPM_CONFIG_CACHE or ~/.npm).",
    )
    parser.add_argument(
        "--advisory-file",
        help="Path to the compromised package advisory JSON. Overrides defaults and environment variable.",
    )
    parser.add_argument(
        "--hash-iocs",
        action="store_true",
        default=True,
        help="Enable hash-based IOC detection for known malicious files (default: enabled).",
    )
    parser.add_argument(
        "--no-hash-iocs",
        action="store_false",
        dest="hash_iocs",
        help="Disable hash-based IOC detection.",
    )
    parser.add_argument(
        "--detect-iocs",
        action="store_true",
        default=True,
        help="Enable script and workflow IOC detection (default: enabled).",
    )
    parser.add_argument(
        "--no-detect-iocs",
        action="store_false",
        dest="detect_iocs",
        help="Disable script and workflow IOC detection.",
    )
    parser.add_argument(
        "--warn-namespaces",
        action="store_true",
        default=True,
        help="Warn when dependencies use compromised maintainer namespaces (default: enabled).",
    )
    parser.add_argument(
        "--no-warn-namespaces",
        action="store_false",
        dest="warn_namespaces",
        help="Disable namespace compromise warnings.",
    )
    parser.add_argument(
        "--detect-patterns",
        action="store_true",
        default=False,
        help="Enable suspicious code pattern detection in JavaScript files (default: disabled).",
    )
    parser.add_argument(
        "--no-detect-patterns",
        action="store_false",
        dest="detect_patterns",
        help="Disable suspicious code pattern detection.",
    )
    parser.add_argument(
        "--pattern-severity",
        choices=["low", "medium", "high", "critical"],
        default="low",
        help="Minimum severity level for pattern detection (default: low).",
    )
    parser.add_argument(
        "--pattern-categories",
        help="Comma-separated list of pattern categories to detect (e.g., eval_usage,child_process).",
    )
    parser.add_argument(
        "--detect-exfiltration",
        action="store_true",
        default=False,
        help="Enable data exfiltration pattern detection in JavaScript files (default: disabled).",
    )
    parser.add_argument(
        "--exfiltration-allowlist",
        help="Comma-separated list of domains/IPs to exclude from exfiltration detection.",
    )
    parser.add_argument(
        "--log-dir",
        default="logs",
        help="Directory where timestamped scan logs are written (default: logs).",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Console/log verbosity (default: INFO).",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable color output in terminal (also respects NO_COLOR environment variable).",
    )
    parser.add_argument(
        "--no-emoji",
        action="store_true",
        help="Disable emoji indicators in terminal output (auto-disabled for non-TTY).",
    )
    return parser.parse_args(argv)


def setup_scan_environment(args: argparse.Namespace) -> Path:
    """Setup logging, load advisory, configure environment."""
    log_dir = Path(args.log_dir).expanduser().resolve()
    use_color = not args.no_color
    log_path = setup_logging(log_dir, args.log_level, use_color=use_color)

    # Handle emoji flag - disable if requested or if terminal doesn't support it
    if args.no_emoji or not Emojis.supports_emoji():
        Emojis.disable()

    LOGGER.info("Detailed execution log: %s", log_path)

    # Load advisory data
    advisory_path = resolve_advisory_path(args.advisory_file)
    if not advisory_path:
        LOGGER.error("Unable to locate advisory dataset. Provide --advisory-file or set %s.", ENV_ADVISORY_PATH)
        sys.exit(2)

    LOGGER.info("Loading advisory data from %s", advisory_path)
    try:
        advisory_index = load_advisory_index(advisory_path)
    except ValueError as exc:
        LOGGER.error("%s", exc)
        sys.exit(2)

    set_compromised_index(advisory_index)
    total_versions = sum(len(versions) for versions in COMPROMISED_PACKAGES.values())
    LOGGER.info("Indexed %s packages covering %s compromised versions.", len(COMPROMISED_PACKAGES), total_versions)

    return log_path


def execute_scan(args: argparse.Namespace, targets: List[Path]) -> tuple[List[Finding], ScanStats]:
    """Execute all scan operations and collect findings."""
    # Parse pattern categories if provided
    pattern_categories = None
    if args.pattern_categories:
        pattern_categories = set(cat.strip() for cat in args.pattern_categories.split(","))

    # Parse exfiltration allowlist if provided
    exfiltration_allowlist = None
    if args.exfiltration_allowlist:
        exfiltration_allowlist = set(item.strip() for item in args.exfiltration_allowlist.split(","))

    all_findings: List[Finding] = []
    overall_stats = ScanStats()

    for target in targets:
        LOGGER.info("Scanning %s", target)
        findings, stats = gather_findings(
            target,
            include_node_modules=args.include_node_modules,
            check_hashes=args.hash_iocs,
            detect_iocs=args.detect_iocs,
            detect_patterns=args.detect_patterns,
            pattern_categories=pattern_categories,
            pattern_min_severity=args.pattern_severity,
            detect_exfiltration=args.detect_exfiltration,
            exfiltration_allowlist=exfiltration_allowlist,
            warn_namespaces=args.warn_namespaces,
        )
        all_findings.extend(findings)
        overall_stats.merge(stats)
        LOGGER.info(
            "Summary for %s: %s manifests (%s within node_modules); lockfiles: %s.",
            target,
            stats.manifests,
            stats.node_module_manifests,
            stats.describe_lockfiles(),
        )

    if args.check_global:
        LOGGER.info("Scanning globally installed npm packages")
        global_findings, inspected = scan_global_npm()
        all_findings.extend(global_findings)
        LOGGER.info("Global npm scan inspected %s packages and flagged %s findings.", inspected, len(global_findings))

    cache_override = args.npm_cache_dir
    check_cache = not args.skip_cache or bool(cache_override)
    if args.skip_cache and cache_override:
        LOGGER.info("Cache scan disabled (--skip-cache); ignoring --npm-cache-dir value %s.", cache_override)
        check_cache = False

    if check_cache:
        cache_index_dir = resolve_cache_index_dir(cache_override)
        LOGGER.info("Scanning npm cache index at %s", cache_index_dir)
        cache_findings, inspected_cache = scan_npm_cache(cache_index_dir)
        all_findings.extend(cache_findings)
        LOGGER.info("Cache scan inspected %s cached artifacts and flagged %s findings.", inspected_cache, len(cache_findings))

    LOGGER.info(
        "Aggregate summary: %s manifests scanned (%s within node_modules); lockfiles: %s.",
        overall_stats.manifests,
        overall_stats.node_module_manifests,
        overall_stats.describe_lockfiles(),
    )

    return all_findings, overall_stats


def generate_output(args: argparse.Namespace, findings: List[Finding], stats: ScanStats, targets: List[Path]) -> None:
    """Generate output in requested format."""
    # Determine output format
    output_format = args.format
    if args.json_output:
        output_format = "json"
    elif output_format is None:
        # Auto-detect: structured for TTY, compact for pipes
        output_format = "structured" if sys.stdout.isatty() else "compact"

    # Generate output in selected format
    if output_format == "json":
        print_json_output(findings)
    elif output_format == "structured":
        root = targets[0] if len(targets) == 1 else None
        print_structured_report(findings, stats, targets, root=root)
    else:  # compact
        root = targets[0] if len(targets) == 1 else None
        print_compact_report(findings, root=root)


def run(argv: Optional[Sequence[str]] = None) -> int:
    """Main entry point for the scanner."""
    args = parse_args(argv)
    log_path = setup_scan_environment(args)

    targets = collect_targets(args.paths)
    if not targets:
        LOGGER.error("No valid targets to scan.")
        return 2

    all_findings, overall_stats = execute_scan(args, targets)
    generate_output(args, all_findings, overall_stats, targets)

    if all_findings:
        LOGGER.warning("Findings recorded in %s", log_path)
        return 1

    LOGGER.info("Scan completed successfully. Log retained at %s", log_path)
    return 0


if __name__ == "__main__":
    sys.exit(run())
