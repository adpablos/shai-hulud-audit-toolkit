"""Main scanner orchestrator for collecting findings from various sources."""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Iterator, List, Optional, Set, Tuple

from scripts.scan_core.config import IOC_FILE_PATTERNS, JS_FILE_EXTENSIONS
from scripts.scan_core.models import Finding, ScanStats
from scripts.scan_core.scanners.iocs import scan_file_for_iocs, detect_workflow_iocs
from scripts.scan_core.scanners.lockfiles import LOCKFILE_HANDLERS
from scripts.scan_core.scanners.node_modules import scan_installed_package
from scripts.scan_core.scanners.package_json import scan_package_json
from scripts.scan_core.scanners.patterns import scan_file_for_patterns, is_minified
from scripts.scan_core.scanners.exfiltration import scan_for_exfiltration

LOGGER = logging.getLogger("shai-hulud")


def safe_walk(root: Path, include_node_modules: bool) -> Iterator[Tuple[Path, List[str], List[str]]]:
    """Safely walk directory tree with error handling."""
    def onerror(exc: OSError) -> None:
        LOGGER.warning("Unable to access directory %s: %s", exc.filename or root, exc)

    try:
        for dirpath, dirnames, filenames in os.walk(
            root,
            topdown=True,
            onerror=onerror,
            followlinks=False,
        ):
            if not include_node_modules:
                dirnames[:] = [d for d in dirnames if d != "node_modules"]
            yield Path(dirpath), dirnames, filenames
    except (OSError, InterruptedError) as exc:  # noqa: PERF203 - want explicit handling
        LOGGER.warning("Traversal aborted in %s: %s", root, exc)


def collect_targets(paths: List[str]) -> List[Path]:
    """Collect and validate scan target paths."""
    resolved: List[Path] = []
    for raw in paths:
        path = Path(raw).expanduser().resolve()
        if not path.exists():
            LOGGER.warning("Path %s does not exist; skipping.", path)
            continue
        resolved.append(path)
    return resolved


def gather_findings(
    root: Path,
    include_node_modules: bool,
    check_hashes: bool = True,
    detect_iocs: bool = True,
    detect_patterns: bool = False,
    pattern_categories: Optional[Set[str]] = None,
    pattern_min_severity: str = "low",
    detect_exfiltration: bool = False,
    exfiltration_allowlist: Optional[Set[str]] = None,
    warn_namespaces: bool = True,
) -> Tuple[List[Finding], ScanStats]:
    """Gather all findings from a directory tree."""
    findings: List[Finding] = []
    stats = ScanStats()

    # Check for workflow IOCs at the root level
    if detect_iocs:
        findings.extend(detect_workflow_iocs(root))

    for current_dir, _dirnames, filenames in safe_walk(root, include_node_modules=include_node_modules):
        in_node_modules = "node_modules" in current_dir.parts

        for filename in filenames:
            file_path = current_dir / filename

            # Check for IOC hashes in suspicious files
            if check_hashes and any(pattern in filename.lower() for pattern in IOC_FILE_PATTERNS):
                ioc_finding = scan_file_for_iocs(file_path)
                if ioc_finding:
                    findings.append(ioc_finding)

            # Check for suspicious code patterns in JavaScript files
            if detect_patterns and file_path.suffix in JS_FILE_EXTENSIONS:
                pattern_findings = scan_file_for_patterns(file_path, pattern_categories, pattern_min_severity)
                findings.extend(pattern_findings)

            # Check for data exfiltration patterns in JavaScript files
            if detect_exfiltration and file_path.suffix in JS_FILE_EXTENSIONS:
                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                    if not is_minified(content):
                        exfil_findings = scan_for_exfiltration(file_path, content, exfiltration_allowlist)
                        findings.extend(exfil_findings)
                except (OSError, InterruptedError) as exc:  # noqa: PERF203
                    LOGGER.debug("Unable to read file for exfiltration scan %s: %s", file_path, exc)

            if filename == "package.json":
                if in_node_modules:
                    if include_node_modules:
                        stats.node_module_manifests += 1
                        findings.extend(scan_installed_package(file_path, warn_namespaces=warn_namespaces))
                else:
                    stats.manifests += 1
                    findings.extend(scan_package_json(file_path, detect_iocs=detect_iocs, warn_namespaces=warn_namespaces))
            elif filename in LOCKFILE_HANDLERS and not in_node_modules:
                stats.lockfiles[filename] += 1
                findings.extend(LOCKFILE_HANDLERS[filename](file_path, warn_namespaces=warn_namespaces))

    return findings, stats
