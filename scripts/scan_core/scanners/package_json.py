"""Package.json scanner with script IOC detection."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, Iterator, List, Set, Tuple

from scripts.scan_core.config import SCRIPT_IOC_PATTERNS
from scripts.scan_core.models import Finding
from scripts.scan_core.utils import load_json, check_version_match, create_namespace_warning


def iter_dependency_specs(block: object) -> Iterator[Tuple[str, str]]:
    """Recursively extract (package, version) pairs from dependency blocks."""
    if isinstance(block, dict):
        for key, value in block.items():
            if isinstance(value, str):
                yield key, value
            elif isinstance(value, dict):
                nested_version = value.get("version") if "version" in value else None
                if isinstance(nested_version, str):
                    yield key, nested_version
                yield from iter_dependency_specs(value)
            elif isinstance(value, list):
                for item in value:
                    yield from iter_dependency_specs({key: item})
    elif isinstance(block, list):
        for item in block:
            yield from iter_dependency_specs(item)


def detect_script_iocs(scripts: Dict[str, str], package_json_path: Path) -> List[Finding]:
    """Detect suspicious IOC patterns in package.json scripts."""
    findings: List[Finding] = []
    for script_name, script_content in scripts.items():
        for pattern in SCRIPT_IOC_PATTERNS:
            if re.search(pattern, script_content, re.IGNORECASE):
                findings.append(
                    Finding(
                        package="script_ioc",
                        version=script_name,
                        source=str(package_json_path),
                        evidence=f"Suspicious pattern in script '{script_name}': {script_content[:100]}",
                        category="script_ioc",
                        severity="high",
                    )
                )
                break  # Only report once per script
    return findings


def scan_package_json(
    path: Path,
    detect_iocs: bool = True,
    warn_namespaces: bool = True,
) -> List[Finding]:
    """Scan package.json for compromised dependencies and IOCs."""
    data = load_json(path)
    if data is None:
        return []

    findings: List[Finding] = []
    namespace_warnings_seen: Set[str] = set()

    sections = [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
        "bundleDependencies",
        "bundledDependencies",
        "resolutions",
        "overrides",
    ]

    for section in sections:
        if section not in data:
            continue
        for pkg, spec in iter_dependency_specs(data[section]):
            version = check_version_match(pkg, str(spec))
            if version:
                findings.append(
                    Finding(
                        package=pkg,
                        version=version,
                        source=str(path),
                        evidence=f"{section} -> {pkg} = {spec}",
                    )
                )
            elif warn_namespaces:
                warning = create_namespace_warning(
                    pkg, str(spec), str(path), namespace_warnings_seen, evidence_prefix=section
                )
                if warning:
                    findings.append(warning)

    # Check for script IOCs if enabled
    if detect_iocs and "scripts" in data and isinstance(data["scripts"], dict):
        findings.extend(detect_script_iocs(data["scripts"], path))

    return findings
