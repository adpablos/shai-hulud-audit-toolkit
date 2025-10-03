"""Utility functions for scanning operations."""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Dict, Optional, Set

from scripts.scan_core.config import ENV_ADVISORY_PATH, DEFAULT_ADVISORY_FILE, SUPPRESSED_WARNING_SUBSTRINGS
from scripts.scan_core.models import Finding

LOGGER = logging.getLogger("shai-hulud")
SUPPRESSED_WARNING_SEEN: Set[str] = set()

# Global index populated by advisory loader
COMPROMISED_PACKAGES: Dict[str, Set[str]] = {}
COMPROMISED_NAMESPACES: Set[str] = set()


def normalize_version(raw: object) -> Optional[str]:
    """Return a sanitised semantic version candidate or None."""
    if raw is None:
        return None
    version = str(raw).strip()
    if not version:
        return None
    if version.startswith('='):
        version = version[1:].strip()
    if version.startswith('v') and len(version) > 1 and version[1].isdigit():
        version = version[1:]
    while version and version[-1] in {'.', ',', ';'}:
        version = version[:-1]
    return version or None


def resolve_advisory_path(cli_path: Optional[str]) -> Optional[Path]:
    """Find the advisory dataset to use for this run."""
    candidates = []
    if cli_path:
        candidates.append(Path(cli_path))
    env_value = os.environ.get(ENV_ADVISORY_PATH)
    if env_value:
        candidates.append(Path(env_value))
    candidates.append(DEFAULT_ADVISORY_FILE)

    for candidate in candidates:
        candidate_path = candidate.expanduser()
        if not candidate_path.is_absolute():
            candidate_path = candidate_path.resolve()
        if candidate_path.is_file():
            LOGGER.debug("Using advisory dataset at %s", candidate_path)
            return candidate_path
        LOGGER.debug("Advisory dataset candidate %s not found", candidate_path)
    return None


def load_json(path: Path) -> Optional[Dict[str, object]]:
    """Load JSON file with error handling and suppression of known issues."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - best effort reader
        path_str = str(path)
        if any(marker in path_str for marker in SUPPRESSED_WARNING_SUBSTRINGS):
            if path_str not in SUPPRESSED_WARNING_SEEN:
                LOGGER.debug("Ignoring known malformed fixture %s: %s", path, exc)
                SUPPRESSED_WARNING_SEEN.add(path_str)
            return None
        LOGGER.warning("Failed to read JSON from %s: %s", path, exc)
        return None


def check_version_match(package: str, spec: str) -> Optional[str]:
    """Check if package version matches compromised version."""
    spec = spec.strip()
    if not spec:
        return None
    versions = COMPROMISED_PACKAGES.get(package)
    if not versions:
        return None
    candidate = normalize_version(spec)
    if candidate and candidate in versions:
        return candidate
    return None


def check_namespace_warning(package: str) -> bool:
    """Check if package belongs to a compromised namespace but is not itself compromised."""
    if not package.startswith("@") or "/" not in package:
        return False
    namespace = package.split("/")[0]
    return namespace in COMPROMISED_NAMESPACES and package not in COMPROMISED_PACKAGES


def create_version_match_finding(
    package: str,
    version: str,
    source: str,
    evidence: str,
    category: str = "dependency",
    severity: str = "medium",
) -> Optional[Finding]:
    """Check version match and create Finding if compromised."""
    match = check_version_match(package, version)
    if match:
        return Finding(package, match, source, evidence, category, severity)
    return None


def create_namespace_warning(
    package: str,
    version: str,
    source: str,
    namespace_warnings_seen: Set[str],
    evidence_prefix: str = "",
) -> Optional[Finding]:
    """Check namespace warning and create Finding if applicable."""
    if not check_namespace_warning(package):
        return None

    namespace = package.split("/")[0]
    if namespace in namespace_warnings_seen:
        return None

    namespace_warnings_seen.add(namespace)
    evidence = f"Namespace {namespace} is compromised; {package} itself not flagged"
    if evidence_prefix:
        evidence = f"{evidence_prefix} -> {evidence}"

    return Finding(
        package=package,
        version=version,
        source=source,
        evidence=evidence,
        category="namespace_warning",
        severity="medium",
    )


def resolve_relative_path(path: str, root: Optional[Path]) -> str:
    """Convert absolute path to relative path if root provided."""
    if not root:
        return path
    try:
        return str(Path(path).resolve().relative_to(root))
    except Exception:  # noqa: BLE001 - best effort formatting
        return path
