"""IOC (Indicators of Compromise) detection for files and workflows."""
from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import List, Optional

from scripts.scan_core import config
from scripts.scan_core.models import Finding

LOGGER = logging.getLogger("shai-hulud")


def compute_file_hash(file_path: Path) -> Optional[str]:
    """Compute SHA-256 hash of a file."""
    try:
        if file_path.stat().st_size > config.MAX_HASH_FILE_SIZE:
            LOGGER.debug("File %s exceeds size limit for hashing", file_path)
            return None

        sha256_hash = hashlib.sha256()
        with file_path.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except (OSError, InterruptedError) as exc:
        LOGGER.debug("Unable to hash file %s: %s", file_path, exc)
        return None


def scan_file_for_iocs(file_path: Path) -> Optional[Finding]:
    """Check if a file matches known malicious hashes."""
    file_hash = compute_file_hash(file_path)
    if file_hash and file_hash in config.MALICIOUS_HASHES:
        return Finding(
            package="IOC",
            version=file_path.name,
            source=str(file_path),
            evidence=f"SHA-256: {file_hash}",
            category="ioc",
        )
    return None


def detect_workflow_iocs(root: Path) -> List[Finding]:
    """Detect suspicious workflow files in .github/workflows directory."""
    findings: List[Finding] = []
    workflows_dir = root / ".github" / "workflows"
    if not workflows_dir.exists():
        return findings

    for workflow_file in workflows_dir.glob("*.yml"):
        for pattern in config.WORKFLOW_IOC_PATTERNS:
            if pattern in str(workflow_file):
                findings.append(
                    Finding(
                        package="workflow_ioc",
                        version=workflow_file.name,
                        source=str(workflow_file),
                        evidence=f"Suspicious workflow name matches known Shai-Hulud pattern: {pattern}",
                        category="workflow_ioc",
                        severity="high",
                    )
                )
                break  # Only report once per workflow

    return findings
