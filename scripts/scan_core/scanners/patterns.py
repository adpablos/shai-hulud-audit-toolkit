"""Suspicious code pattern detection in JavaScript files."""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import List, Optional, Set

from scripts.scan_core.config import SUSPICIOUS_CODE_PATTERNS, MAX_PATTERN_SCAN_SIZE
from scripts.scan_core.models import Finding

LOGGER = logging.getLogger("shai-hulud")


def is_minified(content: str) -> bool:
    """Detect if file content is minified using line length heuristic."""
    lines = content.split("\n")
    if not lines:
        return False
    # If average line length > 200 chars, likely minified
    total_len = sum(len(line) for line in lines[:50])  # Check first 50 lines
    avg_len = total_len / min(len(lines), 50)
    return avg_len > 200


def scan_file_for_patterns(
    file_path: Path,
    categories: Optional[Set[str]] = None,
    min_severity: str = "low",
) -> List[Finding]:
    """Scan JavaScript file content for suspicious code patterns."""
    findings: List[Finding] = []

    # Check file size
    try:
        file_size = file_path.stat().st_size
        if file_size > MAX_PATTERN_SCAN_SIZE:
            LOGGER.debug("Skipping pattern scan for %s (size: %d bytes)", file_path, file_size)
            return findings
    except (OSError, InterruptedError) as exc:  # noqa: PERF203
        LOGGER.debug("Unable to stat file %s: %s", file_path, exc)
        return findings

    # Read file content
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, InterruptedError) as exc:  # noqa: PERF203
        LOGGER.debug("Unable to read file %s: %s", file_path, exc)
        return findings

    # Skip minified files
    if is_minified(content):
        LOGGER.debug("Skipping pattern scan for minified file: %s", file_path)
        return findings

    # Define severity order
    severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    min_sev_level = severity_order.get(min_severity, 0)

    # Scan for patterns
    detected_categories: Set[str] = set()
    for category, pattern_info in SUSPICIOUS_CODE_PATTERNS.items():
        # Filter by category if specified
        if categories and category not in categories:
            continue

        # Filter by severity
        pattern_severity = pattern_info["severity"]
        if severity_order.get(pattern_severity, 0) < min_sev_level:
            continue

        # Skip if we've already detected this category
        if category in detected_categories:
            continue

        # Check patterns
        for pattern in pattern_info["patterns"]:
            if re.search(pattern, content, re.IGNORECASE):
                findings.append(
                    Finding(
                        package=category,
                        version=file_path.name,
                        source=str(file_path),
                        evidence=f"{pattern_info['description']} - pattern: {pattern}",
                        category="suspicious_pattern",
                        severity=pattern_severity,
                    )
                )
                detected_categories.add(category)
                break  # Only report once per category per file

    return findings
