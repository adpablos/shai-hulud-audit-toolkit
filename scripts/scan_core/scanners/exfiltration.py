"""Data exfiltration pattern detection in code files."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional, Set

from scripts.scan_core.config import EXFILTRATION_INDICATORS
from scripts.scan_core.models import Finding


def scan_for_exfiltration(
    file_path: Path,
    content: str,
    allowlist: Optional[Set[str]] = None,
) -> List[Finding]:
    """Detect potential data exfiltration patterns in code with smart severity scoring."""
    findings: List[Finding] = []
    detected_categories: Set[str] = set()

    # Track what we find for severity scoring
    has_credential_access = False
    has_network_call = False
    exfil_findings: List[Dict[str, str]] = []

    # Check for data collection patterns
    for pattern in EXFILTRATION_INDICATORS["data_collection"]:
        if re.search(pattern, content, re.IGNORECASE):
            has_credential_access = True
            break

    # Check for suspicious domains
    for domain in EXFILTRATION_INDICATORS["suspicious_domains"]:
        if allowlist and domain in allowlist:
            continue

        if domain in content.lower():
            has_network_call = True
            exfil_findings.append({"type": "suspicious_domain", "value": domain})

    # Check for webhook patterns (regex)
    for category, patterns in EXFILTRATION_INDICATORS.items():
        if category in ("suspicious_domains", "data_collection"):
            continue  # Already handled

        for pattern in patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                has_network_call = True
                for match in matches[:1]:  # Only report first match per pattern
                    exfil_findings.append({"type": category, "value": match.group(0)})

    # Determine severity based on combination of factors
    if not exfil_findings:
        return findings

    # Critical: Credential access + exfiltration destination in same file
    if has_credential_access and has_network_call:
        severity = "critical"
        evidence_prefix = "CRITICAL: Credential access + network transmission"
    # High: Webhook endpoints or known exfiltration domains
    elif any(
        f["type"] in ("discord_webhooks", "slack_webhooks", "telegram_bots", "generic_webhooks")
        for f in exfil_findings
    ):
        severity = "high"
        evidence_prefix = "Webhook exfiltration pattern"
    # Medium: Suspicious domains without credential access
    elif exfil_findings:
        severity = "medium"
        evidence_prefix = "Suspicious network destination"
    else:
        severity = "low"
        evidence_prefix = "Potential exfiltration indicator"

    # Create findings (one per unique category to avoid noise)
    for finding_info in exfil_findings:
        category_key = finding_info["type"]
        if category_key in detected_categories:
            continue
        detected_categories.add(category_key)

        findings.append(
            Finding(
                package="exfiltration",
                version=file_path.name,
                source=str(file_path),
                evidence=f"{evidence_prefix}: {finding_info['type']} -> {finding_info['value']}",
                category="exfiltration",
                severity=severity,
            )
        )

    return findings
