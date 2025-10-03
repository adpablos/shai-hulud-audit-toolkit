"""Compact summary report using logger output."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional

from scripts.scan_core.models import Finding
from scripts.scan_core.reporting.formatters import Colors, Emojis, determine_risk_level
from scripts.scan_core.utils import resolve_relative_path

LOGGER = logging.getLogger("shai-hulud")


def print_compact_report(findings: List[Finding], root: Optional[Path]) -> None:
    """Print a compact summary report using logger output."""
    if not findings:
        clean_msg = f"{Emojis.get(Emojis.CLEAN)} No compromised packages or IOCs detected."
        LOGGER.info(clean_msg)
        return

    dependency_findings = [f for f in findings if f.category == "dependency"]
    hash_ioc_findings = [f for f in findings if f.category == "ioc"]
    script_ioc_findings = [f for f in findings if f.category == "script_ioc"]
    workflow_ioc_findings = [f for f in findings if f.category == "workflow_ioc"]
    pattern_findings = [f for f in findings if f.category == "suspicious_pattern"]
    exfiltration_findings = [f for f in findings if f.category == "exfiltration"]
    namespace_warnings = [f for f in findings if f.category == "namespace_warning"]
    all_iocs = hash_ioc_findings + script_ioc_findings + workflow_ioc_findings

    if dependency_findings:
        emoji = Emojis.get(Emojis.CRITICAL if len(dependency_findings) >= 10 else Emojis.WARNING)
        header = Colors.colorize(f"{emoji} Detected compromised dependencies:", Colors.RED + Colors.BOLD)
        LOGGER.warning(header)
        for finding in dependency_findings:
            source = resolve_relative_path(finding.source, root)
            pkg_version = Colors.colorize(f"{finding.package}@{finding.version}", Colors.YELLOW)
            pkg_emoji = Emojis.get(Emojis.PACKAGE)
            LOGGER.warning("%s %s (%s) -> %s", pkg_emoji, pkg_version, source, finding.evidence)

    if hash_ioc_findings:
        emoji = Emojis.get(Emojis.IOC)
        header = Colors.colorize(f"{emoji} Detected IOC hash matches (known malicious files):", Colors.RED + Colors.BOLD)
        LOGGER.warning(header)
        for finding in hash_ioc_findings:
            source = resolve_relative_path(finding.source, root)
            filename = Colors.colorize(finding.version, Colors.YELLOW)
            file_emoji = Emojis.get(Emojis.FILE)
            LOGGER.warning("%s %s (%s) -> %s", file_emoji, filename, source, finding.evidence)

    if script_ioc_findings:
        header = Colors.colorize("📝 Detected script IOCs (suspicious package scripts):", Colors.RED + Colors.BOLD)
        LOGGER.warning(header)
        for finding in script_ioc_findings:
            source = resolve_relative_path(finding.source, root)
            script_name = Colors.colorize(finding.version, Colors.YELLOW)
            LOGGER.warning("📝 %s (%s) -> %s", script_name, source, finding.evidence)

    if workflow_ioc_findings:
        header = Colors.colorize("⚙️  Detected workflow IOCs (suspicious GitHub workflows):", Colors.RED + Colors.BOLD)
        LOGGER.warning(header)
        for finding in workflow_ioc_findings:
            source = resolve_relative_path(finding.source, root)
            workflow_name = Colors.colorize(finding.version, Colors.YELLOW)
            LOGGER.warning("⚙️  %s (%s) -> %s", workflow_name, source, finding.evidence)

    if pattern_findings:
        header = Colors.colorize("🔎 Detected suspicious code patterns:", Colors.YELLOW + Colors.BOLD)
        LOGGER.warning(header)
        for finding in pattern_findings:
            source = resolve_relative_path(finding.source, root)
            category = Colors.colorize(finding.package, Colors.YELLOW)
            LOGGER.warning("🔎 %s [%s] (%s) -> %s", category, finding.severity, source, finding.evidence)

    if exfiltration_findings:
        header = Colors.colorize("🚨 Detected data exfiltration risks:", Colors.RED + Colors.BOLD)
        LOGGER.warning(header)
        for finding in exfiltration_findings:
            source = resolve_relative_path(finding.source, root)
            indicator = Colors.colorize(finding.package, Colors.RED if finding.severity in ("high", "critical") else Colors.YELLOW)
            LOGGER.warning("🚨 %s [%s] (%s) -> %s", indicator, finding.severity, source, finding.evidence)

    if namespace_warnings:
        header = Colors.colorize("⚠️  Detected namespace warnings:", Colors.YELLOW + Colors.BOLD)
        LOGGER.warning(header)
        for finding in namespace_warnings:
            source = resolve_relative_path(finding.source, root)
            package_name = Colors.colorize(finding.package, Colors.YELLOW)
            LOGGER.warning("⚠️  %s (%s) [%s] -> %s", package_name, finding.version, source, finding.evidence)

    risk_emoji = determine_risk_level(findings)
    summary_parts = [
        f"Dependencies: {len(dependency_findings)}",
        f"IOCs: {len(all_iocs)}",
        f"Patterns: {len(pattern_findings)}",
        f"Exfiltration: {len(exfiltration_findings)}",
        f"Namespaces: {len(namespace_warnings)}",
    ]
    total_msg = Colors.colorize(
        f"{risk_emoji} Total findings: {len(findings)} ({', '.join(summary_parts)})",
        Colors.RED + Colors.BOLD
    )
    LOGGER.warning(total_msg)
