"""Structured multi-section summary report."""
from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from scripts.scan_core.models import Finding, ScanStats
from scripts.scan_core.reporting.formatters import Colors, Emojis, determine_risk_level
from scripts.scan_core.utils import resolve_relative_path


def print_header() -> None:
    """Print report header."""
    separator = "=" * 70
    print(f"\n{separator}")
    title = f"{Emojis.get(Emojis.STATS)} SHAI-HULUD AUDIT REPORT"
    print(Colors.colorize(title, Colors.BOLD))
    print(separator)


def print_scan_scope(scan_paths: List[Path]) -> None:
    """Print scan scope section."""
    subseparator = "-" * 70
    print(f"\n{Emojis.get(Emojis.SEARCH)} SCAN SCOPE")
    print(subseparator)
    for path in scan_paths:
        print(f"   • {path}")


def print_coverage(stats: ScanStats) -> None:
    """Print coverage statistics section."""
    subseparator = "-" * 70
    print(f"\n{Emojis.get(Emojis.STATS)} COVERAGE")
    print(subseparator)
    print(f"   Manifests scanned:     {stats.manifests}")
    print(f"   Node modules scanned:  {stats.node_module_manifests}")
    lockfiles_desc = stats.describe_lockfiles()
    print(f"   Lockfiles analyzed:    {lockfiles_desc}")


def print_findings_summary(findings: List[Finding]) -> None:
    """Print findings summary section."""
    subseparator = "-" * 70
    dependency_findings = [f for f in findings if f.category == "dependency"]
    hash_ioc_findings = [f for f in findings if f.category == "ioc"]
    script_ioc_findings = [f for f in findings if f.category == "script_ioc"]
    workflow_ioc_findings = [f for f in findings if f.category == "workflow_ioc"]
    pattern_findings = [f for f in findings if f.category == "suspicious_pattern"]
    exfiltration_findings = [f for f in findings if f.category == "exfiltration"]
    namespace_warnings = [f for f in findings if f.category == "namespace_warning"]
    all_iocs = hash_ioc_findings + script_ioc_findings + workflow_ioc_findings

    print(f"\n{Emojis.get(Emojis.SEARCH)} FINDINGS")
    print(subseparator)

    if not findings:
        clean_msg = f"   {Emojis.get(Emojis.CLEAN)} No compromised packages or IOCs detected"
        print(Colors.colorize(clean_msg, Colors.GREEN))
        return

    risk_emoji = determine_risk_level(findings)
    total_line = f"   {risk_emoji} Total Issues:        {len(findings)}"
    print(Colors.colorize(total_line, Colors.RED + Colors.BOLD))

    dep_line = f"      • Dependencies:      {len(dependency_findings)}"
    print(Colors.colorize(dep_line, Colors.YELLOW if dependency_findings else ""))

    ioc_line = f"      • IOC Matches:       {len(all_iocs)}"
    if all_iocs:
        ioc_line += f" ({len(hash_ioc_findings)} hash, {len(script_ioc_findings)} script, {len(workflow_ioc_findings)} workflow)"
    print(Colors.colorize(ioc_line, Colors.RED if all_iocs else ""))

    if pattern_findings:
        pattern_line = f"      • Suspicious Patterns: {len(pattern_findings)}"
        print(Colors.colorize(pattern_line, Colors.YELLOW))

    if exfiltration_findings:
        exfil_line = f"      • Exfiltration Risks: {len(exfiltration_findings)}"
        has_high_severity = any(f.severity in ("high", "critical") for f in exfiltration_findings)
        exfil_color = Colors.RED if has_high_severity else Colors.YELLOW
        print(Colors.colorize(exfil_line, exfil_color))

    if namespace_warnings:
        namespace_line = f"      • Namespace Warnings: {len(namespace_warnings)}"
        print(Colors.colorize(namespace_line, Colors.YELLOW))


def print_dependency_findings(findings: List[Finding], root: Optional[Path]) -> None:
    """Print compromised dependency findings."""
    if not findings:
        return
    print(Colors.colorize("   Compromised Dependencies:", Colors.RED + Colors.BOLD))
    for finding in findings:
        source = resolve_relative_path(finding.source, root)
        pkg_version = Colors.colorize(f"{finding.package}@{finding.version}", Colors.YELLOW)
        pkg_emoji = Emojis.get(Emojis.PACKAGE)
        print(f"   {pkg_emoji} {pkg_version}")
        print(f"      Location: {source}")
        print(f"      Evidence: {finding.evidence}")


def print_ioc_findings(findings: List[Finding], root: Optional[Path]) -> None:
    """Print IOC hash match findings."""
    if not findings:
        return
    print(Colors.colorize("   IOC Hash Matches (Known Malicious Files):", Colors.RED + Colors.BOLD))
    for finding in findings:
        source = resolve_relative_path(finding.source, root)
        filename = Colors.colorize(finding.version, Colors.YELLOW)
        file_emoji = Emojis.get(Emojis.FILE)
        print(f"   {file_emoji} {filename}")
        print(f"      Location: {source}")
        print(f"      Evidence: {finding.evidence}")


def print_script_ioc_findings(findings: List[Finding], root: Optional[Path]) -> None:
    """Print script IOC findings."""
    if not findings:
        return
    print(Colors.colorize("   Script IOCs (Suspicious Package Scripts):", Colors.RED + Colors.BOLD))
    for finding in findings:
        source = resolve_relative_path(finding.source, root)
        script_name = Colors.colorize(finding.version, Colors.YELLOW)
        print(f"   📝 {script_name}")
        print(f"      Location: {source}")
        print(f"      Evidence: {finding.evidence}")


def print_workflow_ioc_findings(findings: List[Finding], root: Optional[Path]) -> None:
    """Print workflow IOC findings."""
    if not findings:
        return
    print(Colors.colorize("   Workflow IOCs (Suspicious GitHub Workflows):", Colors.RED + Colors.BOLD))
    for finding in findings:
        source = resolve_relative_path(finding.source, root)
        workflow_name = Colors.colorize(finding.version, Colors.YELLOW)
        print(f"   ⚙️  {workflow_name}")
        print(f"      Location: {source}")
        print(f"      Evidence: {finding.evidence}")


def print_pattern_findings(findings: List[Finding], root: Optional[Path]) -> None:
    """Print suspicious pattern findings."""
    if not findings:
        return
    print(Colors.colorize("   Suspicious Code Patterns:", Colors.YELLOW + Colors.BOLD))
    for finding in findings:
        source = resolve_relative_path(finding.source, root)
        category_name = Colors.colorize(finding.package, Colors.YELLOW)
        print(f"   🔎 {category_name} ({finding.severity})")
        print(f"      File: {finding.version}")
        print(f"      Location: {source}")
        print(f"      Evidence: {finding.evidence}")


def print_exfiltration_findings(findings: List[Finding], root: Optional[Path]) -> None:
    """Print data exfiltration findings."""
    if not findings:
        return
    print(Colors.colorize("   Data Exfiltration Risks:", Colors.RED + Colors.BOLD))
    for finding in findings:
        source = resolve_relative_path(finding.source, root)
        severity_color = Colors.RED if finding.severity in ("high", "critical") else Colors.YELLOW
        indicator_type = Colors.colorize(finding.package, severity_color)
        print(f"   🚨 {indicator_type} ({finding.severity})")
        print(f"      File: {finding.version}")
        print(f"      Location: {source}")
        print(f"      Evidence: {finding.evidence}")


def print_namespace_warnings(findings: List[Finding], root: Optional[Path]) -> None:
    """Print namespace warning findings."""
    if not findings:
        return
    print(Colors.colorize("   Namespace Warnings:", Colors.YELLOW + Colors.BOLD))
    for finding in findings:
        source = resolve_relative_path(finding.source, root)
        package_name = Colors.colorize(finding.package, Colors.YELLOW)
        print(f"   ⚠️  {package_name} ({finding.version})")
        print(f"      Location: {source}")
        print(f"      Evidence: {finding.evidence}")


def print_recommendations() -> None:
    """Print remediation recommendations."""
    subseparator = "-" * 70
    print(f"\n{Emojis.get(Emojis.INFO)} RECOMMENDATIONS")
    print(subseparator)
    print("   1. Review detailed findings above")
    print("   2. Check advisory sources for remediation guidance")
    print("   3. Update or remove compromised packages")
    print("   4. Re-scan after remediation")


def print_structured_report(
    findings: List[Finding],
    stats: ScanStats,
    scan_paths: List[Path],
    root: Optional[Path] = None,
) -> None:
    """Print a structured multi-section summary report."""
    print_header()
    print_scan_scope(scan_paths)
    print_coverage(stats)
    print_findings_summary(findings)

    if not findings:
        print(f"\n{'=' * 70}\n")
        return

    # Print detailed findings by category
    print(f"\n{Emojis.get(Emojis.WARNING)} DETAILED FINDINGS")
    print("-" * 70)

    dependency_findings = [f for f in findings if f.category == "dependency"]
    hash_ioc_findings = [f for f in findings if f.category == "ioc"]
    script_ioc_findings = [f for f in findings if f.category == "script_ioc"]
    workflow_ioc_findings = [f for f in findings if f.category == "workflow_ioc"]
    pattern_findings = [f for f in findings if f.category == "suspicious_pattern"]
    exfiltration_findings = [f for f in findings if f.category == "exfiltration"]
    namespace_warnings = [f for f in findings if f.category == "namespace_warning"]

    print_dependency_findings(dependency_findings, root)
    if dependency_findings and (hash_ioc_findings or script_ioc_findings or workflow_ioc_findings):
        print()
    print_ioc_findings(hash_ioc_findings, root)
    if hash_ioc_findings and (script_ioc_findings or workflow_ioc_findings):
        print()
    print_script_ioc_findings(script_ioc_findings, root)
    if script_ioc_findings and workflow_ioc_findings:
        print()
    print_workflow_ioc_findings(workflow_ioc_findings, root)
    has_ioc_or_dep = dependency_findings or hash_ioc_findings or script_ioc_findings or workflow_ioc_findings
    if has_ioc_or_dep and pattern_findings:
        print()
    print_pattern_findings(pattern_findings, root)
    if (has_ioc_or_dep or pattern_findings) and exfiltration_findings:
        print()
    print_exfiltration_findings(exfiltration_findings, root)
    if (has_ioc_or_dep or pattern_findings or exfiltration_findings) and namespace_warnings:
        print()
    print_namespace_warnings(namespace_warnings, root)

    print_recommendations()
    print(f"\n{'=' * 70}\n")
