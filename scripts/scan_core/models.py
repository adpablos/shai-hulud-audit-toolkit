"""Data models for scan findings and statistics."""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Dict


@dataclass
class Finding:
    """Represents a security finding from the scan."""

    package: str
    version: str
    source: str
    evidence: str
    category: str = "dependency"  # dependency, ioc, script_ioc, workflow_ioc, suspicious_pattern, exfiltration, namespace_warning
    severity: str = "medium"  # low, medium, high, critical

    def to_dict(self) -> Dict[str, str]:
        """Convert finding to dictionary format."""
        return asdict(self)


@dataclass
class ScanStats:
    """Statistics collected during a scan operation."""

    manifests: int = 0
    node_module_manifests: int = 0
    lockfiles: Counter = field(default_factory=Counter)

    def merge(self, other: "ScanStats") -> None:
        """Merge statistics from another scan."""
        self.manifests += other.manifests
        self.node_module_manifests += other.node_module_manifests
        self.lockfiles.update(other.lockfiles)

    def describe_lockfiles(self) -> str:
        """Return a human-readable description of lockfiles scanned."""
        if not self.lockfiles:
            return "none"
        parts = [f"{count}× {name}" for name, count in sorted(self.lockfiles.items())]
        return ", ".join(parts)
