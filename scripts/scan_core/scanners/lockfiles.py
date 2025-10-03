"""Lockfile scanners for npm, yarn, and pnpm."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, Iterator, List, Set

from scripts.scan_core.models import Finding
from scripts.scan_core.utils import (
    load_json,
    check_version_match,
    normalize_version,
    create_namespace_warning,
)


def scan_npm_lock(path: Path, warn_namespaces: bool = True) -> List[Finding]:
    """Scan package-lock.json or npm-shrinkwrap.json."""
    data = load_json(path)
    if data is None:
        return []
    findings: List[Finding] = []
    namespace_warnings_seen: Set[str] = set()

    def walk_dependencies(deps: Dict[str, object], context: str) -> None:
        for name, meta in deps.items():
            if not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if not isinstance(version, str):
                continue

            if check_version_match(name, version):
                findings.append(
                    Finding(
                        package=name,
                        version=normalize_version(version) or version,
                        source=str(path),
                        evidence=f"{context}:{name}",
                    )
                )
            elif warn_namespaces:
                warning = create_namespace_warning(
                    name, normalize_version(version) or version, str(path), namespace_warnings_seen
                )
                if warning:
                    findings.append(warning)

            nested = meta.get("dependencies")
            if isinstance(nested, dict):
                walk_dependencies(nested, context=f"{context}/{name}")

    if "packages" in data and isinstance(data["packages"], dict):
        for pkg_path, meta in data["packages"].items():
            if pkg_path in ("", None) or not isinstance(meta, dict):
                continue
            name = meta.get("name")
            version = meta.get("version")
            if not (isinstance(name, str) and isinstance(version, str)):
                continue

            if check_version_match(name, version):
                findings.append(
                    Finding(
                        package=name,
                        version=normalize_version(version) or version,
                        source=str(path),
                        evidence=f"packages entry: {pkg_path}",
                    )
                )
            elif warn_namespaces:
                warning = create_namespace_warning(
                    name, normalize_version(version) or version, str(path), namespace_warnings_seen
                )
                if warning:
                    findings.append(warning)

    if "dependencies" in data and isinstance(data["dependencies"], dict):
        walk_dependencies(data["dependencies"], context="dependencies")

    return findings


def descriptor_to_package(descriptor: str) -> str:
    """Extract package name from yarn descriptor."""
    descriptor = descriptor.strip().strip('"')
    if descriptor.startswith('@'):
        second_at = descriptor.find('@', 1)
        if second_at > 0:
            return descriptor[:second_at]
        return descriptor
    at_index = descriptor.find('@')
    if at_index == -1:
        return descriptor
    return descriptor[:at_index]


def parse_yarn_lock(path: Path) -> Iterator[tuple[str, str]]:
    """Parse yarn.lock file and yield (package, version) tuples."""
    current_packages: List[str] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            raw = line.rstrip('\n')
            if not raw.strip() or raw.lstrip().startswith('#'):
                continue
            if not raw.startswith(' '):
                header = raw.rstrip(':')
                descriptors = [item.strip() for item in header.split(',')]
                current_packages = [descriptor_to_package(item) for item in descriptors]
                continue
            stripped = raw.strip()
            if not stripped.startswith('version'):
                continue
            _, _, value = stripped.partition(' ')
            version = value.strip('"')
            if version.startswith(':'):
                version = version.lstrip(':').strip()
            version = version.strip('"')
            for pkg in current_packages:
                yield pkg, version


def scan_yarn_lock(path: Path, warn_namespaces: bool = True) -> List[Finding]:
    """Scan yarn.lock file."""
    findings: List[Finding] = []
    namespace_warnings_seen: Set[str] = set()

    for pkg, version in parse_yarn_lock(path):
        match = check_version_match(pkg, version)
        if match:
            findings.append(
                Finding(
                    package=pkg,
                    version=match,
                    source=str(path),
                    evidence=f"lock entry for {pkg}",
                )
            )
        elif warn_namespaces:
            warning = create_namespace_warning(
                pkg, version, str(path), namespace_warnings_seen
            )
            if warning:
                findings.append(warning)

    return findings


PNPM_PACKAGE_PATTERN = re.compile(r'^\s{2}([^:]+):\s*$')


def scan_pnpm_lock(path: Path, warn_namespaces: bool = True) -> List[Finding]:
    """Scan pnpm-lock.yaml file."""
    findings: List[Finding] = []
    namespace_warnings_seen: Set[str] = set()
    in_packages = False

    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if stripped.startswith('#') or not stripped:
                continue
            if stripped == 'packages:':
                in_packages = True
                continue
            if not in_packages:
                continue

            match = PNPM_PACKAGE_PATTERN.match(line)
            if not match:
                continue

            key = match.group(1).strip()
            if not key.startswith('/'):
                continue

            parts = key.split('/')
            if len(parts) < 3:
                continue

            version_segment = parts[-1]
            if '_' in version_segment:
                version_segment = version_segment.split('_', 1)[0]
            version_segment = version_segment.split('(')[0]
            version = normalize_version(version_segment)

            name_segments = parts[1:-1]
            if not name_segments:
                continue

            if name_segments[0].startswith('@') and len(name_segments) >= 2:
                name = f"{name_segments[0]}/{name_segments[1]}"
            else:
                name = name_segments[0]

            if version and check_version_match(name, version):
                findings.append(
                    Finding(
                        package=name,
                        version=version,
                        source=str(path),
                        evidence=f"packages entry: {key}",
                    )
                )
            elif warn_namespaces and version:
                warning = create_namespace_warning(
                    name, version, str(path), namespace_warnings_seen
                )
                if warning:
                    findings.append(warning)

    return findings


# Lockfile handler mapping
LOCKFILE_HANDLERS = {
    "package-lock.json": scan_npm_lock,
    "npm-shrinkwrap.json": scan_npm_lock,
    "yarn.lock": scan_yarn_lock,
    "pnpm-lock.yaml": scan_pnpm_lock,
}
