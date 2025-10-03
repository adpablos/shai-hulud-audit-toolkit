"""Advisory data loading and indexing."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Set

from scripts.scan_core.utils import normalize_version, COMPROMISED_PACKAGES, COMPROMISED_NAMESPACES


def _register_package(mapping: Dict[str, Set[str]], package: str, version_value: object) -> None:
    """Register a package-version pair in the mapping."""
    version = normalize_version(version_value)
    if version:
        mapping.setdefault(package, set()).add(version)


def _parse_items_schema(payload: Dict[str, object]) -> Dict[str, Set[str]]:
    """Parse advisory format: {items: [{package, version}, ...]}."""
    mapping: Dict[str, Set[str]] = {}
    items = payload.get("items")
    if not isinstance(items, list):
        return mapping

    for entry in items:
        if not isinstance(entry, dict):
            continue
        package = entry.get("package")
        if isinstance(package, str):
            _register_package(mapping, package, entry.get("version"))
    return mapping


def _parse_dict_schema(payload: Dict[str, object]) -> Dict[str, Set[str]]:
    """Parse advisory format: {package: version} or {package: [versions]}."""
    mapping: Dict[str, Set[str]] = {}
    for package, versions in payload.items():
        if not isinstance(package, str):
            continue
        if isinstance(versions, (list, tuple, set)):
            for version in versions:
                _register_package(mapping, package, version)
        else:
            _register_package(mapping, package, versions)
    return mapping


def _parse_list_schema(payload: list) -> Dict[str, Set[str]]:
    """Parse advisory format: [{package, version}, ...]."""
    mapping: Dict[str, Set[str]] = {}
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        package = entry.get("package")
        if isinstance(package, str):
            _register_package(mapping, package, entry.get("version"))
    return mapping


def load_advisory_index(path: Path) -> Dict[str, Set[str]]:
    """Load compromised package data from a JSON advisory file.

    Supports three schemas:
    1. Items format: {items: [{package, version}, ...]}
    2. Dict format: {package: version} or {package: [versions]}
    3. List format: [{package, version}, ...]
    """
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - user supplied content
        raise ValueError(f"Failed to parse advisory file {path}: {exc}") from exc

    # Try each schema parser
    if isinstance(payload, dict) and "items" in payload:
        mapping = _parse_items_schema(payload)
    elif isinstance(payload, dict):
        mapping = _parse_dict_schema(payload)
    elif isinstance(payload, list):
        mapping = _parse_list_schema(payload)
    else:
        raise ValueError("Unsupported advisory schema; expected dict with 'items', dict, or list.")

    if not mapping:
        raise ValueError("Advisory file did not yield any package/version pairs.")
    return mapping


def set_compromised_index(index: Dict[str, Set[str]]) -> None:
    """Populate the global lookup structures with the advisory index."""
    global COMPROMISED_PACKAGES, COMPROMISED_NAMESPACES
    COMPROMISED_PACKAGES.clear()
    COMPROMISED_PACKAGES.update({package: set(versions) for package, versions in index.items()})

    # Extract compromised namespaces (scoped packages starting with @)
    namespaces = set()
    for package in COMPROMISED_PACKAGES:
        if package.startswith("@") and "/" in package:
            namespace = package.split("/")[0]
            namespaces.add(namespace)

    COMPROMISED_NAMESPACES.clear()
    COMPROMISED_NAMESPACES.update(namespaces)
