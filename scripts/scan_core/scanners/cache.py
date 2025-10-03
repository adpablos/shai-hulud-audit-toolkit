"""NPM cache scanner for compromised package detection."""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import unquote, urlparse

from scripts.scan_core.models import Finding
from scripts.scan_core.utils import check_version_match, normalize_version

LOGGER = logging.getLogger("shai-hulud")
CACHE_SOURCE = "npm-cache"


def resolve_cache_index_dir(override: Optional[str]) -> Path:
    """Return the expected npm cache index directory."""
    if override:
        base = Path(override).expanduser()
    else:
        env_cache = os.environ.get("NPM_CONFIG_CACHE")
        base = Path(env_cache).expanduser() if env_cache else Path.home() / ".npm"

    base = base.resolve()
    if base.name == "index-v5":
        return base
    if base.name == "_cacache":
        return (base / "index-v5").resolve()

    candidate = base / "index-v5"
    if candidate.exists():
        return candidate.resolve()
    return (base / "_cacache" / "index-v5").resolve()


def _extract_package_version_from_url(url: str) -> Optional[Tuple[str, str]]:
    """Extract package and version from a tarball URL."""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return None
    path = unquote(parsed.path or "")
    if not path:
        return None

    prefix, sep, suffix = path.rpartition("/-/")
    if not sep or not suffix:
        return None

    package_path = prefix.lstrip("/")
    if not package_path:
        return None

    filename = suffix.split("/")[-1]
    if not filename:
        return None

    cleaned = filename
    for ext in (".tar.gz", ".tgz", ".tar", ".zip"):
        if cleaned.endswith(ext):
            cleaned = cleaned[: -len(ext)]
            break

    if "-" not in cleaned:
        return None

    _name_segment, _, version_segment = cleaned.rpartition("-")
    version = normalize_version(version_segment)
    if not version:
        return None

    return unquote(package_path), version


def parse_cache_entry(entry: Dict[str, object]) -> Optional[Tuple[str, str, str]]:
    """Extract package, version, and URL from a cache index record."""
    if not isinstance(entry, dict):
        return None

    entry_url: Optional[str] = None
    metadata = entry.get("metadata")
    if isinstance(metadata, dict):
        url_value = metadata.get("url") or metadata.get("resolved")
        if isinstance(url_value, str):
            entry_url = url_value

    if not entry_url:
        key = entry.get("key")
        if isinstance(key, str):
            marker = key.find("http")
            if marker != -1:
                entry_url = key[marker:]

    if not entry_url:
        return None

    parsed = _extract_package_version_from_url(entry_url)
    if not parsed:
        return None

    package, version = parsed
    return package, version, entry_url


def scan_npm_cache(index_dir: Path) -> Tuple[List[Finding], int]:
    """Inspect the npm cache index for compromised tarballs."""
    if not index_dir.exists():
        LOGGER.info("Cache index directory %s not found; skipping cache scan.", index_dir)
        return [], 0

    findings: List[Finding] = []
    inspected = 0
    seen_records: Set[Tuple[str, str, str]] = set()

    for entry_path in index_dir.rglob("*"):
        if not entry_path.is_file():
            continue
        try:
            raw_lines = entry_path.read_bytes().splitlines()
        except (OSError, InterruptedError) as exc:  # noqa: PERF203 - explicit handling
            LOGGER.debug("Unable to read cache index file %s: %s", entry_path, exc)
            continue

        for raw_line in raw_lines:
            line = raw_line.strip()
            if not line:
                continue
            try:
                decoded = line.decode("utf-8")
            except UnicodeDecodeError:
                LOGGER.debug("Skipping non-UTF8 cache record in %s", entry_path)
                continue

            _digest, sep, payload = decoded.partition("\t")
            if not sep:
                continue

            try:
                entry = json.loads(payload)
            except json.JSONDecodeError:
                LOGGER.debug("Skipping unparsable cache record in %s", entry_path)
                continue

            parsed = parse_cache_entry(entry)
            if not parsed:
                continue

            package, version, url = parsed
            record_key = (package, version, url)
            if record_key in seen_records:
                continue

            seen_records.add(record_key)
            inspected += 1

            match = check_version_match(package, version)
            if match:
                findings.append(
                    Finding(
                        package=package,
                        version=match,
                        source=CACHE_SOURCE,
                        evidence=f"cache entry -> {url}",
                    )
                )

    return findings, inspected
