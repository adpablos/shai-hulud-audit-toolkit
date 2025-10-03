#!/usr/bin/env python3
"""Shai-Hulud compromise scanner for Node.js projects.

This script inspects project manifests, lockfiles, optional node_modules trees,
and globally installed npm packages to spot any dependency/version combination
that matches the Shai-Hulud supply-chain compromise advisory.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
from datetime import datetime
from collections import Counter
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Sequence, Set, Tuple
from urllib.parse import unquote, urlparse

LOGGER = logging.getLogger("shai-hulud")

ENV_ADVISORY_PATH = "SHAI_HULUD_ADVISORY"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ADVISORY_FILE = PROJECT_ROOT / "data" / "compromised_packages_snapshot.json"

COMPROMISED_PACKAGES: Dict[str, Set[str]] = {}
SUPPRESSED_WARNING_SUBSTRINGS = (
    "resolve/test/resolver/malformed_package_json/package.json",
)
SUPPRESSED_WARNING_SEEN: Set[str] = set()

CACHE_SOURCE = "npm-cache"

# Known malicious Shai-Hulud payload SHA-256 hashes
MALICIOUS_HASHES: Set[str] = {
    "de0e25a3e6c1e1e5998b306b7141b3dc4c0088da9d7bb47c1c00c91e6e4f85d6",
    "81d2a004a1bca6ef87a1caf7d0e0b355ad1764238e40ff6d1b1cb77ad4f595c3",
    "83a650ce44b2a9854802a7fb4c202877815274c129af49e6c2d1d5d5d55c501e",
    "4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db",
    "dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c",
    "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09",
    "b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777",
}

# File patterns to check for IOCs
IOC_FILE_PATTERNS = [
    "bundle.js",
    "index.js",
    "install.js",
    "postinstall.js",
]

# Maximum file size to hash (10 MB)
MAX_HASH_FILE_SIZE = 10 * 1024 * 1024


@dataclass
class ScanStats:
    manifests: int = 0
    node_module_manifests: int = 0
    lockfiles: Counter = field(default_factory=Counter)

    def merge(self, other: "ScanStats") -> None:
        self.manifests += other.manifests
        self.node_module_manifests += other.node_module_manifests
        self.lockfiles.update(other.lockfiles)

    def describe_lockfiles(self) -> str:
        if not self.lockfiles:
            return "none"
        parts = [f"{count}× {name}" for name, count in sorted(self.lockfiles.items())]
        return ", ".join(parts)


def setup_logging(log_dir: Path, level: str) -> Path:
    """Initialise console and file logging for the current execution."""
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"shai_hulud_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    LOGGER.handlers.clear()
    LOGGER.setLevel(numeric_level)
    LOGGER.propagate = False

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    LOGGER.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    LOGGER.addHandler(console_handler)

    return log_path


def normalize_version(raw: object) -> Optional[str]:
    """Return a sanitised semantic version candidate or ``None``."""
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
    candidates: List[Path] = []
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


def load_advisory_index(path: Path) -> Dict[str, Set[str]]:
    """Load compromised package data from a JSON advisory file."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - user supplied content
        raise ValueError(f"Failed to parse advisory file {path}: {exc}") from exc

    mapping: Dict[str, Set[str]] = {}

    def register(package: str, version_value: object) -> None:
        version = normalize_version(version_value)
        if not version:
            return
        mapping.setdefault(package, set()).add(version)

    if isinstance(payload, dict) and "items" in payload and isinstance(payload["items"], list):
        for entry in payload["items"]:
            if not isinstance(entry, dict):
                continue
            package = entry.get("package")
            if isinstance(package, str):
                register(package, entry.get("version"))
    elif isinstance(payload, dict):
        for package, versions in payload.items():
            if not isinstance(package, str):
                continue
            if isinstance(versions, (list, tuple, set)):
                for version in versions:
                    register(package, version)
            else:
                register(package, versions)
    elif isinstance(payload, list):
        for entry in payload:
            if isinstance(entry, dict):
                package = entry.get("package")
                if isinstance(package, str):
                    register(package, entry.get("version"))
    else:
        raise ValueError("Unsupported advisory schema; expected mapping or list of records.")

    if not mapping:
        raise ValueError("Advisory file did not yield any package/version pairs.")
    return mapping


def set_compromised_index(index: Dict[str, Set[str]]) -> None:
    """Populate the global lookup structures with the advisory index."""
    global COMPROMISED_PACKAGES
    COMPROMISED_PACKAGES = {package: set(versions) for package, versions in index.items()}


@dataclass
class Finding:
    package: str
    version: str
    source: str
    evidence: str
    category: str = "dependency"  # "dependency" or "ioc"

    def to_dict(self) -> Dict[str, str]:
        return asdict(self)


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


def load_json(path: Path) -> Optional[Dict[str, object]]:
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


def iter_dependency_specs(block: object) -> Iterator[Tuple[str, str]]:
    if isinstance(block, dict):
        for key, value in block.items():
            if isinstance(value, str):
                yield key, value
            elif isinstance(value, dict):
                nested_version = value.get("version") if "version" in value else None
                if isinstance(nested_version, str):
                    yield key, nested_version
                yield from iter_dependency_specs(value)
            elif isinstance(value, list):
                for item in value:
                    yield from iter_dependency_specs({key: item})
    elif isinstance(block, list):
        for item in block:
            yield from iter_dependency_specs(item)


def scan_package_json(path: Path) -> List[Finding]:
    data = load_json(path)
    if data is None:
        return []
    findings: List[Finding] = []
    sections = [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
        "bundleDependencies",
        "bundledDependencies",
        "resolutions",
        "overrides",
    ]
    for section in sections:
        if section not in data:
            continue
        for pkg, spec in iter_dependency_specs(data[section]):
            version = check_version_match(pkg, str(spec))
            if version:
                findings.append(
                    Finding(
                        package=pkg,
                        version=version,
                        source=str(path),
                        evidence=f"{section} -> {pkg} = {spec}",
                    )
                )
    return findings


def scan_npm_lock(path: Path) -> List[Finding]:
    data = load_json(path)
    if data is None:
        return []
    findings: List[Finding] = []

    def walk_dependencies(deps: Dict[str, object], context: str) -> None:
        for name, meta in deps.items():
            if not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if isinstance(version, str) and check_version_match(name, version):
                findings.append(
                    Finding(
                        package=name,
                        version=normalize_version(version) or version,
                        source=str(path),
                        evidence=f"{context}:{name}",
                    )
                )
            nested = meta.get("dependencies")
            if isinstance(nested, dict):
                walk_dependencies(nested, context=f"{context}/{name}")

    if "packages" in data and isinstance(data["packages"], dict):
        for pkg_path, meta in data["packages"].items():
            if pkg_path in ("", None) or not isinstance(meta, dict):
                continue
            name = meta.get("name")
            version = meta.get("version")
            if isinstance(name, str) and isinstance(version, str) and check_version_match(name, version):
                findings.append(
                    Finding(
                        package=name,
                        version=normalize_version(version) or version,
                        source=str(path),
                        evidence=f"packages entry: {pkg_path}",
                    )
                )
    if "dependencies" in data and isinstance(data["dependencies"], dict):
        walk_dependencies(data["dependencies"], context="dependencies")
    return findings


def descriptor_to_package(descriptor: str) -> str:
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


def parse_yarn_lock(path: Path) -> Iterator[Tuple[str, str]]:
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
            if stripped.startswith('version'):
                _, _, value = stripped.partition(' ')
                version = value.strip('"')
                if version.startswith(':'):
                    version = version.lstrip(':').strip()
                version = version.strip('"')
                for pkg in current_packages:
                    yield pkg, version


def scan_yarn_lock(path: Path) -> List[Finding]:
    findings: List[Finding] = []
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
    return findings


PNPM_PACKAGE_PATTERN = re.compile(r'^\s{2}([^:]+):\s*$')


def scan_pnpm_lock(path: Path) -> List[Finding]:
    findings: List[Finding] = []
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
    return findings


LOCKFILE_HANDLERS = {
    "package-lock.json": scan_npm_lock,
    "npm-shrinkwrap.json": scan_npm_lock,
    "yarn.lock": scan_yarn_lock,
    "pnpm-lock.yaml": scan_pnpm_lock,
}


def safe_walk(root: Path, include_node_modules: bool) -> Iterator[Tuple[Path, List[str], List[str]]]:
    def onerror(exc: OSError) -> None:
        LOGGER.warning("Unable to access directory %s: %s", exc.filename or root, exc)

    try:
        for dirpath, dirnames, filenames in os.walk(
            root,
            topdown=True,
            onerror=onerror,
            followlinks=False,
        ):
            if not include_node_modules:
                dirnames[:] = [d for d in dirnames if d != "node_modules"]
            yield Path(dirpath), dirnames, filenames
    except (OSError, InterruptedError) as exc:  # noqa: PERF203 - want explicit handling
        LOGGER.warning("Traversal aborted in %s: %s", root, exc)


def scan_installed_package(package_json: Path) -> List[Finding]:
    data = load_json(package_json)
    if not data:
        return []
    name = data.get("name")
    version = data.get("version")
    if isinstance(name, str) and isinstance(version, str) and check_version_match(name, version):
        match = normalize_version(version) or version
        return [
            Finding(
                package=name,
                version=match,
                source=str(package_json),
                evidence="installed module package.json",
            )
        ]
    return []


def scan_global_npm() -> Tuple[List[Finding], int]:
    cmd = ["npm", "ls", "-g", "--depth=0", "--json"]
    try:
        result = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        LOGGER.warning("npm executable not found; skipping global package scan.")
        return [], 0
    if result.returncode not in (0, 1):
        LOGGER.warning("npm ls exited with status %s; output may be incomplete.", result.returncode)
    try:
        parsed = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as exc:
        LOGGER.warning("Unable to parse npm ls output: %s", exc)
        return [], 0
    findings: List[Finding] = []
    inspected = 0

    def walk(deps: Dict[str, object], context: str) -> None:
        nonlocal inspected
        for name, meta in deps.items():
            if not isinstance(meta, dict):
                continue
            inspected += 1
            version = meta.get("version")
            if isinstance(version, str) and check_version_match(name, version):
                findings.append(
                    Finding(
                        package=name,
                        version=normalize_version(version) or version,
                        source="npm-global",
                        evidence=f"{context}:{name}",
                    )
                )
            nested = meta.get("dependencies")
            if isinstance(nested, dict):
                walk(nested, context=f"{context}/{name}")

    dependencies = parsed.get("dependencies")
    if isinstance(dependencies, dict):
        walk(dependencies, context="global")
    return findings, inspected


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


def compute_file_hash(file_path: Path) -> Optional[str]:
    """Compute SHA-256 hash of a file."""
    try:
        # Check file size first
        if file_path.stat().st_size > MAX_HASH_FILE_SIZE:
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
    if file_hash and file_hash in MALICIOUS_HASHES:
        return Finding(
            package="IOC",
            version=file_path.name,
            source=str(file_path),
            evidence=f"SHA-256: {file_hash}",
            category="ioc",
        )
    return None


def collect_targets(paths: Sequence[str]) -> List[Path]:
    resolved: List[Path] = []
    for raw in paths:
        path = Path(raw).expanduser().resolve()
        if not path.exists():
            LOGGER.warning("Path %s does not exist; skipping.", path)
            continue
        resolved.append(path)
    return resolved


def gather_findings(root: Path, include_node_modules: bool, check_hashes: bool = True) -> Tuple[List[Finding], ScanStats]:
    findings: List[Finding] = []
    stats = ScanStats()
    for current_dir, _dirnames, filenames in safe_walk(root, include_node_modules=include_node_modules):
        in_node_modules = "node_modules" in current_dir.parts
        for filename in filenames:
            file_path = current_dir / filename

            # Check for IOC hashes in suspicious files
            if check_hashes and any(pattern in filename.lower() for pattern in IOC_FILE_PATTERNS):
                ioc_finding = scan_file_for_iocs(file_path)
                if ioc_finding:
                    findings.append(ioc_finding)

            if filename == "package.json":
                if in_node_modules:
                    if include_node_modules:
                        stats.node_module_manifests += 1
                        findings.extend(scan_installed_package(file_path))
                else:
                    stats.manifests += 1
                    findings.extend(scan_package_json(file_path))
            elif filename in LOCKFILE_HANDLERS and not in_node_modules:
                stats.lockfiles[filename] += 1
                findings.extend(LOCKFILE_HANDLERS[filename](file_path))
    return findings, stats


def summarize(findings: List[Finding], root: Optional[Path]) -> None:
    if not findings:
        LOGGER.info("No compromised packages or IOCs detected.")
        return

    dependency_findings = [f for f in findings if f.category == "dependency"]
    ioc_findings = [f for f in findings if f.category == "ioc"]

    if dependency_findings:
        LOGGER.warning("Detected compromised dependencies:")
        for finding in dependency_findings:
            source = finding.source
            if root:
                try:
                    source = str(Path(source).resolve().relative_to(root))
                except Exception:  # noqa: BLE001 - best effort formatting
                    source = finding.source
            LOGGER.warning("- %s@%s (%s) -> %s", finding.package, finding.version, source, finding.evidence)

    if ioc_findings:
        LOGGER.warning("Detected IOC hash matches (known malicious files):")
        for finding in ioc_findings:
            source = finding.source
            if root:
                try:
                    source = str(Path(source).resolve().relative_to(root))
                except Exception:  # noqa: BLE001 - best effort formatting
                    source = finding.source
            LOGGER.warning("- %s (%s) -> %s", finding.version, source, finding.evidence)

    LOGGER.warning("Total findings: %s (Dependencies: %s, IOCs: %s)",
                   len(findings), len(dependency_findings), len(ioc_findings))


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scan for Shai-Hulud compromised npm packages.")
    parser.add_argument(
        "paths",
        nargs="*",
        default=["."],
        help="Project directories to scan (default: current directory).",
    )
    parser.add_argument("--json", action="store_true", dest="json_output", help="Emit findings as JSON.")
    parser.add_argument(
        "--include-node-modules",
        action="store_true",
        help="Scan installed node_modules trees for resolved versions.",
    )
    parser.add_argument(
        "--check-global",
        action="store_true",
        help="Inspect globally installed npm packages via 'npm ls -g'.",
    )
    parser.add_argument(
        "--skip-cache",
        action="store_true",
        help="Skip inspecting the npm cache index (~/.npm/_cacache/index-v5).",
    )
    parser.add_argument(
        "--npm-cache-dir",
        help="Override the npm cache directory (defaults to $NPM_CONFIG_CACHE or ~/.npm).",
    )
    parser.add_argument(
        "--advisory-file",
        help="Path to the compromised package advisory JSON. Overrides defaults and environment variable.",
    )
    parser.add_argument(
        "--hash-iocs",
        action="store_true",
        default=True,
        help="Enable hash-based IOC detection for known malicious files (default: enabled).",
    )
    parser.add_argument(
        "--no-hash-iocs",
        action="store_false",
        dest="hash_iocs",
        help="Disable hash-based IOC detection.",
    )
    parser.add_argument(
        "--log-dir",
        default="logs",
        help="Directory where timestamped scan logs are written (default: logs).",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Console/log verbosity (default: INFO).",
    )
    return parser.parse_args(argv)


def run(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)

    log_dir = Path(args.log_dir).expanduser().resolve()
    log_path = setup_logging(log_dir, args.log_level)
    LOGGER.info("Detailed execution log: %s", log_path)

    advisory_path = resolve_advisory_path(args.advisory_file)
    if not advisory_path:
        LOGGER.error(
            "Unable to locate advisory dataset. Provide --advisory-file or set %s.",
            ENV_ADVISORY_PATH,
        )
        return 2

    LOGGER.info("Loading advisory data from %s", advisory_path)
    try:
        advisory_index = load_advisory_index(advisory_path)
    except ValueError as exc:
        LOGGER.error("%s", exc)
        return 2
    set_compromised_index(advisory_index)
    total_versions = sum(len(versions) for versions in COMPROMISED_PACKAGES.values())
    LOGGER.info(
        "Indexed %s packages covering %s compromised versions.",
        len(COMPROMISED_PACKAGES),
        total_versions,
    )

    targets = collect_targets(args.paths)
    if not targets:
        LOGGER.error("No valid targets to scan.")
        return 2

    all_findings: List[Finding] = []
    overall_stats = ScanStats()
    for target in targets:
        LOGGER.info("Scanning %s", target)
        findings, stats = gather_findings(target, include_node_modules=args.include_node_modules, check_hashes=args.hash_iocs)
        all_findings.extend(findings)
        overall_stats.merge(stats)
        LOGGER.info(
            "Summary for %s: %s manifests (%s within node_modules); lockfiles: %s.",
            target,
            stats.manifests,
            stats.node_module_manifests,
            stats.describe_lockfiles(),
        )
    if args.check_global:
        LOGGER.info("Scanning globally installed npm packages")
        global_findings, inspected = scan_global_npm()
        all_findings.extend(global_findings)
        LOGGER.info(
            "Global npm scan inspected %s packages and flagged %s findings.",
            inspected,
            len(global_findings),
        )

    cache_override = args.npm_cache_dir
    check_cache = not args.skip_cache or bool(cache_override)
    if args.skip_cache and cache_override:
        LOGGER.info("Cache scan disabled (--skip-cache); ignoring --npm-cache-dir value %s.", cache_override)
        check_cache = False
    if check_cache:
        cache_index_dir = resolve_cache_index_dir(cache_override)
        LOGGER.info("Scanning npm cache index at %s", cache_index_dir)
        cache_findings, inspected_cache = scan_npm_cache(cache_index_dir)
        all_findings.extend(cache_findings)
        LOGGER.info(
            "Cache scan inspected %s cached artifacts and flagged %s findings.",
            inspected_cache,
            len(cache_findings),
        )

    LOGGER.info(
        "Aggregate summary: %s manifests scanned (%s within node_modules); lockfiles: %s.",
        overall_stats.manifests,
        overall_stats.node_module_manifests,
        overall_stats.describe_lockfiles(),
    )

    if args.json_output:
        print(json.dumps([f.to_dict() for f in all_findings], indent=2))
    else:
        root = targets[0] if len(targets) == 1 else None
        summarize(all_findings, root=root)

    if all_findings:
        LOGGER.warning("Findings recorded in %s", log_path)
        return 1
    LOGGER.info("Scan completed successfully. Log retained at %s", log_path)
    return 0


if __name__ == "__main__":
    sys.exit(run())
