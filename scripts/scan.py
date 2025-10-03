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


class Colors:
    """ANSI color codes for terminal output."""

    RED = "\033[31m"
    YELLOW = "\033[33m"
    GREEN = "\033[32m"
    BLUE = "\033[34m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    _enabled = True

    @classmethod
    def disable(cls) -> None:
        """Disable all color output."""
        cls._enabled = False

    @classmethod
    def colorize(cls, text: str, color: str) -> str:
        """Apply color to text if colors are enabled."""
        if not cls._enabled:
            return text
        return f"{color}{text}{cls.RESET}"

    @classmethod
    def supports_color(cls) -> bool:
        """Check if the terminal supports color output."""
        # Respect NO_COLOR environment variable (https://no-color.org/)
        if os.environ.get("NO_COLOR"):
            return False
        # Check if output is a TTY
        if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
            return False
        return True


class Emojis:
    """Emoji indicators for visual scanning results."""

    CRITICAL = "🚨"
    WARNING = "⚠️"
    INFO = "ℹ️"
    CLEAN = "✅"
    STATS = "📊"
    PACKAGE = "📦"
    FILE = "📄"
    IOC = "🔴"
    SEARCH = "🔍"

    _enabled = True

    @classmethod
    def disable(cls) -> None:
        """Disable all emoji output."""
        cls._enabled = False

    @classmethod
    def get(cls, emoji: str) -> str:
        """Return emoji if enabled, empty string otherwise."""
        return emoji if cls._enabled else ""

    @classmethod
    def supports_emoji(cls) -> bool:
        """Check if terminal supports emoji rendering."""
        term = os.environ.get("TERM", "")
        # Disable emojis in dumb terminals or when output is redirected
        if term == "dumb" or not sys.stdout.isatty():
            return False
        return True

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

# Known Shai-Hulud script IOC patterns
SCRIPT_IOC_PATTERNS = [
    r"\bcurl\b.*https?://",
    r"\bwget\b.*https?://",
    r"\bfetch\(",
    r"webhook\.site",
    r"bb8ca5f6-4175-45d2-b042-fc9ebb8170b7",  # Known Shai-Hulud UUID
    r"trufflehog",
]

# Known Shai-Hulud workflow names
WORKFLOW_IOC_PATTERNS = [
    "shai-hulud-workflow.yml",
    "shai-hulud.yml",
    ".github/workflows/shai-hulud",
]

# Suspicious code patterns for extended detection
SUSPICIOUS_CODE_PATTERNS = {
    "eval_usage": {
        "patterns": [r"\beval\s*\(", r"Function\s*\(.*\)\s*\("],
        "description": "Dynamic code evaluation",
        "severity": "high",
    },
    "child_process": {
        "patterns": [r"child_process\.exec", r"child_process\.spawn", r'require\(["\']child_process["\']'],
        "description": "Process execution capabilities",
        "severity": "medium",
    },
    "network_calls": {
        "patterns": [r"https?://[^\s\"\')]+", r"fetch\(", r"axios\.(get|post)", r"request\("],
        "description": "Network communication",
        "severity": "low",
    },
    "credential_access": {
        "patterns": [
            r"process\.env\[.*(?:SECRET|KEY|TOKEN|PASSWORD|API)",
            r'\.env["\']?\s*\)',
            r"AWS_.*(?:KEY|SECRET)",
            r"GITHUB_TOKEN",
        ],
        "description": "Environment credential access",
        "severity": "high",
    },
    "obfuscation": {
        "patterns": [
            r"String\.fromCharCode",
            r"atob\(",
            r'Buffer\.from\(.*["\']base64',
            r"\\x[0-9a-fA-F]{2}",
        ],
        "description": "Code obfuscation techniques",
        "severity": "medium",
    },
    "file_system": {
        "patterns": [r"fs\.readFileSync", r"fs\.writeFileSync", r'require\(["\']fs["\']'],
        "description": "File system access",
        "severity": "low",
    },
    "command_injection": {
        "patterns": [r"\$\{.*\}", r"`.*\$\{.*\}.*`", r"shell:\s*true"],
        "description": "Potential command injection",
        "severity": "high",
    },
}

# JavaScript file extensions to scan for patterns
JS_FILE_EXTENSIONS = {".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx"}

# Maximum file size for pattern scanning (1 MB)
MAX_PATTERN_SCAN_SIZE = 1 * 1024 * 1024

# Data exfiltration indicators
EXFILTRATION_INDICATORS = {
    "suspicious_domains": [
        "pastebin.com",
        "paste.ee",
        "hastebin.com",
        "controlc.com",
        "gist.github.com",
        "githubusercontent.com",
        "ngrok.io",
        "serveo.net",
        "localhost.run",
        "webhook.site",
        "requestbin.com",
        "pipedream.com",
    ],
    "discord_webhooks": [
        r"discord(?:app)?\.com/api/webhooks",
    ],
    "slack_webhooks": [
        r"hooks\.slack\.com/services",
    ],
    "telegram_bots": [
        r"api\.telegram\.org/bot",
    ],
    "generic_webhooks": [
        r"webhook\.site/[a-z0-9-]+",
        r"requestbin\.com/r/[a-z0-9]+",
    ],
    "ip_addresses": [
        r"https?://(?:\d{1,3}\.){3}\d{1,3}",
    ],
    "data_collection": [
        r"\.(env|npmrc|bashrc|bash_profile|zshrc)",
        r"aws/credentials",
        r"ssh/id_rsa",
        r"AWS_.*(?:KEY|SECRET|TOKEN)",
        r"GITHUB_TOKEN",
        r"NPM_TOKEN",
        r"CI_JOB_TOKEN",
    ],
}


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


class ColoredFormatter(logging.Formatter):
    """Logging formatter with ANSI color support."""

    LEVEL_COLORS = {
        logging.DEBUG: Colors.BLUE,
        logging.INFO: Colors.GREEN,
        logging.WARNING: Colors.YELLOW,
        logging.ERROR: Colors.RED,
        logging.CRITICAL: Colors.RED + Colors.BOLD,
    }

    def format(self, record: logging.LogRecord) -> str:
        levelname = record.levelname
        if Colors._enabled:
            color = self.LEVEL_COLORS.get(record.levelno, "")
            record.levelname = Colors.colorize(levelname, color)
        result = super().format(record)
        record.levelname = levelname
        return result


def setup_logging(log_dir: Path, level: str, use_color: bool = True) -> Path:
    """Initialise console and file logging for the current execution."""
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"shai_hulud_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    LOGGER.handlers.clear()
    LOGGER.setLevel(numeric_level)
    LOGGER.propagate = False

    # File handler without colors (for parsing)
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    LOGGER.addHandler(file_handler)

    # Console handler with optional color support
    console_handler = logging.StreamHandler()
    console_handler.setLevel(numeric_level)
    if use_color and Colors.supports_color():
        console_handler.setFormatter(ColoredFormatter("%(levelname)s: %(message)s"))
    else:
        Colors.disable()
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
    category: str = "dependency"  # "dependency", "ioc", "script_ioc", "workflow_ioc", "suspicious_pattern", or "exfiltration"
    severity: str = "medium"  # "low", "medium", "high", or "critical"

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


def detect_script_iocs(scripts: Dict[str, str], package_json_path: Path) -> List[Finding]:
    """Detect suspicious IOC patterns in package.json scripts."""
    findings: List[Finding] = []
    for script_name, script_content in scripts.items():
        for pattern in SCRIPT_IOC_PATTERNS:
            if re.search(pattern, script_content, re.IGNORECASE):
                findings.append(
                    Finding(
                        package="script_ioc",
                        version=script_name,
                        source=str(package_json_path),
                        evidence=f"Suspicious pattern in script '{script_name}': {script_content[:100]}",
                        category="script_ioc",
                        severity="high",
                    )
                )
                break  # Only report once per script
    return findings


def scan_package_json(path: Path, detect_iocs: bool = True) -> List[Finding]:
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

    # Check for script IOCs if enabled
    if detect_iocs and "scripts" in data and isinstance(data["scripts"], dict):
        findings.extend(detect_script_iocs(data["scripts"], path))

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


def scan_for_exfiltration(file_path: Path, content: str, allowlist: Optional[Set[str]] = None) -> List[Finding]:
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
        # Skip if domain is in allowlist
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
    elif any(f["type"] in ("discord_webhooks", "slack_webhooks", "telegram_bots", "generic_webhooks") for f in exfil_findings):
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


def collect_targets(paths: Sequence[str]) -> List[Path]:
    resolved: List[Path] = []
    for raw in paths:
        path = Path(raw).expanduser().resolve()
        if not path.exists():
            LOGGER.warning("Path %s does not exist; skipping.", path)
            continue
        resolved.append(path)
    return resolved


def detect_workflow_iocs(root: Path) -> List[Finding]:
    """Detect suspicious workflow files in .github/workflows directory."""
    findings: List[Finding] = []
    workflows_dir = root / ".github" / "workflows"
    if not workflows_dir.exists():
        return findings

    for workflow_file in workflows_dir.glob("*.yml"):
        for pattern in WORKFLOW_IOC_PATTERNS:
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


def gather_findings(
    root: Path,
    include_node_modules: bool,
    check_hashes: bool = True,
    detect_iocs: bool = True,
    detect_patterns: bool = False,
    pattern_categories: Optional[Set[str]] = None,
    pattern_min_severity: str = "low",
    detect_exfiltration: bool = False,
    exfiltration_allowlist: Optional[Set[str]] = None,
) -> Tuple[List[Finding], ScanStats]:
    findings: List[Finding] = []
    stats = ScanStats()

    # Check for workflow IOCs at the root level
    if detect_iocs:
        findings.extend(detect_workflow_iocs(root))

    for current_dir, _dirnames, filenames in safe_walk(root, include_node_modules=include_node_modules):
        in_node_modules = "node_modules" in current_dir.parts
        for filename in filenames:
            file_path = current_dir / filename

            # Check for IOC hashes in suspicious files
            if check_hashes and any(pattern in filename.lower() for pattern in IOC_FILE_PATTERNS):
                ioc_finding = scan_file_for_iocs(file_path)
                if ioc_finding:
                    findings.append(ioc_finding)

            # Check for suspicious code patterns in JavaScript files
            if detect_patterns and file_path.suffix in JS_FILE_EXTENSIONS:
                pattern_findings = scan_file_for_patterns(file_path, pattern_categories, pattern_min_severity)
                findings.extend(pattern_findings)

            # Check for data exfiltration patterns in JavaScript files
            if detect_exfiltration and file_path.suffix in JS_FILE_EXTENSIONS:
                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                    if not is_minified(content):
                        exfil_findings = scan_for_exfiltration(file_path, content, exfiltration_allowlist)
                        findings.extend(exfil_findings)
                except (OSError, InterruptedError) as exc:  # noqa: PERF203
                    LOGGER.debug("Unable to read file for exfiltration scan %s: %s", file_path, exc)

            if filename == "package.json":
                if in_node_modules:
                    if include_node_modules:
                        stats.node_module_manifests += 1
                        findings.extend(scan_installed_package(file_path))
                else:
                    stats.manifests += 1
                    findings.extend(scan_package_json(file_path, detect_iocs=detect_iocs))
            elif filename in LOCKFILE_HANDLERS and not in_node_modules:
                stats.lockfiles[filename] += 1
                findings.extend(LOCKFILE_HANDLERS[filename](file_path))
    return findings, stats


def determine_risk_level(findings: List[Finding]) -> str:
    """Determine risk level emoji based on finding count and severity."""
    if not findings:
        return Emojis.get(Emojis.CLEAN)

    # IOC findings are always critical
    ioc_count = sum(1 for f in findings if f.category == "ioc")
    if ioc_count > 0:
        return Emojis.get(Emojis.CRITICAL)

    total = len(findings)
    if total >= 10:
        return Emojis.get(Emojis.CRITICAL)
    if total >= 3:
        return Emojis.get(Emojis.WARNING)
    return Emojis.get(Emojis.WARNING)


def print_structured_report(
    findings: List[Finding], stats: ScanStats, scan_paths: List[Path], root: Optional[Path] = None
) -> None:
    """Print a structured multi-section summary report."""
    separator = "=" * 70
    subseparator = "-" * 70

    # Header
    print(f"\n{separator}")
    title = f"{Emojis.get(Emojis.STATS)} SHAI-HULUD AUDIT REPORT"
    print(Colors.colorize(title, Colors.BOLD))
    print(separator)

    # Section 1: Scan Scope
    print(f"\n{Emojis.get(Emojis.SEARCH)} SCAN SCOPE")
    print(subseparator)
    for path in scan_paths:
        print(f"   • {path}")

    # Section 2: Coverage Statistics
    print(f"\n{Emojis.get(Emojis.STATS)} COVERAGE")
    print(subseparator)
    print(f"   Manifests scanned:     {stats.manifests}")
    print(f"   Node modules scanned:  {stats.node_module_manifests}")
    lockfiles_desc = stats.describe_lockfiles()
    print(f"   Lockfiles analyzed:    {lockfiles_desc}")

    # Section 3: Findings Summary
    dependency_findings = [f for f in findings if f.category == "dependency"]
    hash_ioc_findings = [f for f in findings if f.category == "ioc"]
    script_ioc_findings = [f for f in findings if f.category == "script_ioc"]
    workflow_ioc_findings = [f for f in findings if f.category == "workflow_ioc"]
    pattern_findings = [f for f in findings if f.category == "suspicious_pattern"]
    exfiltration_findings = [f for f in findings if f.category == "exfiltration"]
    all_iocs = hash_ioc_findings + script_ioc_findings + workflow_ioc_findings

    print(f"\n{Emojis.get(Emojis.SEARCH)} FINDINGS")
    print(subseparator)
    if not findings:
        clean_msg = f"   {Emojis.get(Emojis.CLEAN)} No compromised packages or IOCs detected"
        print(Colors.colorize(clean_msg, Colors.GREEN))
    else:
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

    # Section 4: Detailed Findings
    if findings:
        print(f"\n{Emojis.get(Emojis.WARNING)} DETAILED FINDINGS")
        print(subseparator)

        if dependency_findings:
            print(Colors.colorize("   Compromised Dependencies:", Colors.RED + Colors.BOLD))
            for finding in dependency_findings:
                source = finding.source
                if root:
                    try:
                        source = str(Path(source).resolve().relative_to(root))
                    except Exception:  # noqa: BLE001 - best effort formatting
                        source = finding.source
                pkg_version = Colors.colorize(f"{finding.package}@{finding.version}", Colors.YELLOW)
                pkg_emoji = Emojis.get(Emojis.PACKAGE)
                print(f"   {pkg_emoji} {pkg_version}")
                print(f"      Location: {source}")
                print(f"      Evidence: {finding.evidence}")

        if hash_ioc_findings:
            if dependency_findings:
                print()
            print(Colors.colorize("   IOC Hash Matches (Known Malicious Files):", Colors.RED + Colors.BOLD))
            for finding in hash_ioc_findings:
                source = finding.source
                if root:
                    try:
                        source = str(Path(source).resolve().relative_to(root))
                    except Exception:  # noqa: BLE001 - best effort formatting
                        source = finding.source
                filename = Colors.colorize(finding.version, Colors.YELLOW)
                file_emoji = Emojis.get(Emojis.FILE)
                print(f"   {file_emoji} {filename}")
                print(f"      Location: {source}")
                print(f"      Evidence: {finding.evidence}")

        if script_ioc_findings:
            if dependency_findings or hash_ioc_findings:
                print()
            print(Colors.colorize("   Script IOCs (Suspicious Package Scripts):", Colors.RED + Colors.BOLD))
            for finding in script_ioc_findings:
                source = finding.source
                if root:
                    try:
                        source = str(Path(source).resolve().relative_to(root))
                    except Exception:  # noqa: BLE001 - best effort formatting
                        source = finding.source
                script_name = Colors.colorize(finding.version, Colors.YELLOW)
                print(f"   📝 {script_name}")
                print(f"      Location: {source}")
                print(f"      Evidence: {finding.evidence}")

        if workflow_ioc_findings:
            if dependency_findings or hash_ioc_findings or script_ioc_findings:
                print()
            print(Colors.colorize("   Workflow IOCs (Suspicious GitHub Workflows):", Colors.RED + Colors.BOLD))
            for finding in workflow_ioc_findings:
                source = finding.source
                if root:
                    try:
                        source = str(Path(source).resolve().relative_to(root))
                    except Exception:  # noqa: BLE001 - best effort formatting
                        source = finding.source
                workflow_name = Colors.colorize(finding.version, Colors.YELLOW)
                print(f"   ⚙️  {workflow_name}")
                print(f"      Location: {source}")
                print(f"      Evidence: {finding.evidence}")

        if pattern_findings:
            if dependency_findings or hash_ioc_findings or script_ioc_findings or workflow_ioc_findings:
                print()
            print(Colors.colorize("   Suspicious Code Patterns:", Colors.YELLOW + Colors.BOLD))
            for finding in pattern_findings:
                source = finding.source
                if root:
                    try:
                        source = str(Path(source).resolve().relative_to(root))
                    except Exception:  # noqa: BLE001 - best effort formatting
                        source = finding.source
                category_name = Colors.colorize(finding.package, Colors.YELLOW)
                print(f"   🔎 {category_name} ({finding.severity})")
                print(f"      File: {finding.version}")
                print(f"      Location: {source}")
                print(f"      Evidence: {finding.evidence}")

        if exfiltration_findings:
            if dependency_findings or hash_ioc_findings or script_ioc_findings or workflow_ioc_findings or pattern_findings:
                print()
            print(Colors.colorize("   Data Exfiltration Risks:", Colors.RED + Colors.BOLD))
            for finding in exfiltration_findings:
                source = finding.source
                if root:
                    try:
                        source = str(Path(source).resolve().relative_to(root))
                    except Exception:  # noqa: BLE001 - best effort formatting
                        source = finding.source
                severity_color = Colors.RED if finding.severity in ("high", "critical") else Colors.YELLOW
                indicator_type = Colors.colorize(finding.package, severity_color)
                print(f"   🚨 {indicator_type} ({finding.severity})")
                print(f"      File: {finding.version}")
                print(f"      Location: {source}")
                print(f"      Evidence: {finding.evidence}")

    # Section 5: Recommendations
    if findings:
        print(f"\n{Emojis.get(Emojis.INFO)} RECOMMENDATIONS")
        print(subseparator)
        print("   1. Review detailed findings above")
        print("   2. Check advisory sources for remediation guidance")
        print("   3. Update or remove compromised packages")
        print("   4. Re-scan after remediation")

    print(f"\n{separator}\n")


def print_compact_report(findings: List[Finding], root: Optional[Path]) -> None:
    """Print a compact summary report (legacy format)."""
    if not findings:
        clean_msg = f"{Emojis.get(Emojis.CLEAN)} No compromised packages or IOCs detected."
        LOGGER.info(clean_msg)
        return

    dependency_findings = [f for f in findings if f.category == "dependency"]
    hash_ioc_findings = [f for f in findings if f.category == "ioc"]
    script_ioc_findings = [f for f in findings if f.category == "script_ioc"]
    workflow_ioc_findings = [f for f in findings if f.category == "workflow_ioc"]
    all_iocs = hash_ioc_findings + script_ioc_findings + workflow_ioc_findings

    if dependency_findings:
        emoji = Emojis.get(Emojis.CRITICAL if len(dependency_findings) >= 10 else Emojis.WARNING)
        header = Colors.colorize(f"{emoji} Detected compromised dependencies:", Colors.RED + Colors.BOLD)
        LOGGER.warning(header)
        for finding in dependency_findings:
            source = finding.source
            if root:
                try:
                    source = str(Path(source).resolve().relative_to(root))
                except Exception:  # noqa: BLE001 - best effort formatting
                    source = finding.source
            pkg_version = Colors.colorize(f"{finding.package}@{finding.version}", Colors.YELLOW)
            pkg_emoji = Emojis.get(Emojis.PACKAGE)
            LOGGER.warning("%s %s (%s) -> %s", pkg_emoji, pkg_version, source, finding.evidence)

    if hash_ioc_findings:
        emoji = Emojis.get(Emojis.IOC)
        header = Colors.colorize(f"{emoji} Detected IOC hash matches (known malicious files):", Colors.RED + Colors.BOLD)
        LOGGER.warning(header)
        for finding in hash_ioc_findings:
            source = finding.source
            if root:
                try:
                    source = str(Path(source).resolve().relative_to(root))
                except Exception:  # noqa: BLE001 - best effort formatting
                    source = finding.source
            filename = Colors.colorize(finding.version, Colors.YELLOW)
            file_emoji = Emojis.get(Emojis.FILE)
            LOGGER.warning("%s %s (%s) -> %s", file_emoji, filename, source, finding.evidence)

    if script_ioc_findings:
        header = Colors.colorize("📝 Detected script IOCs (suspicious package scripts):", Colors.RED + Colors.BOLD)
        LOGGER.warning(header)
        for finding in script_ioc_findings:
            source = finding.source
            if root:
                try:
                    source = str(Path(source).resolve().relative_to(root))
                except Exception:  # noqa: BLE001 - best effort formatting
                    source = finding.source
            script_name = Colors.colorize(finding.version, Colors.YELLOW)
            LOGGER.warning("📝 %s (%s) -> %s", script_name, source, finding.evidence)

    if workflow_ioc_findings:
        header = Colors.colorize("⚙️  Detected workflow IOCs (suspicious GitHub workflows):", Colors.RED + Colors.BOLD)
        LOGGER.warning(header)
        for finding in workflow_ioc_findings:
            source = finding.source
            if root:
                try:
                    source = str(Path(source).resolve().relative_to(root))
                except Exception:  # noqa: BLE001 - best effort formatting
                    source = finding.source
            workflow_name = Colors.colorize(finding.version, Colors.YELLOW)
            LOGGER.warning("⚙️  %s (%s) -> %s", workflow_name, source, finding.evidence)

    pattern_findings = [f for f in findings if f.category == "suspicious_pattern"]
    if pattern_findings:
        header = Colors.colorize("🔎 Detected suspicious code patterns:", Colors.YELLOW + Colors.BOLD)
        LOGGER.warning(header)
        for finding in pattern_findings:
            source = finding.source
            if root:
                try:
                    source = str(Path(source).resolve().relative_to(root))
                except Exception:  # noqa: BLE001 - best effort formatting
                    source = finding.source
            category = Colors.colorize(finding.package, Colors.YELLOW)
            LOGGER.warning("🔎 %s [%s] (%s) -> %s", category, finding.severity, source, finding.evidence)

    exfiltration_findings = [f for f in findings if f.category == "exfiltration"]
    if exfiltration_findings:
        header = Colors.colorize("🚨 Detected data exfiltration risks:", Colors.RED + Colors.BOLD)
        LOGGER.warning(header)
        for finding in exfiltration_findings:
            source = finding.source
            if root:
                try:
                    source = str(Path(source).resolve().relative_to(root))
                except Exception:  # noqa: BLE001 - best effort formatting
                    source = finding.source
            indicator = Colors.colorize(finding.package, Colors.RED if finding.severity in ("high", "critical") else Colors.YELLOW)
            LOGGER.warning("🚨 %s [%s] (%s) -> %s", indicator, finding.severity, source, finding.evidence)

    risk_emoji = determine_risk_level(findings)
    summary_parts = [
        f"Dependencies: {len(dependency_findings)}",
        f"IOCs: {len(all_iocs)}",
        f"Patterns: {len(pattern_findings)}",
        f"Exfiltration: {len(exfiltration_findings)}",
    ]
    total_msg = Colors.colorize(
        f"{risk_emoji} Total findings: {len(findings)} ({', '.join(summary_parts)})",
        Colors.RED + Colors.BOLD
    )
    LOGGER.warning(total_msg)


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scan for Shai-Hulud compromised npm packages.")
    parser.add_argument(
        "paths",
        nargs="*",
        default=["."],
        help="Project directories to scan (default: current directory).",
    )
    parser.add_argument("--json", action="store_true", dest="json_output", help="Emit findings as JSON (alias for --format json).")
    parser.add_argument(
        "--format",
        choices=["structured", "compact", "json"],
        help="Output format: structured (multi-section), compact (legacy), or json. Auto-detects based on TTY.",
    )
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
        "--detect-iocs",
        action="store_true",
        default=True,
        help="Enable script and workflow IOC detection (default: enabled).",
    )
    parser.add_argument(
        "--no-detect-iocs",
        action="store_false",
        dest="detect_iocs",
        help="Disable script and workflow IOC detection.",
    )
    parser.add_argument(
        "--detect-patterns",
        action="store_true",
        default=False,
        help="Enable suspicious code pattern detection in JavaScript files (default: disabled).",
    )
    parser.add_argument(
        "--no-detect-patterns",
        action="store_false",
        dest="detect_patterns",
        help="Disable suspicious code pattern detection.",
    )
    parser.add_argument(
        "--pattern-severity",
        choices=["low", "medium", "high", "critical"],
        default="low",
        help="Minimum severity level for pattern detection (default: low).",
    )
    parser.add_argument(
        "--pattern-categories",
        help="Comma-separated list of pattern categories to detect (e.g., eval_usage,child_process).",
    )
    parser.add_argument(
        "--detect-exfiltration",
        action="store_true",
        default=False,
        help="Enable data exfiltration pattern detection in JavaScript files (default: disabled).",
    )
    parser.add_argument(
        "--exfiltration-allowlist",
        help="Comma-separated list of domains/IPs to exclude from exfiltration detection.",
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
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable color output in terminal (also respects NO_COLOR environment variable).",
    )
    parser.add_argument(
        "--no-emoji",
        action="store_true",
        help="Disable emoji indicators in terminal output (auto-disabled for non-TTY).",
    )
    return parser.parse_args(argv)


def run(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)

    log_dir = Path(args.log_dir).expanduser().resolve()
    use_color = not args.no_color
    log_path = setup_logging(log_dir, args.log_level, use_color=use_color)

    # Handle emoji flag - disable if requested or if terminal doesn't support it
    if args.no_emoji or not Emojis.supports_emoji():
        Emojis.disable()

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

    # Parse pattern categories if provided
    pattern_categories = None
    if args.pattern_categories:
        pattern_categories = set(cat.strip() for cat in args.pattern_categories.split(","))

    # Parse exfiltration allowlist if provided
    exfiltration_allowlist = None
    if args.exfiltration_allowlist:
        exfiltration_allowlist = set(item.strip() for item in args.exfiltration_allowlist.split(","))

    all_findings: List[Finding] = []
    overall_stats = ScanStats()
    for target in targets:
        LOGGER.info("Scanning %s", target)
        findings, stats = gather_findings(
            target,
            include_node_modules=args.include_node_modules,
            check_hashes=args.hash_iocs,
            detect_iocs=args.detect_iocs,
            detect_patterns=args.detect_patterns,
            pattern_categories=pattern_categories,
            pattern_min_severity=args.pattern_severity,
            detect_exfiltration=args.detect_exfiltration,
            exfiltration_allowlist=exfiltration_allowlist,
        )
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

    # Determine output format
    output_format = args.format
    if args.json_output:
        output_format = "json"
    elif output_format is None:
        # Auto-detect: structured for TTY, compact for pipes
        output_format = "structured" if sys.stdout.isatty() else "compact"

    # Generate output in selected format
    if output_format == "json":
        print(json.dumps([f.to_dict() for f in all_findings], indent=2))
    elif output_format == "structured":
        root = targets[0] if len(targets) == 1 else None
        print_structured_report(all_findings, overall_stats, targets, root=root)
    else:  # compact
        root = targets[0] if len(targets) == 1 else None
        print_compact_report(all_findings, root=root)

    if all_findings:
        LOGGER.warning("Findings recorded in %s", log_path)
        return 1
    LOGGER.info("Scan completed successfully. Log retained at %s", log_path)
    return 0


if __name__ == "__main__":
    sys.exit(run())
