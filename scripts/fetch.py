#!/usr/bin/env python3
"""Fetch and consolidate Shai-Hulud compromised npm packages into JSON."""
from __future__ import annotations

import argparse
import html
import json
import logging
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Pattern, Tuple

import urllib.error
import urllib.request

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.7",
}

LOGGER = logging.getLogger("shai-hulud-fetch")

CONFIG_DEFAULT_PATH = Path(__file__).resolve().parents[1] / "config" / "shai_hulud_sources.json"

PACKAGE_PATTERN = re.compile(
    r"(?P<name>@?[a-zA-Z0-9_.\-]+(?:/[a-zA-Z0-9_.\-]+)?)@(?P<version>\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.]+)?)"
)
VERSION_PATTERN = re.compile(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.]+)?")


@dataclass
class SourceConfig:
    url: str
    parser: Optional[str] = None


@dataclass
class SourceResult:
    url: str
    fetched_at: str
    status: str
    parser: Optional[str]
    packages: Dict[str, Dict[str, set]]

    def package_count(self) -> int:
        return sum(len(version_map) for version_map in self.packages.values())

    def succeeded(self) -> bool:
        return not str(self.status).startswith(("HTTPError", "URLError", "Error"))


def fetch_url(url: str, timeout: int = 30) -> Tuple[Optional[str], str, str]:
    fetched_at = datetime.now(timezone.utc).isoformat()
    try:
        request = urllib.request.Request(url, headers=DEFAULT_HEADERS)
        with urllib.request.urlopen(request, timeout=timeout) as response:
            charset = response.headers.get_content_charset() or "utf-8"
            text = response.read().decode(charset, errors="replace")
            status = f"{response.status} {response.reason}"
            return text, status, fetched_at
    except urllib.error.HTTPError as exc:
        LOGGER.error("HTTP error fetching %s: %s", url, exc)
        return None, f"HTTPError:{exc.code}", fetched_at
    except urllib.error.URLError as exc:
        LOGGER.error("URL error fetching %s: %s", url, exc)
        return None, f"URLError:{exc.reason}", fetched_at
    except Exception as exc:  # noqa: BLE001
        LOGGER.exception("Unexpected error fetching %s", url)
        return None, f"Error:{exc}", fetched_at


def extract_packages(text: str, pattern: Pattern[str] = PACKAGE_PATTERN) -> Dict[str, Dict[str, set]]:
    results: Dict[str, Dict[str, set]] = defaultdict(lambda: defaultdict(set))
    for match in pattern.finditer(text):
        name = match.group("name")
        version = normalize_version(match.group("version"))
        if not version:
            continue
        results[name][version]
    return results


def normalize_version(version: str) -> Optional[str]:
    if not version:
        return None
    version = version.strip()
    if version.startswith("v") and version[1:2].isdigit():
        version = version[1:]
    if version.endswith(('.', ',', ';')):
        version = version.rstrip('.,;')
    return version or None


TAG_PATTERN = re.compile(r"<[^>]+>")


def html_to_text(fragment: str) -> str:
    return TAG_PATTERN.sub('', fragment).strip()


def split_versions(text: str) -> List[str]:
    if not text:
        return []
    return [normalize_version(v) for v in VERSION_PATTERN.findall(text)]


def parse_stepsecurity(html_text: str) -> Dict[str, set]:
    packages: Dict[str, set] = defaultdict(set)
    pattern = re.compile(
        r'<td[^>]*class="package-name"[^>]*>(.*?)</td>\s*<td[^>]*class="versions"[^>]*>(.*?)</td>',
        re.IGNORECASE | re.DOTALL,
    )
    for pkg_html, version_html in pattern.findall(html_text):
        package = html_to_text(html.unescape(pkg_html))
        versions = split_versions(html.unescape(version_html))
        if package and versions:
            packages[package].update(filter(None, versions))
    return packages


def parse_ox_security(html_text: str) -> Dict[str, set]:
    packages: Dict[str, set] = defaultdict(set)
    table_match = re.search(
        r'<table[^>]*class="[^"]*has-fixed-layout[^"]*"[^>]*>(.*?)</table>',
        html_text,
        re.IGNORECASE | re.DOTALL,
    )
    if not table_match:
        return packages
    table_html = table_match.group(1)
    for row_html in re.findall(r'<tr>(.*?)</tr>', table_html, re.IGNORECASE | re.DOTALL):
        cells = re.findall(r'<t[dh][^>]*>(.*?)</t[dh]>', row_html, re.IGNORECASE | re.DOTALL)
        if len(cells) < 2:
            continue
        package = html_to_text(html.unescape(cells[0]))
        if package.lower() == 'package':  # header row
            continue
        versions = split_versions(html.unescape(cells[1]))
        if package and versions:
            packages[package].update(filter(None, versions))
    return packages


def parse_wiz(html_text: str) -> Dict[str, set]:
    packages: Dict[str, set] = defaultdict(set)
    for item_html in re.findall(
        r'<li>\s*<p[^>]*class="my-0"[^>]*>(.*?)</p>\s*</li>',
        html_text,
        re.IGNORECASE | re.DOTALL,
    ):
        text = html_to_text(html.unescape(item_html))
        if not text:
            continue
        pkg_match = re.match(r'(@?[A-Za-z0-9_.\-]+(?:/[A-Za-z0-9_.\-]+)?)', text)
        if not pkg_match:
            continue
        package = pkg_match.group(1)
        versions = split_versions(text)
        if package and versions:
            packages[package].update(filter(None, versions))
    return packages


PARSER_REGISTRY: Dict[str, Callable[[str], Dict[str, set]]] = {
    "stepsecurity_table": parse_stepsecurity,
    "ox_table": parse_ox_security,
    "wiz_list": parse_wiz,
}

SUPPORTED_PARSER_HINTS = tuple(PARSER_REGISTRY.keys())
VALID_SOURCE_KEYS = {"url", "parser"}

URL_PARSER_HINTS: List[Tuple[str, Callable[[str], Dict[str, set]]]] = [
    ("stepsecurity.io", parse_stepsecurity),
    ("ox.security", parse_ox_security),
    ("wiz.io", parse_wiz),
]


def get_special_parser(url: str, parser_key: Optional[str]) -> Optional[Callable[[str], Dict[str, set]]]:
    if parser_key:
        parser = PARSER_REGISTRY.get(parser_key)
        if parser is None:
            LOGGER.warning("Unknown parser '%s' for %s; falling back to automatic extraction.", parser_key, url)
        return parser
    for marker, parser in URL_PARSER_HINTS:
        if marker in url:
            return parser
    return None


def load_sources_config(path: Path) -> List[SourceConfig]:
    config_path = path.expanduser().resolve()
    if not config_path.is_file():
        raise FileNotFoundError(f"Sources configuration not found: {config_path}")

    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:  # noqa: BLE001 - surfacing config issues
        raise ValueError(f"Invalid JSON in sources configuration {config_path}: {exc}") from exc

    raw_sources = data.get("sources") if isinstance(data, dict) else None
    if not isinstance(raw_sources, list):
        raise ValueError("Sources configuration must contain a 'sources' array.")

    entries: List[SourceConfig] = []
    for item in raw_sources:
        if isinstance(item, str):
            entries.append(SourceConfig(url=item))
        elif isinstance(item, dict):
            unknown_keys = set(item.keys()) - VALID_SOURCE_KEYS
            if unknown_keys:
                raise ValueError(
                    f"Unknown keys {sorted(unknown_keys)} in sources configuration entry: {item}"
                )
            url = item.get("url")
            parser_key = item.get("parser")
            if not isinstance(url, str) or not url.strip():
                LOGGER.warning("Skipping source entry without valid URL: %s", item)
                continue
            parser_value: Optional[str]
            if parser_key is None:
                parser_value = None
            elif isinstance(parser_key, str):
                parser_key = parser_key.strip()
                if parser_key and parser_key not in PARSER_REGISTRY:
                    raise ValueError(
                        f"Unsupported parser hint '{parser_key}' for source {url}. "
                        f"Supported values: {', '.join(SUPPORTED_PARSER_HINTS)}"
                    )
                parser_value = parser_key or None
            else:
                raise ValueError(
                    f"Parser hint for {url} must be a string if provided (got {type(parser_key).__name__})."
                )
            entries.append(SourceConfig(url=url.strip(), parser=parser_value))
        else:
            LOGGER.warning("Skipping unsupported source entry: %s", item)

    if not entries:
        raise ValueError("No valid sources defined in configuration.")

    LOGGER.info("Loaded %s source definitions from %s", len(entries), config_path)
    return entries


def build_package_mapping(package_versions: Dict[str, Iterable[str]], source_url: str) -> Dict[str, Dict[str, set]]:
    mapping: Dict[str, Dict[str, set]] = defaultdict(lambda: defaultdict(set))
    for package, versions in package_versions.items():
        if not package:
            continue
        package = package.strip()
        if not package:
            continue
        for version in versions:
            normalized = normalize_version(version)
            if not normalized:
                continue
            mapping[package][normalized].add(source_url)
    return mapping


def ensure_source_record(packages: Dict[str, Dict[str, set]], url: str) -> None:
    for pkg_versions in packages.values():
        for sources in pkg_versions.values():
            sources.add(url)


def consolidate(sources_data: Iterable[SourceResult]) -> List[Dict[str, object]]:
    aggregate: Dict[str, Dict[str, set]] = defaultdict(lambda: defaultdict(set))
    for source in sources_data:
        for pkg, versions in source.packages.items():
            for version in versions:
                aggregate[pkg][version].add(source.url)

    items: List[Dict[str, object]] = []
    for pkg in sorted(aggregate):
        for version in sorted(aggregate[pkg]):
            items.append(
                {
                    "package": pkg,
                    "version": version,
                    "source_links": sorted(aggregate[pkg][version]),
                }
            )
    return items


def write_output(
    items: List[Dict[str, object]],
    sources_meta: List[Dict[str, object]],
    output_path: Path,
) -> None:
    packages_set = {item["package"] for item in items}
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sources": sources_meta,
        "counts": {
            "items": len(items),
            "packages": len(packages_set),
        },
        "items": items,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def fetch_sources(
    config_path: Path,
    output_path: Path,
    timeout: int,
    log_dir: Path,
    log_level: str,
) -> Dict[str, object]:
    log_path = setup_logging(log_dir, log_level)

    source_entries = load_sources_config(config_path)

    results: List[SourceResult] = []

    for entry in source_entries:
        url = entry.url
        LOGGER.info("Fetching %s", url)
        text, status, fetched_at = fetch_url(url, timeout=timeout)

        parser_func = None
        parser_label: Optional[str]

        if text:
            parser_func = get_special_parser(url, entry.parser)
            if parser_func:
                packages_raw = parser_func(text)
                packages = build_package_mapping(packages_raw, url)
                parser_label = entry.parser or parser_func.__name__
            else:
                packages = extract_packages(text)
                ensure_source_record(packages, url)
                parser_label = "auto" if entry.parser is None else f"auto({entry.parser})"
        else:
            packages = defaultdict(lambda: defaultdict(set))
            parser_label = entry.parser

        if not text:
            LOGGER.warning("No content retrieved from %s (%s)", url, status)

        results.append(
            SourceResult(
                url=url,
                fetched_at=fetched_at,
                status=status,
                parser=parser_label,
                packages=packages,
            )
        )

        LOGGER.info(
            "Source %s yielded %s packages across %s versions.",
            url,
            len(packages),
            sum(len(version_map) for version_map in packages.values()),
        )

    items = consolidate(results)

    sources_meta = [
        {
            "url": result.url,
            "fetched_at": result.fetched_at,
            "status": result.status,
            "parser": result.parser,
            "packages_found": sum(len(version_map) for version_map in result.packages.values()),
        }
        for result in results
    ]

    successes = sum(1 for result in results if result.succeeded())
    failures = len(results) - successes
    LOGGER.info("Fetch summary: %s sources succeeded, %s failed.", successes, failures)

    output_path = output_path.expanduser().resolve()
    write_output(items, sources_meta, output_path)
    package_total = len({item["package"] for item in items})
    LOGGER.info(
        "Wrote %s items covering %s packages to %s",
        len(items),
        package_total,
        output_path,
    )

    return {
        "output_path": output_path,
        "log_path": log_path,
        "counts": {
            "items": len(items),
            "packages": package_total,
        },
        "sources": sources_meta,
    }


def setup_logging(log_dir: Path, level: str) -> Path:
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"shai_hulud_fetch_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.log"

    numeric_level = getattr(logging, level.upper(), logging.INFO)

    root_logger = logging.getLogger()
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    root_logger.setLevel(numeric_level)

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(numeric_level)
    file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))

    console_handler = logging.StreamHandler()
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))

    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    LOGGER.debug("Logging configured at %s", log_path)
    return log_path


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fetch Shai-Hulud compromised packages.")
    parser.add_argument(
        "--output",
        default="data/compromised_shaihulud.json",
        help="Output JSON path (default: data/compromised_shaihulud.json)",
    )
    parser.add_argument(
        "--config",
        default=str(CONFIG_DEFAULT_PATH),
        help="Path to the sources configuration file (default: config/shai_hulud_sources.json)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging verbosity (default: INFO)",
    )
    parser.add_argument(
        "--log-dir",
        default="logs/fetch",
        help="Directory where fetch logs are written (default: logs/fetch)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="HTTP request timeout in seconds (default: 30)",
    )
    parser.add_argument(
        "--show-parsers",
        action="store_true",
        help="List available parser hints and exit.",
    )
    return parser.parse_args(argv)


def run(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.show_parsers:
        print("Supported parser hints:")
        for hint in SUPPORTED_PARSER_HINTS:
            print(f"- {hint}")
        return 0
    config_path = Path(args.config)
    output_path = Path(args.output)
    log_dir = Path(args.log_dir)

    fetch_sources(
        config_path=config_path,
        output_path=output_path,
        timeout=args.timeout,
        log_dir=log_dir,
        log_level=args.log_level,
    )
    return 0


if __name__ == "__main__":
    sys.exit(run())
