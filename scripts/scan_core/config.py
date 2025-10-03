"""Configuration constants and patterns for Shai-Hulud scanning."""
from pathlib import Path
from typing import Dict, List, Set

# Project paths
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ADVISORY_FILE = PROJECT_ROOT / "data" / "compromised_packages_snapshot.json"
ENV_ADVISORY_PATH = "SHAI_HULUD_ADVISORY"

# Cache configuration
CACHE_SOURCE = "npm-cache"

# Suppressed warnings
SUPPRESSED_WARNING_SUBSTRINGS = (
    "resolve/test/resolver/malformed_package_json/package.json",
)

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
SUSPICIOUS_CODE_PATTERNS: Dict[str, Dict[str, object]] = {
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
EXFILTRATION_INDICATORS: Dict[str, List[str]] = {
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
