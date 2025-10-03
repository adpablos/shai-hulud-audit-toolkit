"""JSON output formatting."""
from __future__ import annotations

import json
from typing import List

from scripts.scan_core.models import Finding


def print_json_output(findings: List[Finding]) -> None:
    """Print findings as JSON."""
    print(json.dumps([f.to_dict() for f in findings], indent=2))
