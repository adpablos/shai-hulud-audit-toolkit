"""Terminal output formatters with color and emoji support."""
from __future__ import annotations

import logging
import os
import sys


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
        """Format log record with colors."""
        levelname = record.levelname
        if Colors._enabled:
            color = self.LEVEL_COLORS.get(record.levelno, "")
            record.levelname = Colors.colorize(levelname, color)
        result = super().format(record)
        record.levelname = levelname
        return result


def determine_risk_level(findings: list) -> str:
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
