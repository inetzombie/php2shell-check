"""PHP version parsing and affected-range comparison.

The PHP2Shell CVEs (CVE-2026-109618, CVE-2026-109619) affect PHP core versions
from 5.4 through 8.5.11 inclusive. Until the exact patched release is confirmed
from php.net, we treat 8.5.11 as the last-affected version: anything strictly
greater than 8.5.11 is reported LIKELY SAFE.
"""

from __future__ import annotations

import re
from typing import Optional, Tuple

# Inclusive affected range. Confirm the exact fixed version from php.net; see README.
MIN_AFFECTED: Tuple[int, int, int] = (5, 4, 0)
MAX_AFFECTED: Tuple[int, int, int] = (8, 5, 11)

# Matches "8.5.11", "8.5", "7.4.33", optionally with trailing suffix like "-1ubuntu".
_VERSION_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")

VULNERABLE = "VULNERABLE"
LIKELY_SAFE = "LIKELY SAFE"
UNKNOWN = "UNKNOWN"


def parse_php_version(text: str) -> Optional[Tuple[int, int, int]]:
    """Extract a (major, minor, patch) tuple from a PHP version string.

    Returns None if no version-looking token is present. A missing patch
    component is treated as 0 (e.g. "8.5" -> (8, 5, 0)).
    """
    if not text:
        return None
    m = _VERSION_RE.search(text)
    if not m:
        return None
    major = int(m.group(1))
    minor = int(m.group(2))
    patch = int(m.group(3)) if m.group(3) is not None else 0
    return (major, minor, patch)


def classify(version: Optional[Tuple[int, int, int]]) -> str:
    """Classify a parsed version against the affected range."""
    if version is None:
        return UNKNOWN
    if version < MIN_AFFECTED:
        # PHP older than 5.4 is EOL and out of the documented affected range.
        return LIKELY_SAFE
    if version > MAX_AFFECTED:
        return LIKELY_SAFE
    return VULNERABLE


def version_str(version: Optional[Tuple[int, int, int]]) -> str:
    if version is None:
        return "unknown"
    return ".".join(str(p) for p in version)
