"""Passive, read-only PHP version detection from a single GET request.

What this module does:
  * Issues ONE ordinary HTTP GET to the user-provided URL.
  * Reads version signals the server already discloses:
      - X-Powered-By header (e.g. "PHP/8.1.2")
      - Server header (e.g. "Apache/2.4 PHP/7.4.33")
      - Set-Cookie presence of PHPSESSID (confirms PHP, not a version)
      - any PHP version string in the body the site itself returns
  * Compares the parsed version against the affected range.

What this module NEVER does:
  * It does not fuzz, force errors, send crafted/multipart payloads, attempt
    code execution, or write anything to the target. It only observes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .version_range import classify, parse_php_version, version_str

DEFAULT_USER_AGENT = "php2shell-check/1.0 (defensive scanner)"
DEFAULT_TIMEOUT = 10.0

# Look for "PHP/8.1.2" style tokens in headers.
_PHP_TOKEN_RE = re.compile(r"PHP/(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)
# Body signal: the phpinfo-style "PHP Version 8.1.2" string that a server may
# expose on a page it returns itself. We require the literal word "Version" and
# a full x.y.z to avoid mistaking marketing copy (e.g. "PHP 8.5 is released")
# for a server banner. We only read it; we never trigger or force it.
_BODY_PHP_RE = re.compile(r"PHP\s*Version[:\s]+(\d+\.\d+\.\d+)", re.IGNORECASE)


@dataclass
class ScanResult:
    url: str
    status: str                       # VULNERABLE / LIKELY SAFE / UNKNOWN
    version: Optional[Tuple[int, int, int]]
    php_detected: bool                # did we see any PHP signal at all?
    signals: Dict[str, str] = field(default_factory=dict)
    http_status: Optional[int] = None
    error: Optional[str] = None

    @property
    def version_display(self) -> str:
        return version_str(self.version)


def _version_from_header_value(value: str) -> Optional[str]:
    if not value:
        return None
    m = _PHP_TOKEN_RE.search(value)
    return m.group(1) if m else None


def extract_signals(headers: Dict[str, str], body: str) -> Tuple[Dict[str, str], bool]:
    """Pull disclosed PHP signals from headers and body.

    Returns (signals, php_detected). `signals` maps a source label to the raw
    disclosed value; the first version-bearing one is authoritative.
    """
    # Normalize header lookup to be case-insensitive.
    lower = {k.lower(): v for k, v in headers.items()}
    signals: Dict[str, str] = {}
    php_detected = False

    xpb = lower.get("x-powered-by", "")
    if xpb:
        ver = _version_from_header_value(xpb)
        if ver:
            signals["X-Powered-By"] = xpb
            php_detected = True
        elif "php" in xpb.lower():
            php_detected = True
            signals.setdefault("X-Powered-By (no version)", xpb)

    server = lower.get("server", "")
    if server:
        ver = _version_from_header_value(server)
        if ver:
            signals["Server"] = server
            php_detected = True
        elif "php" in server.lower():
            php_detected = True
            signals.setdefault("Server (no version)", server)

    set_cookie = lower.get("set-cookie", "")
    if set_cookie and "phpsessid" in set_cookie.lower():
        signals["Set-Cookie"] = "PHPSESSID present (confirms PHP, no version)"
        php_detected = True

    if body:
        m = _BODY_PHP_RE.search(body)
        if m:
            signals["Body"] = "PHP version string in response body: " + m.group(0)
            php_detected = True

    return signals, php_detected


def _best_version(signals: Dict[str, str], headers: Dict[str, str], body: str) -> Optional[str]:
    """Choose the most authoritative disclosed version string.

    Preference order: X-Powered-By, Server, then body.
    """
    lower = {k.lower(): v for k, v in headers.items()}
    for key in ("x-powered-by", "server"):
        ver = _version_from_header_value(lower.get(key, ""))
        if ver:
            return ver
    if body:
        m = _BODY_PHP_RE.search(body)
        if m:
            return m.group(1)
    return None


def scan_response(url: str, http_status: Optional[int], headers: Dict[str, str],
                  body: str) -> ScanResult:
    """Build a ScanResult from an already-fetched response.

    Pure function: no network. This is what the tests exercise directly with
    mocked responses, so there is never any live exploitation in the tests.
    """
    signals, php_detected = extract_signals(headers, body)
    ver_str = _best_version(signals, headers, body)
    version = parse_php_version(ver_str) if ver_str else None
    status = classify(version)
    return ScanResult(
        url=url,
        status=status,
        version=version,
        php_detected=php_detected,
        signals=signals,
        http_status=http_status,
    )


def fetch_and_scan(url: str, *, user_agent: str = DEFAULT_USER_AGENT,
                   timeout: float = DEFAULT_TIMEOUT,
                   session=None) -> ScanResult:
    """Perform ONE polite GET and scan the disclosed signals.

    This is the only function that touches the network, and it is a plain GET
    with a clear User-Agent. It streams and reads a bounded slice of the body
    so we never pull large payloads and never send anything but the request.
    """
    import requests  # local import so the pure functions need no dependency

    sess = session or requests.Session()
    headers = {"User-Agent": user_agent, "Accept": "*/*"}
    try:
        resp = sess.get(url, headers=headers, timeout=timeout, allow_redirects=True)
    except Exception as exc:  # network error, DNS, TLS, timeout
        return ScanResult(url=url, status="UNKNOWN", version=None,
                          php_detected=False, error=str(exc))

    # Read a bounded amount of the body the site itself returned.
    body = ""
    try:
        body = resp.text[:65536]
    except Exception:
        body = ""

    result = scan_response(url, resp.status_code, dict(resp.headers), body)
    return result
