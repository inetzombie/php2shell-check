"""Command-line interface for php2shell-check.

Usage:
    python -m php2shell_check <url>
    python -m php2shell_check --domains my-own-domains.txt
    python -m php2shell_check <url> --json

Safety:
    This tool only reads self-disclosed PHP version information from a single
    polite GET. It never exploits, never sends crafted payloads, and never
    writes to the target. Use it only on sites you own or are authorized to
    assess.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import List
from urllib.parse import urlparse

from . import __version__
from .robots import robots_allows
from .scanner import (DEFAULT_TIMEOUT, DEFAULT_USER_AGENT, ScanResult,
                      fetch_and_scan)
from .version_range import LIKELY_SAFE, MAX_AFFECTED, MIN_AFFECTED, UNKNOWN, VULNERABLE
from .version_range import version_str

DISCLAIMER = (
    "DISCLAIMER: php2shell-check only reads PHP version information that a "
    "server already discloses (headers, cookies, self-returned pages). It does "
    "NOT exploit, fuzz, force errors, or write anything to the target. Use it "
    "ONLY on sites you own or are explicitly authorized to assess."
)

_RANGE = "%s - %s (inclusive)" % (version_str(MIN_AFFECTED), version_str(MAX_AFFECTED))


def _normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return raw
    parsed = urlparse(raw)
    if not parsed.scheme:
        return "https://" + raw
    return raw


def _load_domains(path: str) -> List[str]:
    out: List[str] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            out.append(_normalize_url(line))
    return out


_STATUS_LABEL = {
    VULNERABLE: "[VULNERABLE]   ",
    LIKELY_SAFE: "[LIKELY SAFE]  ",
    UNKNOWN: "[UNKNOWN]      ",
}


def _print_result(result: ScanResult) -> None:
    label = _STATUS_LABEL.get(result.status, "[?] ")
    print("%s%s" % (label, result.url))
    if result.error:
        print("    error: %s" % result.error)
        return
    print("    HTTP status : %s" % result.http_status)
    print("    PHP version : %s" % result.version_display)
    print("    PHP detected: %s" % ("yes" if result.php_detected else "no"))
    if result.signals:
        print("    disclosed signals:")
        for src, val in result.signals.items():
            print("      - %s: %s" % (src, val))
    else:
        print("    disclosed signals: none")
    if result.status == VULNERABLE:
        print("    -> version is within the affected range (%s)." % _RANGE)
    elif result.status == LIKELY_SAFE:
        print("    -> version is outside the affected range (%s)." % _RANGE)
    else:
        print("    -> no PHP version disclosed; cannot determine. Not evidence of safety.")


def _result_to_dict(result: ScanResult) -> dict:
    return {
        "url": result.url,
        "status": result.status,
        "php_version": result.version_display,
        "php_detected": result.php_detected,
        "http_status": result.http_status,
        "signals": result.signals,
        "error": result.error,
    }


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="php2shell-check",
        description="Passive, read-only detector for the PHP2Shell CVEs "
                    "(CVE-2026-109618, CVE-2026-109619). Banner/version based only.",
        epilog=DISCLAIMER,
    )
    p.add_argument("url", nargs="?", help="single URL/host to scan")
    p.add_argument("--domains", metavar="FILE",
                   help="file of YOUR OWN domains (one per line) to scan")
    p.add_argument("--json", action="store_true", help="emit JSON instead of text")
    p.add_argument("--user-agent", default=DEFAULT_USER_AGENT,
                   help="override the User-Agent (default: %(default)s)")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                   help="per-request timeout seconds (default: %(default)s)")
    p.add_argument("--rate-limit", type=float, default=2.0, metavar="SECONDS",
                   help="minimum delay between hosts when using --domains "
                        "(default: %(default)s)")
    p.add_argument("--ignore-robots", action="store_true",
                   help="skip the robots.txt courtesy check (for hosts you own)")
    p.add_argument("--version", action="version",
                   version="php2shell-check " + __version__)
    return p


def scan_one(url: str, args) -> ScanResult:
    if not args.ignore_robots and not robots_allows(
            url, user_agent=args.user_agent, timeout=args.timeout):
        return ScanResult(url=url, status=UNKNOWN, version=None, php_detected=False,
                          error="robots.txt disallows this path; skipped "
                                "(use --ignore-robots for hosts you own)")
    return fetch_and_scan(url, user_agent=args.user_agent, timeout=args.timeout)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if not args.json:
        print(DISCLAIMER)
        print()

    targets: List[str]
    if args.domains:
        targets = _load_domains(args.domains)
        if not targets:
            print("No domains found in %s" % args.domains, file=sys.stderr)
            return 2
    elif args.url:
        targets = [_normalize_url(args.url)]
    else:
        build_parser().print_help()
        return 2

    results: List[ScanResult] = []
    for i, url in enumerate(targets):
        if i > 0 and args.rate_limit > 0:
            time.sleep(args.rate_limit)
        result = scan_one(url, args)
        results.append(result)
        if not args.json:
            _print_result(result)
            print()

    if args.json:
        print(json.dumps([_result_to_dict(r) for r in results], indent=2))

    # Exit code: 1 if any target is VULNERABLE, else 0.
    return 1 if any(r.status == VULNERABLE for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
