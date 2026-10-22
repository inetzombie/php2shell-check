"""Minimal robots.txt courtesy check.

We fetch /robots.txt once and respect a Disallow that would cover the target
path for our User-Agent. This is a politeness measure for a tool that only
reads a single page; it is intentionally conservative.
"""

from __future__ import annotations

from urllib.parse import urlparse, urlunparse
from urllib.robotparser import RobotFileParser

from .scanner import DEFAULT_USER_AGENT, DEFAULT_TIMEOUT


def robots_allows(url: str, *, user_agent: str = DEFAULT_USER_AGENT,
                  timeout: float = DEFAULT_TIMEOUT, session=None) -> bool:
    """Return True if robots.txt permits fetching `url` (or has no opinion).

    Fails open on any error fetching robots.txt: a missing or unreachable
    robots file is treated as "no restriction", which is the standard reading.
    """
    import requests

    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return True
    robots_url = urlunparse((parsed.scheme, parsed.netloc, "/robots.txt", "", "", ""))

    sess = session or requests.Session()
    try:
        resp = sess.get(robots_url, headers={"User-Agent": user_agent},
                        timeout=timeout, allow_redirects=True)
        if resp.status_code >= 400:
            return True
        rp = RobotFileParser()
        rp.parse(resp.text.splitlines())
        return rp.can_fetch(user_agent, url)
    except Exception:
        return True
