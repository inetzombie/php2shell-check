"""php2shell-check: a passive, read-only detector for the PHP2Shell CVEs.

CVE-2026-109618 and CVE-2026-109619 are unauthenticated RCE bugs in PHP core
affecting versions 5.4 through 8.5.11.

This package NEVER exploits, fuzzes, forces errors, or writes anything to a
target. It only reads version information a server already discloses.
"""

__version__ = "1.0"
