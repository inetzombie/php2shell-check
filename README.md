# php2shell-check

A **safe, passive, read-only** detector for the PHP2Shell CVEs
(**CVE-2026-109618** and **CVE-2026-109619**) — a pair of critical
unauthenticated RCE bugs in PHP core affecting versions **5.4 through 8.5.11**.

This tool does **banner / version-based detection only**. It reads the PHP
version a server *already discloses* and tells you whether that version falls
inside the affected range. It is a defensive triage aid, not an exploit.

> ⚠️ **AUTHORIZED USE ONLY.** Run this only against sites you own or are
> explicitly authorized to assess. It only reads self-disclosed version
> information, but you are still responsible for where you point it.

## What it does

1. Makes **one** ordinary `GET` request to the URL you provide, with a clear
   User-Agent (`php2shell-check/1.0 (defensive scanner)`).
2. Reads the PHP version from signals the server discloses on its own:
   - the `X-Powered-By` header (e.g. `PHP/8.1.2`)
   - the `Server` header (e.g. `Apache/2.4.57 PHP/7.4.33`)
   - `Set-Cookie` — presence of `PHPSESSID` (confirms PHP is in use; no version)
   - a phpinfo-style `PHP Version x.y.z` string in a page the site returns itself
3. Parses that version and compares it against the affected range
   (`>= 5.4.0`, `<= 8.5.11`), printing one of:
   - **VULNERABLE** — disclosed version is inside the affected range
   - **LIKELY SAFE** — disclosed version is above the affected range
   - **UNKNOWN** — no version was disclosed (this is *not* evidence of safety)
4. Prints a disclaimer every run (text mode).

## What it does NOT do

This is the important part. The tool **never**:

- exploits either CVE, or any other vulnerability;
- sends crafted, multipart, or malicious payloads;
- fuzzes inputs or deliberately forces errors to coax out a version;
- attempts code execution of any kind;
- writes, uploads, or injects **anything** to the target — including any
  marketing string, token ticker, or "demo" message;
- logs in, brute-forces, or follows any authenticated flow.

It observes what is already in the response to a single, plain `GET`. That's it.

## About the affected range

PHP core versions **5.4 → 8.5.11** are documented as affected. The exact
**patched** release should be confirmed from the official source
(<https://www.php.net/ChangeLog-8.php> and the php.net security advisories).
Until then this tool treats **8.5.11 as the last-affected version**: anything
strictly greater is reported `LIKELY SAFE`. If php.net later states a different
fixed version, update `MAX_AFFECTED` in `php2shell_check/version_range.py`.

Note also that a disclosed version can be inaccurate (distros backport security
fixes without bumping the version string), so `VULNERABLE` means
"version string is in range — investigate", not "proven exploitable".

## Install

```bash
pip install -r requirements.txt   # just: requests
```

Python 3.8+. Standard library only, plus `requests` for the single HTTP call.

## Usage

```bash
# scan one host
python -m php2shell_check https://example.com

# JSON output
python -m php2shell_check https://example.com --json

# scan a file of YOUR OWN domains (one per line), rate-limited
python -m php2shell_check --domains examples.txt --rate-limit 2

# for a host you own, skip the robots.txt courtesy check
python -m php2shell_check https://mysite.test --ignore-robots
```

Options: `--json`, `--user-agent`, `--timeout`, `--rate-limit`,
`--ignore-robots`, `--version`.

- Only **one host per invocation** unless you pass `--domains` with a file of
  your own domains.
- `robots.txt` is fetched once and respected (fails open if unreachable).
- A rate limit (default 2s) spaces out requests when scanning a domains file.
- Exit code is `1` if any target is `VULNERABLE`, else `0`.

## Sample output

Live runs against two real public sites (plain `GET`, no exploitation). Both
suppress `expose_php`, so no version is disclosed — a realistic, honest result
that shows good version-hiding hygiene on their part:

```
$ python -m php2shell_check https://wordpress.org
DISCLAIMER: php2shell-check only reads PHP version information that a server
already discloses (headers, cookies, self-returned pages). It does NOT exploit,
fuzz, force errors, or write anything to the target. Use it ONLY on sites you
own or are explicitly authorized to assess.

[UNKNOWN]      https://wordpress.org
    HTTP status : 200
    PHP version : unknown
    PHP detected: no
    disclosed signals: none
    -> no PHP version disclosed; cannot determine. Not evidence of safety.
```

```
$ python -m php2shell_check https://www.php.net --json
[
  {
    "url": "https://www.php.net",
    "status": "UNKNOWN",
    "php_version": "unknown",
    "php_detected": false,
    "http_status": 200,
    "signals": {},
    "error": null
  }
]
```

For reference, a host that *does* disclose its version prints like this (shape
shown by the test suite, which mocks the HTTP responses):

```
[VULNERABLE]   https://example.test
    HTTP status : 200
    PHP version : 8.1.2
    PHP detected: yes
    disclosed signals:
      - X-Powered-By: PHP/8.1.2
    -> version is within the affected range (5.4.0 - 8.5.11 (inclusive)).
```

## Tests

No live exploitation happens anywhere in the tests. HTTP responses are mocked,
covering the VULNERABLE, LIKELY SAFE, and UNKNOWN cases, header/body parsing,
and the CLI.

```bash
python -m unittest discover -s tests
```

## Project layout

```
php2shell_check/
  version_range.py   # parse PHP version, classify against affected range
  scanner.py         # passive signal extraction + single-GET fetch (pure core)
  robots.py          # robots.txt courtesy check
  cli.py             # argparse CLI, output formatting, disclaimer
tests/               # mocked-response unit tests (no network, no exploit)
```

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 der_zuhalter.
