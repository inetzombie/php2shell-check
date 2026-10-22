import io
import unittest
from contextlib import redirect_stdout

from php2shell_check import cli
from php2shell_check.scanner import ScanResult
from php2shell_check.version_range import LIKELY_SAFE, UNKNOWN, VULNERABLE


class TestNormalizeUrl(unittest.TestCase):
    def test_adds_https(self):
        self.assertEqual(cli._normalize_url("example.com"), "https://example.com")

    def test_keeps_scheme(self):
        self.assertEqual(cli._normalize_url("http://example.com"),
                         "http://example.com")


class TestPrintResult(unittest.TestCase):
    def _render(self, result):
        buf = io.StringIO()
        with redirect_stdout(buf):
            cli._print_result(result)
        return buf.getvalue()

    def test_vulnerable_output(self):
        r = ScanResult(url="https://x.test", status=VULNERABLE, version=(8, 1, 2),
                       php_detected=True, signals={"X-Powered-By": "PHP/8.1.2"},
                       http_status=200)
        out = self._render(r)
        self.assertIn("VULNERABLE", out)
        self.assertIn("8.1.2", out)

    def test_unknown_output_not_safe(self):
        r = ScanResult(url="https://x.test", status=UNKNOWN, version=None,
                       php_detected=False, signals={}, http_status=200)
        out = self._render(r)
        self.assertIn("UNKNOWN", out)
        self.assertIn("Not evidence of safety", out)


class TestMainWithStub(unittest.TestCase):
    def setUp(self):
        self._orig_fetch = cli.fetch_and_scan
        self._orig_robots = cli.robots_allows
        cli.robots_allows = lambda *a, **k: True

    def tearDown(self):
        cli.fetch_and_scan = self._orig_fetch
        cli.robots_allows = self._orig_robots

    def test_exit_code_vulnerable(self):
        cli.fetch_and_scan = lambda url, **k: ScanResult(
            url=url, status=VULNERABLE, version=(8, 1, 2), php_detected=True,
            signals={"X-Powered-By": "PHP/8.1.2"}, http_status=200)
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli.main(["example.test"])
        self.assertEqual(code, 1)

    def test_exit_code_safe(self):
        cli.fetch_and_scan = lambda url, **k: ScanResult(
            url=url, status=LIKELY_SAFE, version=(9, 0, 0), php_detected=True,
            signals={}, http_status=200)
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli.main(["example.test"])
        self.assertEqual(code, 0)

    def test_json_output(self):
        cli.fetch_and_scan = lambda url, **k: ScanResult(
            url=url, status=UNKNOWN, version=None, php_detected=False,
            signals={}, http_status=200)
        buf = io.StringIO()
        with redirect_stdout(buf):
            cli.main(["example.test", "--json"])
        out = buf.getvalue()
        self.assertIn('"status": "UNKNOWN"', out)


if __name__ == "__main__":
    unittest.main()
