import unittest

from php2shell_check.scanner import (extract_signals, fetch_and_scan,
                                      scan_response)
from php2shell_check.version_range import LIKELY_SAFE, UNKNOWN, VULNERABLE


class FakeResponse:
    """Minimal stand-in for requests.Response (no network)."""
    def __init__(self, status_code=200, headers=None, text=""):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text


class FakeSession:
    """Returns a canned response (or raises) for a single GET; no network."""
    def __init__(self, response=None, exc=None):
        self._response = response
        self._exc = exc
        self.calls = []

    def get(self, url, headers=None, timeout=None, allow_redirects=True):
        self.calls.append((url, headers, timeout))
        if self._exc is not None:
            raise self._exc
        return self._response


class TestExtractSignals(unittest.TestCase):
    def test_x_powered_by_version(self):
        signals, detected = extract_signals({"X-Powered-By": "PHP/8.1.2"}, "")
        self.assertTrue(detected)
        self.assertIn("X-Powered-By", signals)

    def test_server_header_version(self):
        signals, detected = extract_signals(
            {"Server": "Apache/2.4.57 (Debian) PHP/7.4.33"}, "")
        self.assertTrue(detected)
        self.assertIn("Server", signals)

    def test_phpsessid_cookie_confirms_php_no_version(self):
        signals, detected = extract_signals(
            {"Set-Cookie": "PHPSESSID=abc123; path=/"}, "")
        self.assertTrue(detected)
        self.assertIn("Set-Cookie", signals)

    def test_no_php_signals(self):
        signals, detected = extract_signals(
            {"Server": "nginx/1.25.3"}, "<html>hi</html>")
        self.assertFalse(detected)
        self.assertEqual(signals, {})

    def test_case_insensitive_headers(self):
        signals, detected = extract_signals({"x-powered-by": "php/8.0.1"}, "")
        self.assertTrue(detected)


class TestScanResponseVulnerable(unittest.TestCase):
    def test_vulnerable_from_x_powered_by(self):
        r = scan_response("https://example.test", 200,
                          {"X-Powered-By": "PHP/8.1.2"}, "")
        self.assertEqual(r.status, VULNERABLE)
        self.assertEqual(r.version, (8, 1, 2))
        self.assertTrue(r.php_detected)

    def test_vulnerable_upper_bound(self):
        r = scan_response("https://example.test", 200,
                          {"X-Powered-By": "PHP/8.5.11"}, "")
        self.assertEqual(r.status, VULNERABLE)

    def test_vulnerable_from_body(self):
        body = "<h1>PHP Version 7.2.10</h1>"
        r = scan_response("https://example.test", 200, {}, body)
        self.assertEqual(r.status, VULNERABLE)
        self.assertEqual(r.version, (7, 2, 10))


class TestScanResponseSafe(unittest.TestCase):
    def test_safe_above_range(self):
        r = scan_response("https://example.test", 200,
                          {"X-Powered-By": "PHP/8.5.12"}, "")
        self.assertEqual(r.status, LIKELY_SAFE)
        self.assertEqual(r.version, (8, 5, 12))

    def test_safe_new_major(self):
        r = scan_response("https://example.test", 200,
                          {"X-Powered-By": "PHP/9.0.0"}, "")
        self.assertEqual(r.status, LIKELY_SAFE)


class TestScanResponseUnknown(unittest.TestCase):
    def test_unknown_no_disclosure(self):
        r = scan_response("https://example.test", 200,
                          {"Server": "nginx/1.25.3"}, "<html>ok</html>")
        self.assertEqual(r.status, UNKNOWN)
        self.assertIsNone(r.version)
        self.assertFalse(r.php_detected)

    def test_unknown_php_detected_but_no_version(self):
        # PHPSESSID confirms PHP but gives no version -> UNKNOWN status.
        r = scan_response("https://example.test", 200,
                          {"Set-Cookie": "PHPSESSID=xyz; path=/"}, "")
        self.assertEqual(r.status, UNKNOWN)
        self.assertTrue(r.php_detected)


class TestFetchAndScan(unittest.TestCase):
    def test_fetch_uses_single_get_and_ua(self):
        resp = FakeResponse(200, {"X-Powered-By": "PHP/8.1.2"}, "ok")
        sess = FakeSession(response=resp)
        r = fetch_and_scan("https://example.test", session=sess)
        self.assertEqual(r.status, VULNERABLE)
        self.assertEqual(len(sess.calls), 1)  # exactly ONE request
        _, headers, _ = sess.calls[0]
        self.assertIn("php2shell-check", headers["User-Agent"])

    def test_fetch_network_error_is_unknown(self):
        sess = FakeSession(exc=RuntimeError("dns failure"))
        r = fetch_and_scan("https://example.test", session=sess)
        self.assertEqual(r.status, UNKNOWN)
        self.assertIsNotNone(r.error)


if __name__ == "__main__":
    unittest.main()
