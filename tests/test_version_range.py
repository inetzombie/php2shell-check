import unittest

from php2shell_check.version_range import (LIKELY_SAFE, UNKNOWN, VULNERABLE,
                                           classify, parse_php_version,
                                           version_str)


class TestParse(unittest.TestCase):
    def test_full_version(self):
        self.assertEqual(parse_php_version("PHP/8.1.2"), (8, 1, 2))

    def test_two_component(self):
        self.assertEqual(parse_php_version("8.5"), (8, 5, 0))

    def test_with_suffix(self):
        self.assertEqual(parse_php_version("7.4.33-1ubuntu"), (7, 4, 33))

    def test_none_when_no_number(self):
        # parse_php_version finds any version-shaped token; callers only feed
        # it PHP-labelled strings (see scanner._version_from_header_value),
        # so a string with no number returns None.
        self.assertIsNone(parse_php_version("nginx"))
        self.assertIsNone(parse_php_version("Apache Server"))

    def test_empty(self):
        self.assertIsNone(parse_php_version(""))
        self.assertIsNone(parse_php_version(None))


class TestClassify(unittest.TestCase):
    def test_vulnerable_lower_bound(self):
        self.assertEqual(classify((5, 4, 0)), VULNERABLE)

    def test_vulnerable_upper_bound(self):
        self.assertEqual(classify((8, 5, 11)), VULNERABLE)

    def test_vulnerable_mid(self):
        self.assertEqual(classify((7, 4, 33)), VULNERABLE)
        self.assertEqual(classify((8, 1, 2)), VULNERABLE)

    def test_safe_above_range(self):
        self.assertEqual(classify((8, 5, 12)), LIKELY_SAFE)
        self.assertEqual(classify((8, 6, 0)), LIKELY_SAFE)
        self.assertEqual(classify((9, 0, 0)), LIKELY_SAFE)

    def test_safe_below_range(self):
        self.assertEqual(classify((5, 3, 29)), LIKELY_SAFE)

    def test_unknown(self):
        self.assertEqual(classify(None), UNKNOWN)


class TestVersionStr(unittest.TestCase):
    def test_tuple(self):
        self.assertEqual(version_str((8, 1, 2)), "8.1.2")

    def test_none(self):
        self.assertEqual(version_str(None), "unknown")


if __name__ == "__main__":
    unittest.main()
