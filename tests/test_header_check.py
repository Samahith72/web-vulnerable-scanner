"""
Tests for header_check.py

Uses requests_mock to simulate HTTP responses so tests don't
depend on a live server being available.
"""

import unittest
import requests_mock
from src.scanner.header_check import check_headers


class TestHeaderCheck(unittest.TestCase):

    def test_all_headers_present(self):
        """If all security headers exist, there should be no findings."""
        url = "http://test-site.com"
        good_headers = {
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "Strict-Transport-Security": "max-age=63072000",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        }

        with requests_mock.Mocker() as m:
            m.get(url, headers=good_headers)
            findings = check_headers(url)

        self.assertEqual(findings, [])

    def test_missing_headers_detected(self):
        """If headers are missing, they should show up as findings."""
        url = "http://test-site.com"

        with requests_mock.Mocker() as m:
            m.get(url, headers={})  # no security headers at all
            findings = check_headers(url)

        self.assertEqual(len(findings), 5)
        checked_names = [f["check"] for f in findings]
        self.assertIn("Missing Header: Content-Security-Policy", checked_names)

    def test_connection_error_handled(self):
        """If the target is unreachable, it should return an Error finding, not crash."""
        url = "http://unreachable-site.invalid"

        with requests_mock.Mocker() as m:
            import requests
            m.get(url, exc=requests.exceptions.ConnectionError)
            findings = check_headers(url)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "Error")


if __name__ == "__main__":
    unittest.main()
