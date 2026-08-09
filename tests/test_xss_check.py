"""
Tests for xss_check.py
"""

import unittest
import requests_mock
from src.scanner.xss_check import check_xss, XSS_PAYLOAD


class TestXSSCheck(unittest.TestCase):

    def _make_form(self, action, method="get"):
        return {
            "page": "http://test.com/page",
            "action": action,
            "method": method,
            "fields": [{"name": "input", "type": "text"}],
        }

    def test_detects_reflected_xss(self):
        """If payload is reflected unescaped in response, flag it."""
        form = self._make_form("/search")

        with requests_mock.Mocker() as m:
            # Response contains our payload unescaped
            m.get("http://test.com/search", text=f"<html>{XSS_PAYLOAD}</html>")
            findings = check_xss([form], "http://test.com")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check"], "Reflected XSS")
        self.assertEqual(findings[0]["severity"], "High")

    def test_no_finding_when_payload_escaped(self):
        """If payload is escaped in response, no finding."""
        form = self._make_form("/search")

        with requests_mock.Mocker() as m:
            # Response has the payload HTML-escaped — safe
            m.get("http://test.com/search",
                  text="<html>&lt;script&gt;xss_test_payload&lt;/script&gt;</html>")
            findings = check_xss([form], "http://test.com")

        self.assertEqual(len(findings), 0)

    def test_post_form_tested(self):
        """POST forms should also be tested."""
        form = self._make_form("/submit", method="post")

        with requests_mock.Mocker() as m:
            m.post("http://test.com/submit", text=f"<html>{XSS_PAYLOAD}</html>")
            findings = check_xss([form], "http://test.com")

        self.assertEqual(len(findings), 1)

    def test_empty_forms_list(self):
        """No forms = no findings."""
        findings = check_xss([], "http://test.com")
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
