"""
Tests for csrf_check.py
"""

import unittest
from src.scanner.csrf_check import check_csrf, has_csrf_token


class TestHasCsrfToken(unittest.TestCase):

    def test_detects_standard_csrf_field(self):
        fields = [
            {"name": "username", "type": "text"},
            {"name": "csrf_token", "type": "hidden"},
        ]
        self.assertTrue(has_csrf_token(fields))

    def test_detects_user_token_field(self):
        """DVWA uses 'user_token' as its CSRF field name."""
        fields = [{"name": "user_token", "type": "hidden"}]
        self.assertTrue(has_csrf_token(fields))

    def test_detects_hidden_field_with_token_in_name(self):
        fields = [{"name": "my_token_value", "type": "hidden"}]
        self.assertTrue(has_csrf_token(fields))

    def test_no_csrf_token_returns_false(self):
        fields = [
            {"name": "username", "type": "text"},
            {"name": "password", "type": "password"},
        ]
        self.assertFalse(has_csrf_token(fields))

    def test_empty_fields_returns_false(self):
        self.assertFalse(has_csrf_token([]))


class TestCheckCsrf(unittest.TestCase):

    def _make_form(self, method, fields):
        return {
            "page": "http://test.com/form-page",
            "action": "/submit",
            "method": method,
            "fields": fields,
        }

    def test_post_form_without_csrf_flagged(self):
        form = self._make_form("post", [
            {"name": "username", "type": "text"},
            {"name": "password", "type": "password"},
        ])
        findings = check_csrf([form])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check"], "Missing CSRF Token")
        self.assertEqual(findings[0]["severity"], "High")

    def test_post_form_with_csrf_not_flagged(self):
        form = self._make_form("post", [
            {"name": "username", "type": "text"},
            {"name": "csrf_token", "type": "hidden"},
        ])
        findings = check_csrf([form])
        self.assertEqual(findings, [])

    def test_get_form_not_checked(self):
        """GET forms should never be flagged for missing CSRF."""
        form = self._make_form("get", [
            {"name": "search", "type": "text"},
        ])
        findings = check_csrf([form])
        self.assertEqual(findings, [])

    def test_empty_forms_list(self):
        self.assertEqual(check_csrf([]), [])

    def test_multiple_forms_flags_correct_ones(self):
        forms = [
            self._make_form("post", [{"name": "email", "type": "text"}]),
            self._make_form("post", [{"name": "csrf_token", "type": "hidden"}]),
            self._make_form("get", [{"name": "q", "type": "text"}]),
        ]
        findings = check_csrf(forms)
        self.assertEqual(len(findings), 1)


if __name__ == "__main__":
    unittest.main()
