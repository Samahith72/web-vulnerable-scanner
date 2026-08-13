"""
Tests for report.py
"""

import os
import unittest
import tempfile
from src.scanner.report import generate_html_report, _severity_badge, _summary_bar


class TestSeverityBadge(unittest.TestCase):

    def test_high_badge_contains_severity(self):
        badge = _severity_badge("High")
        self.assertIn("High", badge)

    def test_badge_is_html(self):
        badge = _severity_badge("Medium")
        self.assertIn("<span", badge)


class TestSummaryBar(unittest.TestCase):

    def test_counts_severities_correctly(self):
        findings = [
            {"severity": "High"},
            {"severity": "High"},
            {"severity": "Medium"},
            {"severity": "Low"},
        ]
        bar = _summary_bar(findings)
        # Should show count of 2 for High
        self.assertIn(">2<", bar)

    def test_empty_findings_shows_zeros(self):
        bar = _summary_bar([])
        self.assertIn(">0<", bar)


class TestGenerateHtmlReport(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.output_path = os.path.join(self.test_dir, "test_report.html")

    def test_report_file_is_created(self):
        generate_html_report([], "http://test.com", self.output_path)
        self.assertTrue(os.path.exists(self.output_path))

    def test_report_contains_target(self):
        generate_html_report([], "http://test.com", self.output_path)
        with open(self.output_path) as f:
            content = f.read()
        self.assertIn("http://test.com", content)

    def test_report_contains_findings(self):
        findings = [{
            "check": "Missing Header: X-Frame-Options",
            "severity": "Medium",
            "description": "Clickjacking risk",
            "recommendation": "Add X-Frame-Options header",
        }]
        generate_html_report(findings, "http://test.com", self.output_path)
        with open(self.output_path) as f:
            content = f.read()
        self.assertIn("X-Frame-Options", content)
        self.assertIn("Clickjacking risk", content)

    def test_report_sorted_by_severity(self):
        findings = [
            {"check": "Low finding", "severity": "Low",
             "description": "d", "recommendation": "r"},
            {"check": "High finding", "severity": "High",
             "description": "d", "recommendation": "r"},
        ]
        generate_html_report(findings, "http://test.com", self.output_path)
        with open(self.output_path) as f:
            content = f.read()
        # High should appear before Low in the document
        self.assertLess(content.index("High finding"), content.index("Low finding"))

    def test_empty_findings_shows_no_vulnerabilities_message(self):
        generate_html_report([], "http://test.com", self.output_path)
        with open(self.output_path) as f:
            content = f.read()
        self.assertIn("No vulnerabilities found", content)

    def tearDown(self):
        if os.path.exists(self.output_path):
            os.remove(self.output_path)


if __name__ == "__main__":
    unittest.main()
