"""
Tests for js_check.py
"""

import unittest
import requests_mock
from src.scanner.js_check import extract_scripts, check_js_libraries


class TestExtractScripts(unittest.TestCase):

    def test_extracts_versioned_script(self):
        html = '<html><script src="/js/jquery-1.8.3.min.js"></script></html>'
        scripts = extract_scripts(html, "http://test.com", "http://test.com")
        self.assertEqual(len(scripts), 1)
        self.assertEqual(scripts[0]["name"], "jquery")
        self.assertEqual(scripts[0]["version"], "1.8.3")

    def test_ignores_unversioned_scripts(self):
        html = '<html><script src="/js/app.js"></script></html>'
        scripts = extract_scripts(html, "http://test.com", "http://test.com")
        self.assertEqual(len(scripts), 0)

    def test_extracts_multiple_scripts(self):
        html = """
        <html>
            <script src="/js/jquery-3.4.1.min.js"></script>
            <script src="/js/bootstrap-4.3.1.min.js"></script>
        </html>
        """
        scripts = extract_scripts(html, "http://test.com", "http://test.com")
        self.assertEqual(len(scripts), 2)
        names = [s["name"] for s in scripts]
        self.assertIn("jquery", names)
        self.assertIn("bootstrap", names)


class TestCheckJsLibraries(unittest.TestCase):

    def test_detects_vulnerable_jquery(self):
        html = '<html><script src="/js/jquery-1.8.3.min.js"></script></html>'

        with requests_mock.Mocker() as m:
            m.get("http://test.com/page",
                  text=html,
                  headers={"Content-Type": "text/html"})
            findings = check_js_libraries(["http://test.com/page"], "http://test.com")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check"], "Outdated JS Library")
        self.assertEqual(findings[0]["severity"], "High")
        self.assertIn("jquery", findings[0]["description"])
        self.assertIn("1.8.3", findings[0]["description"])

    def test_no_finding_for_unknown_library(self):
        html = '<html><script src="/js/myapp-1.0.0.js"></script></html>'

        with requests_mock.Mocker() as m:
            m.get("http://test.com/page",
                  text=html,
                  headers={"Content-Type": "text/html"})
            findings = check_js_libraries(["http://test.com/page"], "http://test.com")

        self.assertEqual(findings, [])

    def test_no_duplicate_findings_across_pages(self):
        """Same library on multiple pages should only produce one finding."""
        html = '<html><script src="/js/jquery-1.8.3.min.js"></script></html>'

        with requests_mock.Mocker() as m:
            m.get("http://test.com/page1", text=html, headers={"Content-Type": "text/html"})
            m.get("http://test.com/page2", text=html, headers={"Content-Type": "text/html"})
            findings = check_js_libraries(
                ["http://test.com/page1", "http://test.com/page2"],
                "http://test.com"
            )

        self.assertEqual(len(findings), 1)

    def test_empty_pages_list(self):
        findings = check_js_libraries([], "http://test.com")
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
