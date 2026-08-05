"""
Tests for crawler.py

Uses requests_mock to simulate a small multi-page site with forms,
so we can verify crawling and form-extraction logic without needing
a live server.
"""

import unittest
import requests_mock
from src.scanner.crawler import crawl, is_internal_link, extract_forms
from bs4 import BeautifulSoup


class TestIsInternalLink(unittest.TestCase):

    def test_relative_link_is_internal(self):
        self.assertTrue(is_internal_link("http://test.com", "/about"))

    def test_same_domain_is_internal(self):
        self.assertTrue(is_internal_link("http://test.com", "http://test.com/contact"))

    def test_external_domain_is_not_internal(self):
        self.assertFalse(is_internal_link("http://test.com", "http://evil.com/page"))


class TestExtractForms(unittest.TestCase):

    def test_extracts_form_fields(self):
        html = """
        <form action="/login" method="post">
            <input name="username" type="text">
            <input name="password" type="password">
        </form>
        """
        soup = BeautifulSoup(html, "html.parser")
        forms = extract_forms(soup, "http://test.com/login-page")

        self.assertEqual(len(forms), 1)
        self.assertEqual(forms[0]["action"], "/login")
        self.assertEqual(forms[0]["method"], "post")
        self.assertEqual(len(forms[0]["fields"]), 2)


class TestCrawl(unittest.TestCase):

    def test_crawls_linked_internal_pages(self):
        home_html = '<html><body><a href="/about">About</a></body></html>'
        about_html = """
        <html><body>
            <form action="/subscribe" method="get">
                <input name="email" type="text">
            </form>
        </body></html>
        """

        with requests_mock.Mocker() as m:
            m.get("http://test.com", text=home_html, headers={"Content-Type": "text/html"})
            m.get("http://test.com/about", text=about_html, headers={"Content-Type": "text/html"})

            result = crawl("http://test.com", max_pages=5)

        self.assertIn("http://test.com", result["visited_pages"])
        self.assertIn("http://test.com/about", result["visited_pages"])
        self.assertEqual(len(result["forms"]), 1)
        self.assertEqual(result["forms"][0]["action"], "/subscribe")

    def test_does_not_follow_external_links(self):
        home_html = '<html><body><a href="http://evil.com/page">External</a></body></html>'

        with requests_mock.Mocker() as m:
            m.get("http://test.com", text=home_html, headers={"Content-Type": "text/html"})

            result = crawl("http://test.com", max_pages=5)

        self.assertEqual(len(result["visited_pages"]), 1)
        self.assertNotIn("http://evil.com/page", result["visited_pages"])


if __name__ == "__main__":
    unittest.main()
