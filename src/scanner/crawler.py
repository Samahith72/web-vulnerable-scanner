"""
crawler.py

Crawls a target site starting from a base URL, discovering internal
pages and HTML forms. This map is used by later checks (XSS, CSRF)
to know what to test.
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


def is_internal_link(base_url: str, link: str) -> bool:
    """Returns True if `link` belongs to the same domain as `base_url`."""
    base_domain = urlparse(base_url).netloc
    link_domain = urlparse(link).netloc
    # A relative link (no netloc) is always internal
    return link_domain == "" or link_domain == base_domain


def extract_forms(soup: BeautifulSoup, page_url: str) -> list:
    """Extracts all forms on a page along with their input fields."""
    forms = []
    for form in soup.find_all("form"):
        fields = []
        for input_tag in form.find_all(["input", "textarea", "select"]):
            fields.append({
                "name": input_tag.get("name"),
                "type": input_tag.get("type", "text"),
            })

        forms.append({
            "page": page_url,
            "action": form.get("action", ""),
            "method": form.get("method", "get").lower(),
            "fields": fields,
        })
    return forms


def crawl(base_url: str, max_pages: int = 25) -> dict:
    """
    Crawls the site starting at base_url, up to max_pages.

    Returns:
        {
            "visited_pages": [...],
            "forms": [...]
        }
    """
    visited = set()
    to_visit = [base_url]
    all_forms = []

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)

        if url in visited:
            continue

        try:
            response = requests.get(url, timeout=5)
        except requests.exceptions.RequestException:
            continue  # skip pages that fail to load

        visited.add(url)

        # Only parse HTML responses
        content_type = response.headers.get("Content-Type", "")
        if "text/html" not in content_type:
            continue

        soup = BeautifulSoup(response.text, "html.parser")

        # Collect forms on this page
        all_forms.extend(extract_forms(soup, url))

        # Find new internal links to follow
        for link_tag in soup.find_all("a", href=True):
            full_url = urljoin(url, link_tag["href"])
            full_url = full_url.split("#")[0]  # strip fragments

            if is_internal_link(base_url, full_url) and full_url not in visited:
                to_visit.append(full_url)

    return {
        "visited_pages": list(visited),
        "forms": all_forms,
    }


if __name__ == "__main__":
    target = "http://localhost:3000"
    result = crawl(target, max_pages=15)

    print(f"\nCrawled {len(result['visited_pages'])} pages from {target}\n")
    for page in result["visited_pages"]:
        print(f"  {page}")

    print(f"\nFound {len(result['forms'])} forms:\n")
    for form in result["forms"]:
        print(f"  Page: {form['page']}")
        print(f"  Method: {form['method']}  Action: {form['action']}")
        print(f"  Fields: {form['fields']}\n")
