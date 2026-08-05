# Architecture

## Crawler Limitations

The crawler uses `requests` + BeautifulSoup, which only sees the initial
server-rendered HTML. Modern single-page applications (SPAs) like OWASP
Juice Shop render their content client-side via JavaScript after page load,
so a static crawler sees an empty shell (`<div id="root"></div>`) and finds
no links or forms.

This was confirmed when crawling Juice Shop directly: 1 page visited,
0 forms found, despite the site having many pages and forms once rendered.

**Verified working** via unit tests with mocked server-rendered HTML
(see `tests/test_crawler.py`), confirming the crawling and form-extraction
logic itself is correct.

**Planned fix / stretch goal:** integrate Selenium or Playwright to render
JavaScript before parsing, enabling the crawler to work against modern SPAs.
