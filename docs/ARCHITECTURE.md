# Architecture

## Overview

The scanner is structured as a pipeline:
main.py
├── header_check.py → checks HTTP response headers
├── auth.py → handles authenticated sessions (e.g. DVWA login)
├── crawler.py → discovers pages and forms
└── xss_check.py → tests forms for reflected XSS

Each module returns a list of finding dicts in this standard shape:

```python
{
    "check":          "Name of the check",
    "severity":       "High / Medium / Low / Error",
    "description":    "What was found and why it matters",
    "recommendation": "How to fix it",
}
```

This makes it easy to pass all findings into a report generator later
regardless of which module produced them.

---

## Modules

### header_check.py
Sends a single GET request to the target and inspects response headers
for the presence of 5 key security headers. No crawling needed.
Maps to **OWASP A05:2021 – Security Misconfiguration**.

### auth.py
Handles login for targets that require authentication. Currently
implements DVWA login — fetches the CSRF user_token from the login
page first, then POSTs credentials + token and returns an authenticated
`requests.Session` with cookies set.

### crawler.py
Starts at a base URL and follows internal links up to a configurable
`max_pages` limit. Extracts all `<form>` tags and their input fields
from each page visited. Returns a structured map used by all detectors.

**Limitation:** Uses `requests` + BeautifulSoup (static HTML only).
Modern SPAs like OWASP Juice Shop render content via JavaScript after
page load, so the crawler sees an empty shell and finds no links or forms.
Verified working against server-rendered apps like DVWA.

**Planned fix / stretch goal:** Integrate Selenium or Playwright to render
JavaScript before parsing, enabling full SPA support.

### xss_check.py
Takes the form map from the crawler and submits a harmless but detectable
payload (`<script>xss_test_payload</script>`) into every text-like input
field. If the raw payload appears unescaped in the response HTML, the form
is reflecting unsanitized input and is flagged as a High severity finding.
Maps to **OWASP A03:2021 – Injection**.

---

## Practice Targets

| Target | URL | Notes |
|---|---|---|
| OWASP Juice Shop | http://localhost:3000 | Modern SPA — header checks only (crawler limitation) |
| DVWA | http://localhost:8080 | Server-rendered PHP — full scanning supported |

---

## Crawler Limitation Detail

Confirmed when crawling Juice Shop directly: 1 page visited, 0 forms found,
despite the site having many pages and forms once JavaScript renders them.
DVWA is used from Phase 3 onwards as the primary scan target because it is
server-rendered and the crawler works fully against it.
