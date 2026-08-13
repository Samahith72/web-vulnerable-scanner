## Overview

The scanner is structured as a pipeline:

```
main.py
  ├── header_check.py  → checks HTTP response headers
  ├── auth.py          → handles authenticated sessions (e.g. DVWA login)
  ├── crawler.py       → discovers pages and forms
  ├── xss_check.py     → tests forms for reflected XSS
  ├── csrf_check.py    → checks POST forms for missing CSRF tokens
  ├── js_check.py      → detects outdated/vulnerable JS libraries
  └── report.py        → generates HTML report from all findings
```

Each scanner module returns a list of finding dicts in this standard shape:

```python
{
    "check":          "Name of the check",
    "severity":       "High / Medium / Low / Error",
    "description":    "What was found and why it matters",
    "recommendation": "How to fix it",
}
```

Findings are sorted by severity (High → Medium → Low) before display
and before being passed into the report generator.

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

**Planned stretch goal:** Integrate Selenium or Playwright for full
SPA support.

### xss_check.py
Takes the form map from the crawler and submits a harmless but detectable
payload into every text-like input field. If the raw payload appears
unescaped in the response HTML, the form is flagged as High severity.
Maps to **OWASP A03:2021 – Injection**.

### csrf_check.py
Inspects every POST form discovered by the crawler for the presence of
a CSRF token field. Checks field names against a list of known CSRF token
naming patterns used by popular frameworks. GET forms are skipped.
Maps to **OWASP A01:2021 – Broken Access Control**.

### js_check.py
Fetches each crawled page and inspects `<script src="...">` tags for
library name and version number in the filename. Matches against a local
vulnerability database of known-vulnerable versions with CVE references.
Deduplicates findings so the same library is only reported once.
Maps to **OWASP A06:2021 – Vulnerable and Outdated Components**.

### report.py
Collects all findings from every module and renders them into a
self-contained HTML file — no external dependencies needed to open it.
Includes a severity summary dashboard, color-coded finding cards, and
scan metadata (target, time, version). Report is sorted High → Low.

---

## Practice Targets

| Target | URL | Notes |
|---|---|---|
| OWASP Juice Shop | http://localhost:3000 | Header checks only (SPA limitation) |
| DVWA | http://localhost:8080 | Full scanning — all phases |

---

## Crawler Limitation Detail

Confirmed when crawling Juice Shop: 1 page visited, 0 forms found,
despite the site having many pages and forms once JavaScript renders them.
DVWA is the primary scan target from Phase 3 onwards because it is
server-rendered PHP and the crawler works fully against it.
