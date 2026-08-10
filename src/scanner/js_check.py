"""
js_check.py

Scans pages for outdated or known-vulnerable JavaScript libraries
by inspecting <script src="..."> tags and matching version numbers
against a local vulnerability database.

Maps to OWASP A06:2021 - Vulnerable and Outdated Components.
"""

import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin


# Local vulnerability database
# Format: { "library_name": { "version": "CVE / description" } }
# Extend this as you learn about more CVEs
VULNERABLE_LIBRARIES = {
    "jquery": {
        "1.2.0": "CVE-2007-2379: XSS via .html()",
        "1.2.1": "CVE-2007-2379: XSS via .html()",
        "1.3.0": "CVE-2009-4284: XSS vulnerability",
        "1.3.1": "CVE-2009-4284: XSS vulnerability",
        "1.3.2": "CVE-2009-4284: XSS vulnerability",
        "1.4.0": "CVE-2010-5312: XSS in jQuery UI dialog",
        "1.4.1": "CVE-2010-5312: XSS in jQuery UI dialog",
        "1.4.2": "CVE-2010-5312: XSS in jQuery UI dialog",
        "1.4.3": "CVE-2010-5312: XSS in jQuery UI dialog",
        "1.4.4": "CVE-2010-5312: XSS in jQuery UI dialog",
        "1.6.0": "CVE-2011-4969: XSS via location.hash",
        "1.6.1": "CVE-2011-4969: XSS via location.hash",
        "1.6.2": "CVE-2011-4969: XSS via location.hash",
        "1.6.3": "CVE-2011-4969: XSS via location.hash",
        "1.6.4": "CVE-2011-4969: XSS via location.hash",
        "1.7.0": "CVE-2012-6708: XSS via selector",
        "1.7.1": "CVE-2012-6708: XSS via selector",
        "1.7.2": "CVE-2012-6708: XSS via selector",
        "1.8.0": "CVE-2012-6708: XSS via selector",
        "1.8.1": "CVE-2012-6708: XSS via selector",
        "1.8.2": "CVE-2012-6708: XSS via selector",
        "1.8.3": "CVE-2012-6708: XSS via selector",
        "1.9.0": "CVE-2015-9251: XSS via cross-domain Ajax",
        "1.9.1": "CVE-2015-9251: XSS via cross-domain Ajax",
        "1.10.0": "CVE-2015-9251: XSS via cross-domain Ajax",
        "1.10.1": "CVE-2015-9251: XSS via cross-domain Ajax",
        "1.10.2": "CVE-2015-9251: XSS via cross-domain Ajax",
        "1.11.0": "CVE-2015-9251: XSS via cross-domain Ajax",
        "1.11.1": "CVE-2015-9251: XSS via cross-domain Ajax",
        "1.11.2": "CVE-2015-9251: XSS via cross-domain Ajax",
        "1.11.3": "CVE-2015-9251: XSS via cross-domain Ajax",
        "1.12.0": "CVE-2015-9251: XSS via cross-domain Ajax",
        "1.12.1": "CVE-2015-9251: XSS via cross-domain Ajax",
        "1.12.2": "CVE-2015-9251: XSS via cross-domain Ajax",
        "1.12.3": "CVE-2015-9251: XSS via cross-domain Ajax",
        "1.12.4": "CVE-2015-9251: XSS via cross-domain Ajax",
        "2.0.0": "CVE-2015-9251: XSS via cross-domain Ajax",
        "2.1.0": "CVE-2015-9251: XSS via cross-domain Ajax",
        "2.1.1": "CVE-2015-9251: XSS via cross-domain Ajax",
        "2.1.2": "CVE-2015-9251: XSS via cross-domain Ajax",
        "2.1.3": "CVE-2015-9251: XSS via cross-domain Ajax",
        "2.1.4": "CVE-2015-9251: XSS via cross-domain Ajax",
        "2.2.0": "CVE-2015-9251: XSS via cross-domain Ajax",
        "2.2.1": "CVE-2015-9251: XSS via cross-domain Ajax",
        "2.2.2": "CVE-2015-9251: XSS via cross-domain Ajax",
        "2.2.3": "CVE-2015-9251: XSS via cross-domain Ajax",
        "2.2.4": "CVE-2015-9251: XSS via cross-domain Ajax",
        "3.0.0": "CVE-2019-11358: Prototype pollution",
        "3.1.0": "CVE-2019-11358: Prototype pollution",
        "3.1.1": "CVE-2019-11358: Prototype pollution",
        "3.2.0": "CVE-2019-11358: Prototype pollution",
        "3.2.1": "CVE-2019-11358: Prototype pollution",
        "3.3.0": "CVE-2019-11358: Prototype pollution",
        "3.3.1": "CVE-2019-11358: Prototype pollution",
        "3.4.0": "CVE-2020-11022: XSS via HTML passed to manipulation methods",
        "3.4.1": "CVE-2020-11022: XSS via HTML passed to manipulation methods",
        "3.5.0": "CVE-2020-11023: XSS in certain HTML manipulation methods",
    },
    "bootstrap": {
        "3.0.0": "CVE-2018-14040: XSS in data-target attribute",
        "3.0.1": "CVE-2018-14040: XSS in data-target attribute",
        "3.0.2": "CVE-2018-14040: XSS in data-target attribute",
        "3.0.3": "CVE-2018-14040: XSS in data-target attribute",
        "3.1.0": "CVE-2018-14040: XSS in data-target attribute",
        "3.1.1": "CVE-2018-14040: XSS in data-target attribute",
        "3.2.0": "CVE-2018-14040: XSS in data-target attribute",
        "3.2.1": "CVE-2018-14040: XSS in data-target attribute",
        "3.3.0": "CVE-2018-14040: XSS in data-target attribute",
        "3.3.1": "CVE-2018-14040: XSS in data-target attribute",
        "3.3.2": "CVE-2018-14040: XSS in data-target attribute",
        "3.3.3": "CVE-2018-14040: XSS in data-target attribute",
        "3.3.4": "CVE-2018-14040: XSS in data-target attribute",
        "3.3.5": "CVE-2018-14040: XSS in data-target attribute",
        "3.3.6": "CVE-2018-14040: XSS in data-target attribute",
        "3.3.7": "CVE-2018-14040: XSS in data-target attribute",
        "4.0.0": "CVE-2019-8331: XSS in tooltip/popover data-template",
        "4.1.0": "CVE-2019-8331: XSS in tooltip/popover data-template",
        "4.1.1": "CVE-2019-8331: XSS in tooltip/popover data-template",
        "4.1.2": "CVE-2019-8331: XSS in tooltip/popover data-template",
        "4.1.3": "CVE-2019-8331: XSS in tooltip/popover data-template",
        "4.2.0": "CVE-2019-8331: XSS in tooltip/popover data-template",
        "4.2.1": "CVE-2019-8331: XSS in tooltip/popover data-template",
        "4.3.0": "CVE-2019-8331: XSS in tooltip/popover data-template",
        "4.3.1": "CVE-2019-8331: XSS in tooltip/popover data-template",
    },
    "angularjs": {
        "1.0.0": "CVE-2019-14863: XSS via attribute interpolation",
        "1.1.0": "CVE-2019-14863: XSS via attribute interpolation",
        "1.2.0": "CVE-2019-14863: XSS via attribute interpolation",
        "1.3.0": "CVE-2019-14863: XSS via attribute interpolation",
        "1.4.0": "CVE-2019-14863: XSS via attribute interpolation",
        "1.5.0": "CVE-2019-14863: XSS via attribute interpolation",
        "1.6.0": "CVE-2019-14863: XSS via attribute interpolation",
    },
}

# Regex to extract library name and version from script src
# Matches patterns like: jquery-3.4.1.min.js, bootstrap-4.3.1.js
SCRIPT_VERSION_PATTERN = re.compile(
    r"^(.*?)[-.](\d+\.\d+\.?\d*)(?:\.min)?\.js$",
    re.IGNORECASE
)


def extract_scripts(html: str, page_url: str, base_url: str) -> list:
    """
    Extracts all <script src="..."> tags from a page and
    attempts to parse library name + version from the filename.

    Returns a list of dicts: { name, version, src }
    """
    soup = BeautifulSoup(html, "html.parser")
    scripts = []

    for tag in soup.find_all("script", src=True):
        src = tag["src"]
        full_src = urljoin(base_url, src)
        filename = src.split("/")[-1].split("?")[0]  # strip path and query params

        match = SCRIPT_VERSION_PATTERN.search(filename)
        if match:
            scripts.append({
                "name": match.group(1).lower(),
                "version": match.group(2),
                "src": full_src,
                "page": page_url,
            })

    return scripts


def check_js_libraries(visited_pages: list, base_url: str, session=None) -> list:
    """
    Fetches each visited page and checks its script tags for
    known-vulnerable library versions.

    Args:
        visited_pages: List of URLs from the crawler.
        base_url:      Base URL of the target.
        session:       Optional authenticated requests.Session.

    Returns:
        List of finding dicts.
    """
    findings = []
    requester = session or requests
    checked = set()  # avoid duplicate findings for the same lib+version

    for page_url in visited_pages:
        try:
            response = requester.get(page_url, timeout=5)
        except requests.exceptions.RequestException:
            continue

        scripts = extract_scripts(response.text, page_url, base_url)

        for script in scripts:
            name = script["name"]
            version = script["version"]
            key = f"{name}-{version}"

            if key in checked:
                continue
            checked.add(key)

            if name in VULNERABLE_LIBRARIES:
                if version in VULNERABLE_LIBRARIES[name]:
                    cve_info = VULNERABLE_LIBRARIES[name][version]
                    findings.append({
                        "check": "Outdated JS Library",
                        "severity": "High",
                        "url": script["src"],
                        "page": script["page"],
                        "description": (
                            f"Detected {name} v{version} which has a known "
                            f"vulnerability: {cve_info}. "
                            f"Found on: {script['page']}"
                        ),
                        "recommendation": (
                            f"Upgrade {name} to the latest stable version. "
                            f"Check https://www.cvedetails.com for full CVE details."
                        ),
                    })

    return findings
