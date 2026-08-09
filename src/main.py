"""
main.py

Entry point for the web vulnerability scanner.
Runs all checks against a target and prints findings.
"""

from scanner.header_check import check_headers
from scanner.crawler import crawl
from scanner.auth import dvwa_login
from scanner.xss_check import check_xss


def run_scan(base_url: str, use_auth: bool = False):
    print(f"\n{'='*55}")
    print(f"  Web Vulnerability Scanner")
    print(f"  Target: {base_url}")
    print(f"{'='*55}\n")

    all_findings = []

    # Phase 1: Header check
    print("[*] Running security header checks...")
    header_findings = check_headers(base_url)
    all_findings.extend(header_findings)
    print(f"    Found {len(header_findings)} header issue(s)\n")

    # Phase 2: Crawl the site
    print("[*] Crawling site for pages and forms...")
    session = None
    if use_auth:
        print("    Logging in...")
        session = dvwa_login(base_url)
    result = crawl(base_url, max_pages=20)
    print(f"    Visited {len(result['visited_pages'])} page(s)")
    print(f"    Found {len(result['forms'])} form(s)\n")

    # Phase 3: XSS check
    print("[*] Testing forms for reflected XSS...")
    xss_findings = check_xss(result["forms"], base_url, session=session)
    all_findings.extend(xss_findings)
    print(f"    Found {len(xss_findings)} XSS vulnerability(s)\n")

    # Print all findings
    print(f"{'='*55}")
    print(f"  Scan Complete — {len(all_findings)} total finding(s)")
    print(f"{'='*55}\n")

    for f in all_findings:
        severity = f.get("severity", "Info")
        print(f"[{severity}] {f['check']}")
        print(f"  {f['description']}")
        print(f"  Fix: {f['recommendation']}\n")


if __name__ == "__main__":
    # Run against DVWA with auth
    run_scan("http://localhost:8080", use_auth=True)
