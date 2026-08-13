"""
main.py

Entry point for the web vulnerability scanner.
Runs all checks against a target and prints findings,
then generates an HTML report.
"""

from scanner.header_check import check_headers
from scanner.crawler import crawl
from scanner.auth import dvwa_login
from scanner.xss_check import check_xss
from scanner.csrf_check import check_csrf
from scanner.js_check import check_js_libraries
from scanner.report import generate_html_report


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

    # Phase 2: Crawl
    print("[*] Crawling site for pages and forms...")
    session = None
    if use_auth:
        print("    Logging in...")
        session = dvwa_login(base_url)
    result = crawl(base_url, max_pages=20)
    print(f"    Visited {len(result['visited_pages'])} page(s)")
    print(f"    Found {len(result['forms'])} form(s)\n")

    # Phase 3: XSS
    print("[*] Testing forms for reflected XSS...")
    xss_findings = check_xss(result["forms"], base_url, session=session)
    all_findings.extend(xss_findings)
    print(f"    Found {len(xss_findings)} XSS vulnerability(s)\n")

    # Phase 4: CSRF
    print("[*] Checking forms for missing CSRF tokens...")
    csrf_findings = check_csrf(result["forms"])
    all_findings.extend(csrf_findings)
    print(f"    Found {len(csrf_findings)} CSRF issue(s)\n")

    # Phase 5: JS libraries
    print("[*] Checking for outdated JS libraries...")
    js_findings = check_js_libraries(
        result["visited_pages"], base_url, session=session
    )
    all_findings.extend(js_findings)
    print(f"    Found {len(js_findings)} outdated library(s)\n")

    # Print summary to terminal
    print(f"{'='*55}")
    print(f"  Scan Complete — {len(all_findings)} total finding(s)")
    print(f"{'='*55}\n")

    severity_order = {"High": 0, "Medium": 1, "Low": 2, "Error": 3}
    sorted_findings = sorted(
        all_findings,
        key=lambda f: severity_order.get(f.get("severity", "Low"), 99)
    )

    for f in sorted_findings:
        severity = f.get("severity", "Info")
        print(f"[{severity}] {f['check']}")
        print(f"  {f['description']}")
        print(f"  Fix: {f['recommendation']}\n")

    # Phase 6: Generate HTML report
    print("[*] Generating HTML report...")
    report_path = generate_html_report(
        findings=all_findings,
        target=base_url,
        output_path="reports/scan_report.html",
        scanner_version="1.0.0"
    )
    print(f"    Report saved to: {report_path}\n")


if __name__ == "__main__":
    run_scan("http://localhost:8080", use_auth=True)
