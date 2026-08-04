"""
header_check.py

Checks a target URL for the presence of key HTTP security headers.
Maps to OWASP A05:2021 - Security Misconfiguration.
"""

import requests

# Headers we check for, with a short explanation of what each one protects against
SECURITY_HEADERS = {
    "Content-Security-Policy": "Helps prevent XSS by restricting where scripts/styles can load from.",
    "X-Frame-Options": "Prevents clickjacking by controlling if the page can be embedded in an iframe.",
    "Strict-Transport-Security": "Forces browsers to use HTTPS, preventing downgrade attacks.",
    "X-Content-Type-Options": "Prevents MIME-sniffing attacks by enforcing declared content types.",
    "Referrer-Policy": "Controls how much referrer information is leaked to other sites.",
}


def check_headers(url: str) -> list:
    """
    Sends a GET request to the target URL and checks for missing security headers.

    Args:
        url: The target URL to scan.

    Returns:
        A list of finding dicts, each with check, severity, description, recommendation.
    """
    findings = []

    try:
        response = requests.get(url, timeout=5)
    except requests.exceptions.RequestException as e:
        return [{
            "check": "Header Check",
            "severity": "Error",
            "description": f"Could not connect to {url}: {e}",
            "recommendation": "Verify the target URL is correct and reachable."
        }]

    for header, explanation in SECURITY_HEADERS.items():
        if header not in response.headers:
            findings.append({
                "check": f"Missing Header: {header}",
                "severity": "Medium",
                "description": explanation,
                "recommendation": f"Add the '{header}' header to server responses."
            })

    return findings


if __name__ == "__main__":
    # Quick manual test when running this file directly
    target = "http://localhost:3000"
    results = check_headers(target)

    print(f"\nScan results for {target}:\n")
    if not results:
        print("✅ All checked security headers are present.")
    else:
        for finding in results:
            print(f"❌ {finding['check']}")
            print(f"   Severity: {finding['severity']}")
            print(f"   {finding['description']}")
            print(f"   Fix: {finding['recommendation']}\n")
