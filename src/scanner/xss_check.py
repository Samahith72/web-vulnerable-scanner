"""
xss_check.py

Tests discovered forms for reflected XSS vulnerabilities by submitting
a harmless test payload and checking if it appears unescaped in the response.

Maps to OWASP A03:2021 - Injection.
"""

import requests
from urllib.parse import urljoin

# Harmless payload that's detectable but won't actually execute
# We check if it appears RAW in the response (unescaped)
XSS_PAYLOAD = "<script>xss_test_payload</script>"


def check_xss(forms: list, base_url: str, session: requests.Session = None) -> list:
    """
    Tests each form for reflected XSS by submitting a test payload
    into every input field and checking the response.

    Args:
        forms:    List of form dicts from the crawler.
        base_url: Base URL of the target (used to resolve relative action URLs).
        session:  Optional requests.Session (used when auth cookies are needed).

    Returns:
        List of finding dicts.
    """
    findings = []
    requester = session or requests

    for form in forms:
        # Build the absolute URL for the form action
        action_url = urljoin(base_url, form["action"]) if form["action"] else form["page"]

        # Build form data: put payload in every text-like field
        form_data = {}
        for field in form["fields"]:
            field_name = field.get("name")
            field_type = field.get("type", "text")

            if not field_name:
                continue

            if field_type in ("text", "search", "email", "url", "textarea", "hidden"):
                form_data[field_name] = XSS_PAYLOAD
            else:
                # For non-text fields (checkbox, submit, etc.) use a safe default
                form_data[field_name] = "1"

        if not form_data:
            continue

        try:
            if form["method"] == "post":
                response = requester.post(action_url, data=form_data, timeout=5)
            else:
                response = requester.get(action_url, params=form_data, timeout=5)
        except requests.exceptions.RequestException:
            continue

        # If our raw payload appears in the response, input is reflected unescaped
        if XSS_PAYLOAD in response.text:
            findings.append({
                "check": "Reflected XSS",
                "severity": "High",
                "url": action_url,
                "method": form["method"].upper(),
                "payload": XSS_PAYLOAD,
                "description": (
                    f"Form at {action_url} reflects unsanitized input. "
                    f"The payload '{XSS_PAYLOAD}' was returned unescaped in the response."
                ),
                "recommendation": (
                    "Sanitize and escape all user input before rendering it in HTML. "
                    "Use Content-Security-Policy headers as an additional defense layer."
                ),
            })

    return findings
