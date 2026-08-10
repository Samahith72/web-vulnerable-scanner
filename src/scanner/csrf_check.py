"""
csrf_check.py

Checks discovered forms for missing CSRF protection tokens.
POST forms that handle sensitive actions without a CSRF token
are vulnerable to Cross-Site Request Forgery attacks.

Maps to OWASP A01:2021 - Broken Access Control.
"""

# Common names used for CSRF token fields across frameworks
CSRF_TOKEN_NAMES = {
    "csrf_token",
    "csrftoken",
    "csrf",
    "_csrf",
    "_token",
    "user_token",
    "authenticity_token",
    "requestverificationtoken",
    "__requestverificationtoken",
    "x-csrf-token",
}


def has_csrf_token(fields: list) -> bool:
    """
    Returns True if any field in the form looks like a CSRF token.

    Checks both field name and type — a CSRF token is typically
    a hidden input whose name matches a known pattern.
    """
    for field in fields:
        name = (field.get("name") or "").lower()
        field_type = (field.get("type") or "").lower()

        if name in CSRF_TOKEN_NAMES:
            return True

        # Some frameworks use hidden fields with non-standard names
        # that still contain 'csrf' or 'token' in the name
        if field_type == "hidden" and ("csrf" in name or "token" in name):
            return True

    return False


def check_csrf(forms: list) -> list:
    """
    Checks each POST form for missing CSRF protection.

    Only POST forms are checked — GET forms are not expected
    to have CSRF tokens (GET should never change server state).

    Args:
        forms: List of form dicts from the crawler.

    Returns:
        List of finding dicts.
    """
    findings = []

    for form in forms:
        # Only POST forms are relevant for CSRF
        if form["method"].lower() != "post":
            continue

        if not has_csrf_token(form["fields"]):
            findings.append({
                "check": "Missing CSRF Token",
                "severity": "High",
                "url": form["page"],
                "action": form["action"],
                "description": (
                    f"POST form on {form['page']} (action: '{form['action']}') "
                    f"has no CSRF token field. An attacker could trick an "
                    f"authenticated user into submitting this form from a "
                    f"malicious site."
                ),
                "recommendation": (
                    "Add a unique, unpredictable CSRF token to every POST form. "
                    "Validate the token server-side on every state-changing request. "
                    "Consider using the SameSite cookie attribute as an additional "
                    "defense layer."
                ),
            })

    return findings
