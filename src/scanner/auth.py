"""
auth.py

Handles authenticated sessions for targets that require login.
"""

import requests


def dvwa_login(base_url: str, username: str = "admin", password: str = "password") -> requests.Session:
    """
    Logs into DVWA and returns an authenticated session.

    DVWA uses a CSRF token (user_token) on its login form,
    so we fetch it first before submitting credentials.

    Args:
        base_url: e.g. 'http://localhost:8080'
        username: DVWA username (default: admin)
        password: DVWA password (default: password)

    Returns:
        An authenticated requests.Session with cookies set.
    """
    session = requests.Session()
    login_url = f"{base_url}/login.php"

    # Step 1: GET the login page to grab the CSRF token
    response = session.get(login_url, timeout=5)

    # Extract user_token from the hidden input field
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(response.text, "html.parser")
    token_input = soup.find("input", {"name": "user_token"})
    user_token = token_input["value"] if token_input else ""

    # Step 2: POST credentials + token
    session.post(login_url, data={
        "username": username,
        "password": password,
        "Login": "Login",
        "user_token": user_token,
    }, timeout=5)

    return session
