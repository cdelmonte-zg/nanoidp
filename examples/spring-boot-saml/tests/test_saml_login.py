"""SAML login to the Spring Boot SP through NanoIDP, the way a browser does it.

Needs NanoIDP on :8000 with this preset and the SP (sp/) on :8080.
"""
import html
import re

import requests

SP = "http://localhost:8080"
TIMEOUT = 10  # seconds: a stuck server fails the test instead of hanging it


def form(page, url=None):
    """The action and the fields of the first form on a page."""
    action = re.search(r'<form[^>]*action="([^"]+)"', page)
    fields = {html.unescape(name): html.unescape(value) for name, value in
              re.findall(r'<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"', page)}
    return (html.unescape(action[1]) if action else url), fields


def saml_login(path, username, password):
    """Open `path` on the SP, log in at NanoIDP, return (browser, final page)."""
    browser = requests.Session()
    # 1. The SP answers with a form that posts an AuthnRequest to NanoIDP
    action, fields = form(browser.get(SP + path, timeout=TIMEOUT).text)
    # 2. NanoIDP shows its login form (it posts back to the same URL)
    login_page = browser.post(action, data=fields, timeout=TIMEOUT)
    action, fields = form(login_page.text, login_page.url)
    fields.update(username=username, password=password)
    # 3. NanoIDP answers with a form that posts the SAMLResponse to the SP's ACS
    answer = browser.post(action, data=fields, timeout=TIMEOUT)
    if "SAMLResponse" not in answer.text:
        return browser, answer
    action, fields = form(answer.text)
    # 4. The SP validates the response and sends the browser where it started
    return browser, browser.post(action, data=fields, timeout=TIMEOUT)


def test_admin_reaches_the_admin_area():
    browser, page = saml_login("/admin", "admin", "admin")
    assert page.status_code == 200, page.text
    assert page.text == "admin area for admin@example.org\n"


def test_roles_become_authorities_and_attributes_arrive():
    browser, _ = saml_login("/", "admin", "admin")
    home = browser.get(SP + "/", timeout=TIMEOUT).text
    assert "user=admin@example.org" in home                 # NameID: the email
    assert "ROLE_ADMIN" in home and "ROLE_USER" in home     # from the roles attribute
    assert "roles=[ADMIN, USER]" in home
    assert "groups=[ADMINISTRATORS]" in home


def test_a_user_without_the_admin_role_is_refused():
    _, page = saml_login("/admin", "user", "user")
    assert page.status_code == 403


def test_a_wrong_password_gets_no_saml_response():
    _, page = saml_login("/", "admin", "wrong")
    assert "SAMLResponse" not in page.text
    assert page.url.startswith("http://localhost:8000/saml/sso")
