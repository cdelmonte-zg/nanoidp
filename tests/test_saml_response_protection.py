"""Credential-bearing form pages only permit explicitly named script origins."""

import pytest

from tests.test_authorize_response_mode import BASE
from tests.test_saml import TestSAMLSSO as _SAML
from tests.test_timing_and_cors_settings import _client


def test_saml_response_after_password_login_is_not_cacheable(client):
    request = _SAML()._create_saml_request(compress=False)
    page = client.post("/saml/sso", data={"SAMLRequest": request})
    assert b"password" in page.data
    page = client.post(
        "/saml/sso",
        data={
            "SAMLRequest": request,
            "username": "admin",
            "password": "admin",
        },
    )
    assert page.status_code == 200
    assert b'name="SAMLResponse"' in page.data
    assert page.headers.get("Cache-Control") == "no-cache, no-store"
    assert page.headers.get("Pragma") == "no-cache"


@pytest.mark.parametrize("surface", ["saml", "oauth"])
@pytest.mark.parametrize("profile", ["dev", "stricter-dev", "oauth21"])
@pytest.mark.parametrize(
    "declared, allowed",
    [
        (None, False),
        (["*"], False),
        ([], False),
        (["*", "http://localhost:3000"], True),
        (["http://localhost:3000"], True),
        (["http://different.example"], False),
    ],
)
def test_form_pages_require_a_named_origin(isolated_repo_config, surface, profile, declared, allowed):
    client = _client(
        isolated_repo_config,
        security_profile=profile,
        cors_allowed_origins=declared,
        login={"mode": "persona", "auto_login": True},
        oauth={"issuer_from_proxy_headers": True},
    )
    origin = "http://localhost:3000"
    headers = {"Origin": origin, "X-Forwarded-Host": "localhost:3000"}
    if surface == "saml":
        page = client.post(
            "/saml/sso",
            data={
                "SAMLRequest": _SAML()._create_saml_request(compress=False),
                "username": "admin",
            },
            headers=headers,
        )
        assert b'name="SAMLResponse"' in page.data
    else:
        page = client.post(
            "/authorize",
            data={
                **BASE,
                "response_mode": "form_post",
                "login_hint": "persona-auto-login:admin",
                "code_challenge": "a" * 43,
                "code_challenge_method": "S256",
            },
            headers=headers,
            follow_redirects=True,
        )
        assert b'name="code"' in page.data
    assert page.status_code == 200
    assert page.headers.get("Access-Control-Allow-Origin") == (origin if allowed else None)
    assert "Origin" in page.vary
