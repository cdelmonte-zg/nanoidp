"""Where /saml/sso posts an assertion.

The Assertion Consumer Service URL comes from the AuthnRequest, or from
saml.default_acs_url when the request names none, and is the ``action`` of
the form that delivers the assertion. It must be an absolute http or https
URL that names its host, and not the identity provider itself. Otherwise
the request is refused before a login page is shown, a session is created
or an assertion is issued.
"""

import base64
import sys
import zlib
from html import escape
from urllib.parse import quote

import pytest

import nanoidp.routes.saml as saml_module
from nanoidp.services.audit import get_audit_log
from nanoidp.services.redirect_uri import is_http_url_with_a_host, is_the_same_host_and_port
from tests.test_timing_and_cors_settings import _client

GOOD = "http://localhost:8080/acs"

_UNUSABLE = [
    "javascript:void(0)",
    "JavaScript:void(0)",
    " javascript:void(0)",
    "javascript://sp.example/%0avoid(0)",
    "vbscript:x",
    "data:text/html,hello",
    "file:///etc/passwd",
    "ftp://sp.example/acs",
    "com.example.app:/acs",
    "/api/config",
    "acs",
    "//other.example/acs",
    "https:/other.example/acs",
    "https:other.example/acs",
    "http:///other.example/acs",
    "http://",
    "http://\\other.example/acs",
    "http://other.example\\@localhost/acs",
    "http://[::1/acs",
    "?x=1",
    "#fragment",
    # Whitespace and control characters, which a URL does not have and
    # Python strips or keeps depending on its version.
    " http://sp.example/acs",
    "http://sp.example/acs ",
    "http://sp.example/a cs",
    "http:// /acs",
    "http://sp.example/acs\x7f",
    # A port that is not one.
    "http://sp.example:notaport/acs",
    "http://sp.example:99999/acs",
]
_USABLE = [
    GOOD,
    "https://sp.example/saml/acs?tenant=a&x=1",
    "http://127.0.0.1:9/a",
    "http://[::1]:8080/acs",
    "HTTP://SP.example/acs",
    "https://sp.example",
]


def _authn_request(acs):
    attribute = "" if acs is None else f' AssertionConsumerServiceURL="{escape(acs, quote=True)}"'
    return (
        '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_1" '
        f'Version="2.0" IssueInstant="2026-11-17T00:00:00Z"{attribute}>'
        '<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">sp</saml:Issuer>'
        "</samlp:AuthnRequest>"
    )


def _post_binding(acs):
    return base64.b64encode(_authn_request(acs).encode()).decode()


def _redirect_binding(acs):
    compressor = zlib.compressobj(wbits=-15)
    deflated = compressor.compress(_authn_request(acs).encode()) + compressor.flush()
    return f"SAMLRequest={quote(base64.b64encode(deflated).decode())}&RelayState=r"


def _text(response):
    return response.get_data(as_text=True)


def _refused(response):
    """A 400 that is neither a login page nor a page carrying an assertion."""
    return (
        response.status_code == 400
        and "SAMLResponse" not in _text(response)
        and 'name="password"' not in _text(response)
        and "<form" not in _text(response)
    )


def _logged_in(client):
    page = client.post("/saml/sso", data={"SAMLRequest": _post_binding(GOOD), "username": "admin", "password": "admin"})
    assert "SAMLResponse" in _text(page)


class TestThePredicate:
    @pytest.mark.parametrize("acs", _UNUSABLE + ["", "   "])
    def test_what_a_form_must_not_post_to(self, acs):
        assert is_http_url_with_a_host(acs) is False

    @pytest.mark.parametrize("acs", _USABLE)
    def test_an_absolute_http_url_with_a_host(self, acs):
        assert is_http_url_with_a_host(acs) is True


class TestAnUnusableAcsIsRefusedBeforeAnything:
    @pytest.mark.parametrize("acs", _UNUSABLE)
    def test_no_login_page_for_it(self, client, acs):
        """The Redirect binding's first GET, and the POST binding's first
        POST: nobody is asked for a password on behalf of such a request."""
        assert _refused(client.get(f"/saml/sso?{_redirect_binding(acs)}"))
        assert _refused(client.post("/saml/sso", data={"SAMLRequest": _post_binding(acs)}))

    @pytest.mark.parametrize("acs", _UNUSABLE)
    def test_no_assertion_for_the_right_password(self, client, acs):
        """One POST with the credentials of the shipped configuration."""
        answer = client.post(
            "/saml/sso", data={"SAMLRequest": _post_binding(acs), "username": "admin", "password": "admin"}
        )

        assert _refused(answer)

    @pytest.mark.parametrize("acs", _UNUSABLE)
    def test_no_assertion_in_persona_mode(self, isolated_repo_config, acs):
        """One POST, no password, no cookie."""
        client = _client(isolated_repo_config, login={"mode": "persona"})

        answer = client.post(
            "/saml/sso",
            data={"SAMLRequest": _post_binding(acs), "username": "admin"},
        )

        assert _refused(answer)

    @pytest.mark.parametrize("acs", _UNUSABLE)
    def test_no_assertion_for_a_browser_already_logged_in(self, client, acs):
        _logged_in(client)

        assert _refused(client.get(f"/saml/sso?{_redirect_binding(acs)}"))
        assert _refused(client.post("/saml/sso", data={"SAMLRequest": _post_binding(acs)}))

    def test_the_refused_login_created_no_session(self, client):
        """Credentials sent with a refused request log nobody in."""
        client.post(
            "/saml/sso",
            data={"SAMLRequest": _post_binding("javascript:void(0)"), "username": "admin", "password": "admin"},
        )

        page = client.get(f"/saml/sso?{_redirect_binding(GOOD)}")

        assert page.status_code == 200
        assert 'name="password"' in _text(page)
        assert "SAMLResponse" not in _text(page)

    def test_it_is_audited_with_the_value_bounded(self, client, app):
        acs = "javascript:" + "a" * 5000

        client.post("/saml/sso", data={"SAMLRequest": _post_binding(acs)})

        with app.app_context():
            entry = get_audit_log().get_entries(limit=1)[0]
        assert (entry["event_type"], entry["status"], entry["endpoint"]) == ("saml_request", "failed", "/saml/sso")
        assert "absolute http or https URL" in entry["details"]["reason"]
        assert entry["details"]["acs_url"] == acs[:200]

    def test_the_refused_value_is_not_written_into_the_answer(self, client):
        answer = client.post("/saml/sso", data={"SAMLRequest": _post_binding("javascript:void(0)")})

        assert "javascript" not in _text(answer)

    def test_the_answer_says_what_is_wrong_and_names_both_sources(self, client):
        answer = client.post("/saml/sso", data={"SAMLRequest": _post_binding("/api/config")})

        assert "AssertionConsumerServiceURL" in _text(answer)
        assert "saml.default_acs_url" in _text(answer)
        assert "absolute http or https URL that names its host" in _text(answer)


class TestAUsableAcsStillWorks:
    @pytest.mark.parametrize("acs", _USABLE)
    def test_the_login_page_then_the_assertion_to_it(self, client, acs):
        page = client.get(f"/saml/sso?{_redirect_binding(acs)}")
        assert page.status_code == 200
        assert 'name="password"' in _text(page)

        delivered = client.post(
            "/saml/sso", data={"SAMLRequest": _post_binding(acs), "username": "admin", "password": "admin"}
        )

        assert delivered.status_code == 200
        assert f'<form method="post" action="{escape(acs, quote=True)}">' in _text(delivered)
        assert "SAMLResponse" in _text(delivered)


class TestTheDefaultAcsFollowsTheSameRule:
    @pytest.mark.parametrize("default", ["javascript:void(0)", "/api/config", "https:/other.example/acs"])
    def test_an_unusable_default_is_refused_when_the_request_names_none(self, isolated_repo_config, default):
        client = _client(isolated_repo_config, saml={"default_acs_url": default})

        assert _refused(client.get(f"/saml/sso?{_redirect_binding(None)}"))
        assert _refused(
            client.post(
                "/saml/sso", data={"SAMLRequest": _post_binding(None), "username": "admin", "password": "admin"}
            )
        )

    def test_a_blank_default_is_refused_before_the_login_too(self, isolated_repo_config):
        client = _client(isolated_repo_config, saml={"default_acs_url": ""})

        answer = client.get(f"/saml/sso?{_redirect_binding(None)}")

        assert _refused(answer)
        assert "saml.default_acs_url is not configured" in _text(answer)

    def test_a_request_that_names_a_usable_acs_does_not_meet_the_default(self, isolated_repo_config):
        client = _client(isolated_repo_config, saml={"default_acs_url": "javascript:void(0)"})

        delivered = client.post(
            "/saml/sso", data={"SAMLRequest": _post_binding(GOOD), "username": "admin", "password": "admin"}
        )

        assert f'action="{GOOD}"' in _text(delivered)

    def test_a_usable_default_receives_the_assertion(self, isolated_repo_config):
        client = _client(isolated_repo_config, saml={"default_acs_url": "https://sp.example/default-acs"})

        delivered = client.post(
            "/saml/sso", data={"SAMLRequest": _post_binding(None), "username": "admin", "password": "admin"}
        )

        assert 'action="https://sp.example/default-acs"' in _text(delivered)


class TestAnAcsThatNamesThisInstance:
    """A service provider is another server. The test client asks
    ``localhost``, port 80."""

    @pytest.mark.parametrize(
        "acs",
        ["http://localhost/keys/regenerate", "http://LOCALHOST:80/audit/clear", "http://localhost/saml/sso"],
    )
    def test_it_is_refused_like_any_unusable_acs(self, client, acs):
        assert _refused(client.get(f"/saml/sso?{_redirect_binding(acs)}"))
        _logged_in(client)
        answer = client.get(f"/saml/sso?{_redirect_binding(acs)}")
        assert _refused(answer)
        assert "must not name this identity provider itself" in _text(answer)

    def test_it_is_refused_with_the_ui_login_gate_on_too(self, isolated_repo_config):
        client = _client(isolated_repo_config, session={"require_ui_login": True})
        client.post("/login", data={"username": "admin", "password": "admin"})

        page = client.get(f"/saml/sso?{_redirect_binding('http://localhost/keys/regenerate')}")

        assert _refused(page)

    @pytest.mark.parametrize(
        "acs",
        ["http://localhost:8080/acs", "https://localhost/acs", "http://127.0.0.1/acs", "http://localhost.sp.example/acs"],
    )
    def test_another_port_scheme_or_name_is_another_place(self, client, acs):
        delivered = client.post(
            "/saml/sso", data={"SAMLRequest": _post_binding(acs), "username": "admin", "password": "admin"}
        )

        assert f'action="{acs}"' in _text(delivered)

    @pytest.mark.parametrize(
        "uri, other, same",
        [
            ("http://idp.test/x", "http://idp.test/", True),
            ("http://IDP.test:80/x", "http://idp.TEST/", True),
            ("https://idp.test/x", "https://idp.test:443/", True),
            ("https://idp.test:8443/x", "https://idp.test:8443/", True),
            ("https://idp.test:8000/x", "http://idp.test:8000/", True),
            ("http://[::1]:8000/x", "http://[::1]:8000/", True),
            ("http://idp.test:8000/x", "http://idp.test/", False),
            ("http://idp.test/x", "http://idp.test:8000/", False),
            ("https://idp.test/x", "http://idp.test/", False),
            ("http://idp.test.other.example/x", "http://idp.test/", False),
            ("http://127.0.0.1/x", "http://localhost/", False),
        ],
    )
    def test_the_same_name_and_port(self, uri, other, same):
        assert is_the_same_host_and_port(uri, other) is same

    def test_the_audit_entry_names_the_session_it_would_have_used(self, client, app):
        _logged_in(client)

        client.get(f"/saml/sso?{_redirect_binding('http://localhost/keys/regenerate')}")

        with app.app_context():
            entry = get_audit_log().get_entries(limit=1)[0]
        assert (entry["status"], entry["username"]) == ("failed", "admin")
        assert "must not name this identity provider itself" in entry["details"]["reason"]

    def test_without_a_session_the_audit_entry_names_nobody(self, client, app):
        client.get(f"/saml/sso?{_redirect_binding('javascript:void(0)')}")

        with app.app_context():
            entry = get_audit_log().get_entries(limit=1)[0]
        assert entry["username"] is None


def _deflated(raw):
    compressor = zlib.compressobj(9, wbits=-15)
    return compressor.compress(raw) + compressor.flush()


def _deflated_zeros(mebibytes):
    """A DEFLATE stream of that many mebibytes of zeros, built a mebibyte
    at a time: the test itself never holds what the stream inflates to."""
    compressor = zlib.compressobj(9, wbits=-15)
    chunk = b"\0" * (1024 * 1024)
    return b"".join(compressor.compress(chunk) for _ in range(mebibytes)) + compressor.flush()


class TestARequestInflatesToABoundedSize:
    """A DEFLATE-compressed request is read up to a bound."""

    BOUND = saml_module.MAX_INFLATED_SAML_REQUEST_BYTES

    def test_the_bound_is_a_mebibyte(self):
        assert self.BOUND == 1024 * 1024

    def test_up_to_the_bound_it_inflates(self):
        raw = b"a" * self.BOUND

        assert saml_module._inflate(_deflated(raw)) == raw

    def test_one_byte_more_is_refused(self):
        with pytest.raises(saml_module.SamlRequestTooLarge, match="inflates to more than"):
            saml_module._inflate(_deflated(b"a" * (self.BOUND + 1)))

    def test_bytes_that_are_not_deflate_are_a_zlib_error_as_before(self):
        with pytest.raises(zlib.error):
            saml_module._inflate(_authn_request(GOOD).encode())

    def test_a_truncated_stream_is_a_zlib_error_as_before(self):
        with pytest.raises(zlib.error):
            saml_module._inflate(_deflated(_authn_request(GOOD).encode())[:-5])

    @pytest.mark.parametrize("signed_requests", [False, True])
    @pytest.mark.parametrize("method", ["GET", "POST"])
    def test_a_request_past_the_bound_is_refused(self, isolated_repo_config, app, signed_requests, method):
        """Refused as what it is, whether or not requests must be signed:
        not read as a request that names no ACS, which would get the login
        page and the default ACS."""
        client = _client(isolated_repo_config, saml={"want_authn_requests_signed": signed_requests})
        oversized = base64.b64encode(_deflated_zeros(2)).decode()

        if method == "GET":
            answer = client.get(f"/saml/sso?SAMLRequest={quote(oversized)}")
        else:
            answer = client.post(
                "/saml/sso", data={"SAMLRequest": oversized, "username": "admin", "password": "admin"}
            )

        assert _refused(answer)
        entry = get_audit_log().get_entries(limit=1)[0]
        assert (entry["event_type"], entry["status"]) == ("saml_request", "failed")
        if signed_requests and method == "GET":
            # Refused earlier, unread: the Redirect binding's signature is
            # in the query, and this request has none.
            assert "AuthnRequest signature rejected" in _text(answer)
        else:
            assert "inflates to more than 1048576 bytes" in _text(answer)
            assert "inflates to more than" in entry["details"]["reason"]

    @pytest.mark.skipif(sys.platform != "linux", reason="ru_maxrss is read in Linux's unit, kibibytes")
    def test_a_request_past_the_bound_is_not_inflated(self, client):
        """A stream of 300 MiB: the process does not grow by it."""
        import resource

        oversized = base64.b64encode(_deflated_zeros(300)).decode()
        before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

        answer = client.post("/saml/sso", data={"SAMLRequest": oversized})

        grown_mib = (resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - before) / 1024
        assert _refused(answer)
        assert grown_mib < 50

    def test_a_request_of_ordinary_size_still_takes_the_redirect_binding(self, client):
        page = client.get(f"/saml/sso?{_redirect_binding(GOOD)}")

        assert page.status_code == 200
        assert 'name="password"' in _text(page)
