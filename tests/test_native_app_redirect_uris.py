"""
Native-app redirect URIs on /authorize (issue #81, RFC 8252).

Two additive relaxations of the web-client assumptions from #67:

- RFC 8252 §7.1: private-use scheme URIs (``com.example.app:/oauth2redirect``)
  have a scheme and a path but no authority; they are absolute URIs and
  must pass syntactic validation (RFC 6749 §3.1.2).
- RFC 8252 §7.3: a registered loopback URI (``http://127.0.0.1:{port}/...``,
  ``http://[::1]:{port}/...``) must match any port, because native apps bind
  an ephemeral port. Everything else keeps exact string matching, and
  ``localhost`` gets no port flexibility.
"""

import json

import pytest

from nanoidp.config import ConfigManager, OAuthClient, get_config
from nanoidp.services.redirect_uri import (
    PRIVATE_SCHEME_REASON,
    has_acceptable_scheme,
    is_absolute_redirect_uri,
    is_loopback_redirect_uri,
    redirect_uri_is_registered,
    redirect_uri_matches,
    redirect_uri_rejection_reason,
)

CUSTOM_SCHEME = "com.example.app:/oauth2redirect"
LOOPBACK_V4 = "http://127.0.0.1:0/callback"
LOOPBACK_V6 = "http://[::1]:0/callback"
LOCALHOST = "http://localhost:3000/callback"
WEB = "https://app.example.com/cb"


class TestPrivateUseSchemeRule:
    """RFC 8252 §7.1 minimum rule: a private-use scheme must contain a period."""

    @pytest.mark.parametrize(
        "uri",
        [
            CUSTOM_SCHEME,
            "com.example.app://callback",  # authority form is fine too
            "a.b:/x",
            LOOPBACK_V4,
            LOCALHOST,
            WEB,
        ],
    )
    def test_acceptable_schemes(self, uri):
        assert has_acceptable_scheme(uri)
        assert redirect_uri_rejection_reason(uri) is None

    @pytest.mark.parametrize("uri", ["myapp://callback", "myapp:/x", "app:/cb"])
    def test_private_scheme_without_period_rejected(self, uri):
        assert not has_acceptable_scheme(uri)
        assert redirect_uri_rejection_reason(uri) == PRIVATE_SCHEME_REASON

    def test_non_absolute_gets_generic_reason(self):
        assert redirect_uri_rejection_reason("/relative") == "Invalid redirect_uri"
        assert redirect_uri_rejection_reason("https://a.example/cb#f") == "Invalid redirect_uri"

    def test_authorize_rejects_myapp_scheme_with_rfc_reason(self, client):
        """demo-client has no redirect_uris, so only the syntactic gate applies."""
        response = client.get(
            "/authorize",
            query_string={
                "response_type": "code",
                "client_id": "demo-client",
                "redirect_uri": "myapp://callback",
                "scope": "openid",
            },
        )
        assert response.status_code == 400
        assert "Location" not in response.headers
        body = response.get_json()
        assert body["error"] == "invalid_request"
        assert "RFC 8252 section 7.1" in body["error_description"]


class TestIsAbsoluteRedirectUri:
    @pytest.mark.parametrize(
        "uri",
        [
            CUSTOM_SCHEME,
            "myapp://callback",  # absolute; the scheme rule is a separate gate
            LOOPBACK_V4,
            LOOPBACK_V6,
            "http://127.0.0.1/callback",
            LOCALHOST,
            WEB,
            "https://app.example.com/cb?state=keep",
        ],
    )
    def test_absolute_uris_accepted(self, uri):
        assert is_absolute_redirect_uri(uri)

    @pytest.mark.parametrize(
        "uri",
        [
            "/relative/path",  # no scheme (RFC 6749 §3.1.2: absolute URI)
            "callback",
            "",
            "com.example.app:",  # scheme only, no path and no authority
            "https://app.example.com/cb#frag",  # §3.1.2: no fragment
            "https://app.example.com/cb#",
            "com.example.app:/cb#x",
        ],
    )
    def test_non_absolute_or_fragment_rejected(self, uri):
        assert not is_absolute_redirect_uri(uri)


class TestIsLoopbackRedirectUri:
    @pytest.mark.parametrize(
        "uri",
        [LOOPBACK_V4, LOOPBACK_V6, "http://127.0.0.1/cb", "http://[::1]/cb"],
    )
    def test_loopback_literals(self, uri):
        assert is_loopback_redirect_uri(uri)

    @pytest.mark.parametrize(
        "uri",
        [
            LOCALHOST,  # §7.3 / §8.3: "localhost" is not the loopback literal
            "https://127.0.0.1:3000/cb",  # only http gets the exception
            "http://127.0.0.2/cb",
            "http://10.0.0.1/cb",
            CUSTOM_SCHEME,
            WEB,
        ],
    )
    def test_everything_else(self, uri):
        assert not is_loopback_redirect_uri(uri)


class TestRedirectUriMatches:
    @pytest.mark.parametrize(
        "requested,registered",
        [
            ("http://127.0.0.1:51234/callback", LOOPBACK_V4),
            ("http://127.0.0.1/callback", LOOPBACK_V4),
            ("http://127.0.0.1:51234/callback", "http://127.0.0.1/callback"),
            ("http://[::1]:51234/callback", LOOPBACK_V6),
            ("http://[::1]/callback", "http://[::1]:9/callback"),
            ("http://127.0.0.1:5/cb?x=1", "http://127.0.0.1:9/cb?x=1"),
            (CUSTOM_SCHEME, CUSTOM_SCHEME),
            (WEB, WEB),
            (LOCALHOST, LOCALHOST),
        ],
    )
    def test_matches(self, requested, registered):
        assert redirect_uri_matches(requested, registered)

    @pytest.mark.parametrize(
        "requested,registered",
        [
            ("http://localhost:3001/callback", LOCALHOST),  # localhost: exact port
            ("http://127.0.0.1:5/callback", LOCALHOST),  # loopback vs localhost
            ("http://localhost:5/callback", LOOPBACK_V4),
            ("https://app.example.com:444/cb", WEB),  # non-loopback: exact port
            ("http://127.0.0.1:5/other", LOOPBACK_V4),  # path stays exact
            ("http://127.0.0.1:5/callback/", LOOPBACK_V4),
            ("http://127.0.0.1:5/callback?x=1", LOOPBACK_V4),  # query stays exact
            ("https://127.0.0.1:5/callback", LOOPBACK_V4),  # scheme stays exact
            ("http://[::1]:5/callback", LOOPBACK_V4),  # v6 vs v4 literal
            ("http://127.0.0.2:5/callback", LOOPBACK_V4),
            ("com.example.app:/other", CUSTOM_SCHEME),
            ("com.example.evil:/oauth2redirect", CUSTOM_SCHEME),
        ],
    )
    def test_mismatches(self, requested, registered):
        assert not redirect_uri_matches(requested, registered)

    def test_is_registered_scans_every_entry(self):
        registered = [WEB, LOOPBACK_V4, CUSTOM_SCHEME]
        assert redirect_uri_is_registered("http://127.0.0.1:9999/callback", registered)
        assert redirect_uri_is_registered(CUSTOM_SCHEME, registered)
        assert not redirect_uri_is_registered("http://localhost:9999/callback", registered)
        assert not redirect_uri_is_registered(WEB, [])


@pytest.fixture
def native_client(app):
    """A client registered the way a native app would be (RFC 8252)."""
    with app.app_context():
        get_config().settings.clients.append(
            OAuthClient(
                client_id="native-client",
                client_secret="native-secret",
                redirect_uris=[CUSTOM_SCHEME, LOOPBACK_V4, LOOPBACK_V6, LOCALHOST],
            )
        )
    return "native-client"


def _authorize(client, client_id, redirect_uri):
    return client.get(
        "/authorize",
        query_string={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": "openid",
        },
    )


class TestAuthorizeNativeApp:
    """The accept/reject matrix on the live endpoint."""

    @pytest.mark.parametrize(
        "redirect_uri",
        [
            CUSTOM_SCHEME,
            "http://127.0.0.1:51234/callback",
            "http://127.0.0.1/callback",
            "http://[::1]:51234/callback",
            LOCALHOST,
        ],
    )
    def test_accepted(self, client, native_client, redirect_uri):
        response = _authorize(client, native_client, redirect_uri)
        assert response.status_code == 200
        assert b"username" in response.data  # login form rendered

    @pytest.mark.parametrize(
        "redirect_uri",
        [
            "http://localhost:3001/callback",  # localhost keeps exact port
            "http://127.0.0.1:51234/other",  # loopback path stays exact
            "https://127.0.0.1:51234/callback",  # https loopback: no exception
            "com.example.evil:/oauth2redirect",  # different private scheme
            "com.example.app:/oauth2redirect/extra",
        ],
    )
    def test_rejected_without_redirect(self, client, native_client, redirect_uri):
        response = _authorize(client, native_client, redirect_uri)
        assert response.status_code == 400
        assert "Location" not in response.headers  # §3.1.2.4
        data = json.loads(response.data)
        assert data["error"] == "invalid_request"
        assert "not registered" in data["error_description"]

    def test_non_loopback_registration_gets_no_port_flexibility(self, client, app):
        with app.app_context():
            get_config().settings.clients.append(
                OAuthClient(
                    client_id="web-only", client_secret="s", redirect_uris=[WEB]
                )
            )
        assert _authorize(client, "web-only", WEB).status_code == 200
        assert (
            _authorize(client, "web-only", "https://app.example.com:444/cb").status_code
            == 400
        )

    def test_unregistered_client_accepts_custom_scheme(self, client):
        """demo-client has no redirect_uris: a private-use scheme URI is a
        valid absolute URI and is accepted like any other."""
        assert _authorize(client, "demo-client", CUSTOM_SCHEME).status_code == 200

    @pytest.mark.parametrize("redirect_uri", ["/relative", "https://a.example/cb#frag"])
    def test_non_absolute_still_invalid(self, client, redirect_uri):
        response = _authorize(client, "demo-client", redirect_uri)
        assert response.status_code == 400
        assert json.loads(response.data)["error_description"] == "Invalid redirect_uri"

    def test_loopback_flow_completes_and_redirects_to_ephemeral_port(
        self, client, native_client
    ):
        """The login POST leg uses the same matcher and redirects to the
        port the app actually asked for, not the registered placeholder."""
        response = client.post(
            "/authorize",
            data={
                "response_type": "code",
                "client_id": native_client,
                "redirect_uri": "http://127.0.0.1:51234/callback",
                "scope": "openid",
                "username": "admin",
                "password": "admin",
            },
        )
        assert response.status_code == 302
        assert response.headers["Location"].startswith("http://127.0.0.1:51234/callback?")
        assert "code=" in response.headers["Location"]

    def test_custom_scheme_flow_redirects_to_app_scheme(self, client, native_client):
        response = client.post(
            "/authorize",
            data={
                "response_type": "code",
                "client_id": native_client,
                "redirect_uri": CUSTOM_SCHEME,
                "scope": "openid",
                "username": "admin",
                "password": "admin",
            },
        )
        assert response.status_code == 302
        assert response.headers["Location"].startswith(CUSTOM_SCHEME + "?")

    def test_oauth21_profile_keeps_loopback_port_exception(self, client, app, native_client):
        """OAuth 2.1 draft §4.1.1 carves out native-app loopback ports
        (RFC 8252 §7.3); the profile must not tighten it away."""
        # oauth21 also mandates PKCE, so send a challenge: the only variable
        # under test here is the redirect_uri matcher.
        pkce = {"code_challenge": "E" * 43, "code_challenge_method": "S256"}
        with app.app_context():
            get_config().settings.security_profile = "oauth21"
        try:
            response = client.get(
                "/authorize",
                query_string={
                    "response_type": "code",
                    "client_id": native_client,
                    "redirect_uri": "http://127.0.0.1:51234/callback",
                    "scope": "openid",
                    **pkce,
                },
            )
            assert response.status_code == 200
            response = client.get(
                "/authorize",
                query_string={
                    "response_type": "code",
                    "client_id": native_client,
                    "redirect_uri": "http://localhost:3001/callback",
                    "scope": "openid",
                    **pkce,
                },
            )
            assert response.status_code == 400
            assert "not registered" in json.loads(response.data)["error_description"]
        finally:
            with app.app_context():
                get_config().settings.security_profile = "dev"


class TestRegistrationSurfacesAcceptNativeUris:
    """UI, /api and MCP registration paths store native-app URIs verbatim."""

    def _config(self, tmp_path):
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "settings.yaml").write_text(
            "oauth:\n"
            '  issuer: "http://localhost:8000"\n'
            "  clients:\n"
            '    - client_id: "test"\n'
            '      client_secret: "test"\n'
        )
        (config_dir / "users.yaml").write_text(
            'users:\n  admin:\n    password: "admin"\ndefault_user: admin\n'
        )
        return ConfigManager(str(config_dir))

    async def test_mcp_create_client_with_native_uris(self, tmp_path):
        from nanoidp.mcp_server import _execute_tool

        config = self._config(tmp_path)
        result = await _execute_tool(
            "create_client",
            {
                "client_id": "native",
                "client_secret": "s",
                "redirect_uris": [CUSTOM_SCHEME, LOOPBACK_V4],
            },
            config,
        )
        assert result["success"] is True
        assert config.get_client("native").redirect_uris == [CUSTOM_SCHEME, LOOPBACK_V4]

    def test_ui_create_client_with_native_uris(self, client, app):
        response = client.post(
            "/clients/create",
            data={
                "client_id": "ui-native",
                "client_secret": "s",
                "redirect_uris": f"{CUSTOM_SCHEME}\n{LOOPBACK_V4}",
            },
        )
        assert response.status_code in (302, 303)
        with app.app_context():
            stored = get_config().get_client("ui-native")
        assert stored is not None
        assert stored.redirect_uris == [CUSTOM_SCHEME, LOOPBACK_V4]
        # and the registration is honoured end-to-end
        assert _authorize(client, "ui-native", "http://127.0.0.1:7/callback").status_code == 200
        assert _authorize(client, "ui-native", LOCALHOST).status_code == 400


class TestLoopbackPortExceptionTouchesOnlyThePort:
    """#81 review: the port exception must relax the port and nothing else.

    The previous implementation re-serialized the parsed URI, which
    normalized scheme case, dropped an empty query and never validated the
    port, so ``:evil`` was silently stripped. The comparison now slices only
    the port substring out of the ORIGINAL string.
    """

    REGISTERED = "http://127.0.0.1:0/cb"

    @pytest.mark.parametrize(
        "requested",
        [
            "http://127.0.0.1:evil/cb",     # non-numeric port
            "http://127.0.0.1:99999/cb",    # out-of-range port
            "http://127.0.0.1:123/cb?",     # empty query is not "no query"
            "HTTP://127.0.0.1:123/cb",      # scheme case preserved
            "http://127.0.0.1:123/cb/",     # trailing slash
            "http://127.0.0.1:123/CB",      # path case
            "http://127.0.0.1:0080/cb",     # zero-padded port is not a port literal
            "http://user@127.0.0.1:123/cb", # userinfo differs
        ],
    )
    def test_rejected(self, requested):
        assert not redirect_uri_matches(requested, self.REGISTERED)

    @pytest.mark.parametrize(
        "requested",
        ["http://127.0.0.1:123/cb", "http://127.0.0.1:65535/cb", "http://127.0.0.1/cb"],
    )
    def test_accepted(self, requested):
        assert redirect_uri_matches(requested, self.REGISTERED)

    def test_ipv6_only_port_varies(self):
        assert redirect_uri_matches("http://[::1]:4242/cb", "http://[::1]:0/cb")
        assert not redirect_uri_matches("http://[::1]:4242/cb?", "http://[::1]:0/cb")
        assert not redirect_uri_matches("http://[::1]:evil/cb", "http://[::1]:0/cb")

    def test_registered_with_invalid_port_never_matches(self):
        assert not redirect_uri_matches("http://127.0.0.1:123/cb", "http://127.0.0.1:evil/cb")
