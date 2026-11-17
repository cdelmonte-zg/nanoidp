"""The SOAP answers of /saml/attribute-query (#488, SAML 2.0 Bindings 3.2.3.2).

The endpoint is a backend exchange with no password and no cookie. Its
answers carry the cache headers the SOAP binding recommends, whatever the
outcome, and no script reads them from an origin the operator did not name:
on success the body is a statement of a user's attributes signed by the IdP,
which the app-wide CORS rule would hand to any page.
"""

import pytest

import nanoidp.routes.saml as saml_module
from nanoidp.routes._auth import NO_STORE, SAML_POST_BINDING, SAML_SOAP_BINDING, no_store
from tests.test_timing_and_cors_settings import _client

URL = "/saml/attribute-query"
EVIL = {"Origin": "http://evil.example"}
LOCALHOST = "http://localhost:3000"


def _query(name_id="admin"):
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>'
        '<samlp:AttributeQuery xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
        ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
        ' ID="_q488" Version="2.0" IssueInstant="2026-11-17T00:00:00Z">'
        "<saml:Issuer>test-sp</saml:Issuer>"
        f"<saml:Subject><saml:NameID>{name_id}</saml:NameID></saml:Subject>"
        "</samlp:AttributeQuery></soap:Body></soap:Envelope>"
    )


def _fail_inside(monkeypatch):
    def failing(*args, **kwargs):
        raise RuntimeError("ours")

    monkeypatch.setattr(saml_module, "_build_attribute_query_response", failing)


# Every way the endpoint answers in SOAP: (id, body, status, what the body holds).
_OUTCOMES = [
    ("assertion", _query(), 200, "Assertion"),
    ("unknown-principal", _query("no-such-user"), 200, "UnknownPrincipal"),
    ("client-fault", "<not-xml", 500, "soap:Client"),
    ("server-fault", _query(), 500, "soap:Server"),
]
_EACH_OUTCOME = pytest.mark.parametrize(
    "outcome, body, status, holds", _OUTCOMES, ids=[outcome for outcome, *_ in _OUTCOMES]
)


def _post(client, monkeypatch, outcome, body, headers=None, content_type="text/xml"):
    if outcome == "server-fault":
        _fail_inside(monkeypatch)
    return client.post(URL, data=body, headers={"Content-Type": content_type, **(headers or {})})


class TestNoCacheKeepsTheAnswer:
    @_EACH_OUTCOME
    def test_the_soap_binding_directives_whatever_the_outcome(self, client, monkeypatch, outcome, body, status, holds):
        answer = _post(client, monkeypatch, outcome, body)

        assert answer.status_code == status
        assert holds in answer.get_data(as_text=True)
        assert answer.mimetype == "text/xml"
        assert answer.headers.get_all("Cache-Control") == ["no-cache, no-store, must-revalidate, private"]
        assert answer.headers.get_all("Pragma") == ["no-cache"]

    @_EACH_OUTCOME
    def test_no_validator_a_cache_could_revalidate_with(self, client, monkeypatch, outcome, body, status, holds):
        answer = _post(client, monkeypatch, outcome, body)

        assert "ETag" not in answer.headers
        assert "Last-Modified" not in answer.headers


class TestTheThreeWordings:
    def test_each_text_names_its_directives(self):
        assert NO_STORE == "no-store"
        assert SAML_POST_BINDING == "no-cache, no-store"
        assert SAML_SOAP_BINDING == "no-cache, no-store, must-revalidate, private"

    def test_no_store_is_the_wording_nobody_asked_otherwise(self, app):
        with app.test_request_context():
            assert no_store("x").headers["Cache-Control"] == "no-store"

    def test_a_wording_nobody_named_is_refused(self, app):
        with app.test_request_context():
            with pytest.raises(ValueError):
                no_store("x", wording="public, max-age=60")

    def test_the_other_surfaces_keep_theirs(self, client, auth_header):
        token = client.post("/token", data={"grant_type": "client_credentials"}, headers=auth_header)

        assert token.headers["Cache-Control"] == "no-store"


class TestNoOtherOriginReadsTheAnswer:
    @_EACH_OUTCOME
    @pytest.mark.parametrize("content_type", ["text/xml", "text/plain"])
    def test_under_the_permissive_default(self, client, monkeypatch, outcome, body, status, holds, content_type):
        """text/plain is the request a browser sends with no preflight: the
        endpoint answers it the same, so nothing else stands in the way."""
        answer = _post(client, monkeypatch, outcome, body, EVIL, content_type)

        assert answer.status_code == status
        assert holds in answer.get_data(as_text=True)
        assert "Access-Control-Allow-Origin" not in answer.headers

    @_EACH_OUTCOME
    def test_under_a_declared_star(self, isolated_repo_config, monkeypatch, outcome, body, status, holds):
        client = _client(isolated_repo_config, cors_allowed_origins=["*"])

        answer = _post(client, monkeypatch, outcome, body, EVIL)

        assert "Access-Control-Allow-Origin" not in answer.headers

    @_EACH_OUTCOME
    @pytest.mark.parametrize("content_type", ["text/xml", "text/plain"])
    def test_the_profiles_localhost_rule_is_not_a_named_origin(
        self, isolated_repo_config, monkeypatch, outcome, body, status, holds, content_type
    ):
        client = _client(isolated_repo_config, security_profile="stricter-dev")

        answer = _post(client, monkeypatch, outcome, body, {"Origin": LOCALHOST}, content_type)

        assert "Access-Control-Allow-Origin" not in answer.headers

    @_EACH_OUTCOME
    @pytest.mark.parametrize("content_type", ["text/xml", "text/plain"])
    def test_a_localhost_origin_the_operator_named_reads_it_under_stricter_dev(
        self, isolated_repo_config, monkeypatch, outcome, body, status, holds, content_type
    ):
        client = _client(isolated_repo_config, security_profile="stricter-dev", cors_allowed_origins=[LOCALHOST])

        named = _post(client, monkeypatch, outcome, body, {"Origin": LOCALHOST}, content_type)
        other = _post(client, monkeypatch, outcome, body, {"Origin": "http://localhost:4000"}, content_type)

        assert named.headers.get("Access-Control-Allow-Origin") == LOCALHOST
        assert "Access-Control-Allow-Origin" not in other.headers

    @_EACH_OUTCOME
    def test_a_named_origin_reads_it_and_no_other(self, isolated_repo_config, monkeypatch, outcome, body, status, holds):
        client = _client(isolated_repo_config, cors_allowed_origins=["https://app.example"])

        named = _post(client, monkeypatch, outcome, body, {"Origin": "https://app.example"})
        other = _post(client, monkeypatch, outcome, body, EVIL)

        assert named.headers.get("Access-Control-Allow-Origin") == "https://app.example"
        assert "Access-Control-Allow-Origin" not in other.headers

    def test_a_backend_caller_is_answered_as_before(self, client):
        """No Origin, no browser: the exchange the endpoint is for."""
        answer = client.post(URL, data=_query(), headers={"Content-Type": "text/xml"})

        assert answer.status_code == 200
        assert "Assertion" in answer.get_data(as_text=True)
        assert "Access-Control-Allow-Origin" not in answer.headers

    def test_the_rule_stays_open_elsewhere(self, client):
        """The same attributes over REST stay readable, by design (#163)."""
        answer = client.get("/api/users/admin", headers=EVIL)

        assert answer.status_code == 200
        assert answer.headers.get("Access-Control-Allow-Origin") is not None
