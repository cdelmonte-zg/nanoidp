"""
Issue #463: request objects are not implemented, so /authorize refuses the
``request`` and ``request_uri`` parameters (OIDC Core 6.1 / 6.2) and the
discovery document says so explicitly. Discovery section 3 reads an omitted
``request_uri_parameter_supported`` as TRUE, which is why the explicit false
matters: until #463 the document promised by omission what the server never
read.

A request that carries one of the two is refused whatever else it says or
lacks: Core 6.1 lets everything but response_type and client_id travel
inside the object, so the object may hold the very parameter the query
omits, and no other error is the right answer. Only WHERE the refusal goes
depends on the rest: to the validated redirect_uri (with ``state`` from the
query and ``iss`` when the issuer qualifies, #258) once there is one, and
locally otherwise - only ever to a URI the client's redirect policy
accepts, which for a client without registered URIs is #67's permissive
``dev`` rule. The
conformance suite ends its request object test as SKIPPED on
``error=request_not_supported`` and checks no state there, since the
suite's state travels inside the object.
"""

import json
from urllib.parse import parse_qs, urlparse

import pytest
from werkzeug.datastructures import MultiDict

from nanoidp.config import get_config
from tests.conftest import pending_transaction_ids

REDIRECT = "http://localhost:3000/callback"
HTTPS_ISSUER = "https://idp.example"
# An unsigned request object in the suite's shape: state and nonce inside.
REQUEST_OBJECT = (
    "eyJhbGciOiJub25lIn0."
    "eyJzdGF0ZSI6IklOU0lERSIsIm5vbmNlIjoiTjEiLCJyZXNwb25zZV90eXBlIjoiY29kZSJ9."
)
REQUEST_URI = "https://rp.example/request-objects/1"


def _query(**extra):
    params = {
        "response_type": "code",
        "client_id": "registered-client",
        "redirect_uri": REDIRECT,
        "scope": "openid",
        "state": "from-the-query",
    }
    params.update(extra)
    return params


def _loc_params(resp):
    return parse_qs(urlparse(resp.headers["Location"]).query)


def _failed_authorization_events(app):
    with app.app_context():
        from nanoidp.services import get_audit_log

        entries = get_audit_log().get_entries(event_type="authorization_request")
    return [entry for entry in entries if entry["status"] == "failed"]


class TestDiscoverySaysSo:
    @pytest.mark.parametrize(
        "path",
        ["/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"],
    )
    def test_both_flags_are_explicitly_false(self, client, path):
        doc = json.loads(client.get(path).data)
        assert doc["request_parameter_supported"] is False
        assert doc["request_uri_parameter_supported"] is False

    @pytest.mark.asyncio
    async def test_the_mcp_tool_says_the_same(self, app):
        from nanoidp.mcp_server import _execute_tool

        with app.app_context():
            doc = await _execute_tool("get_oidc_discovery", {}, get_config())
        assert doc["request_parameter_supported"] is False
        assert doc["request_uri_parameter_supported"] is False


class TestRefusal:
    def test_request_is_refused_to_the_validated_redirect_uri(self, client, app):
        with app.app_context():
            get_config().settings.issuer = HTTPS_ISSUER
        resp = client.get("/authorize", query_string=_query(request=REQUEST_OBJECT))
        assert resp.status_code == 302
        params = _loc_params(resp)
        assert params["error"] == ["request_not_supported"]
        assert params["error_description"] == ["The request parameter is not supported"]
        assert params["state"] == ["from-the-query"]
        assert params["iss"] == [HTTPS_ISSUER]
        assert "code" not in params
        assert urlparse(resp.headers["Location"]).path == "/callback"

    def test_request_uri_is_refused_with_its_own_error(self, client):
        resp = client.get("/authorize", query_string=_query(request_uri=REQUEST_URI))
        assert resp.status_code == 302
        params = _loc_params(resp)
        assert params["error"] == ["request_uri_not_supported"]
        assert params["error_description"] == ["The request_uri parameter is not supported"]
        assert params["state"] == ["from-the-query"]

    def test_a_repeated_parameter_is_refused_on_any_non_empty_value(self, client):
        """request=&request=<object>: the empty first value does not hide
        the object behind it (review round 3). Presence is what is refused,
        so every repetition counts; no value is read."""
        query = _query()
        resp = client.get(
            "/authorize",
            query_string=[*query.items(), ("request", ""), ("request", REQUEST_OBJECT)],
        )
        assert resp.status_code == 302
        assert _loc_params(resp)["error"] == ["request_not_supported"]

    def test_request_wins_when_both_are_sent(self, client):
        resp = client.get(
            "/authorize", query_string=_query(request=REQUEST_OBJECT, request_uri=REQUEST_URI)
        )
        assert _loc_params(resp)["error"] == ["request_not_supported"]

    def test_the_suite_shape_without_state_in_the_query(self, client):
        """The suite sends client_id, redirect_uri, request, response_type and
        scope; its state is inside the object and the response carries none
        (the suite checks none on this error)."""
        query = _query(request=REQUEST_OBJECT)
        del query["state"]
        resp = client.get("/authorize", query_string=query)
        assert resp.status_code == 302
        params = _loc_params(resp)
        assert params["error"] == ["request_not_supported"]
        assert "state" not in params

    def test_the_direct_post_entry_point_refuses_the_same_way(self, client):
        """A POST without transaction_id and with the request in its query
        string goes through the same validation as a GET (#325)."""
        resp = client.post(
            "/authorize",
            query_string=_query(request=REQUEST_OBJECT),
            data={"username": "admin", "password": "admin"},
        )
        assert resp.status_code == 302
        assert _loc_params(resp)["error"] == ["request_not_supported"]

    def test_a_refused_request_creates_no_transaction(self, client):
        client.get("/authorize", query_string=_query(request=REQUEST_OBJECT))
        assert pending_transaction_ids(client) == []


class TestEmptyValuesAreOmittedParameters:
    """RFC 6749 3.1: a parameter sent without a value is treated as omitted,
    as scope= and code_challenge_method= already are at this endpoint."""

    @pytest.mark.parametrize("field", ["request", "request_uri"])
    def test_an_empty_value_does_not_refuse(self, client, field):
        resp = client.get("/authorize", query_string=_query(**{field: ""}))
        assert resp.status_code == 200
        assert b"<form" in resp.data


class TestWhereTheErrorGoes:
    """The refusal is the answer whatever the rest of the request says; the
    rest decides only whether it is delivered or stays local."""

    @pytest.mark.parametrize(
        "shape",
        [
            pytest.param(
                {"redirect_uri": "http://localhost:3000/elsewhere"}, id="unregistered redirect_uri"
            ),
            pytest.param({"redirect_uri": "not a uri"}, id="malformed redirect_uri"),
            pytest.param({"client_id": "no-such-client"}, id="unknown client"),
        ],
    )
    def test_the_error_stays_local_without_a_validated_redirect_uri(self, client, shape):
        """A URI outside the client's registered list, a malformed one, or a
        client that does not exist never receives anything (RFC 6749
        3.1.2.4): the refusal is answered locally, with its own code."""
        resp = client.get("/authorize", query_string=_query(request=REQUEST_OBJECT, **shape))
        assert resp.status_code == 400
        assert resp.headers.get("Location") is None
        body = json.loads(resp.data)
        assert body["error"] == "request_not_supported"
        assert body["error_description"] == "The request parameter is not supported"

    def test_oauth21_keeps_the_refusal_local_for_a_client_without_registered_uris(
        self, client, app
    ):
        """Under oauth21 a client without registered redirect_uris cannot be
        used at /authorize (#68): the refusal may not be delivered to a URI
        that profile would not accept, so it stays local."""
        with app.app_context():
            get_config().settings.security_profile = "oauth21"
        resp = client.get(
            "/authorize", query_string=_query(client_id="demo-client", request=REQUEST_OBJECT)
        )
        assert resp.status_code == 400
        assert resp.headers.get("Location") is None
        assert json.loads(resp.data)["error"] == "request_not_supported"

    def test_core_6_1_shape_with_the_redirect_uri_inside_the_object(self, client):
        """Core 6.1: only response_type and client_id must be in the query;
        a client may put its redirect_uri inside the object. With no
        redirect_uri in the query the refusal stays local, and it is the
        refusal, not 'redirect_uri is required' - nothing in the object was
        read, and that is the one thing the client needs to hear."""
        query = _query(request=REQUEST_OBJECT)
        del query["redirect_uri"]
        resp = client.get("/authorize", query_string=query)
        assert resp.status_code == 400
        assert resp.headers.get("Location") is None
        assert json.loads(resp.data)["error"] == "request_not_supported"

    def test_a_bare_request_object_is_a_request_and_is_refused(self, client):
        """A GET carrying only request= is a request (request is a request
        field), not a resume of the browser's pending transaction: it is
        refused locally, and the pending transaction is left as it was."""
        client.get("/authorize", query_string=_query())
        (pending,) = pending_transaction_ids(client)
        for field, error in (
            ("request", "request_not_supported"),
            ("request_uri", "request_uri_not_supported"),
        ):
            resp = client.get("/authorize", query_string={field: REQUEST_OBJECT})
            assert resp.status_code == 400, field
            assert json.loads(resp.data)["error"] == error
        assert pending_transaction_ids(client) == [pending]

    def test_a_request_object_in_the_post_body_is_ignored_and_audited(self, client, app):
        """#325: OAuth parameters in a POST body are never read, and their
        presence is audited as a forged request. request and request_uri
        are OAuth parameters."""
        client.get("/authorize", query_string=_query())
        resp = client.post(
            "/authorize",
            data={"username": "admin", "password": "admin", "request": REQUEST_OBJECT},
        )
        assert resp.status_code == 302
        assert "code" in parse_qs(urlparse(resp.headers["Location"]).query)
        forged = _failed_authorization_events(app)[0]
        assert forged["details"]["fields"] == ["request"]
        assert REQUEST_OBJECT not in json.dumps(forged)

    def test_a_repeated_request_object_in_the_post_body_is_still_audited(self, client, app):
        """request=&request=<object> in the body: the empty first value does
        not hide the forged field from the audit (review round 7)."""
        client.get("/authorize", query_string=_query())
        resp = client.post(
            "/authorize",
            data=MultiDict(
                [
                    ("username", "admin"),
                    ("password", "admin"),
                    ("request", ""),
                    ("request", REQUEST_OBJECT),
                ]
            ),
        )
        assert resp.status_code == 302
        assert _failed_authorization_events(app)[0]["details"]["fields"] == ["request"]

    def test_a_named_transaction_refuses_a_request_object_added_to_its_query(self, client):
        """A POST naming its transaction must carry the query string that
        created it (#346): request= added to it is a different request."""
        page = client.get("/authorize", query_string=_query())
        (transaction_id,) = pending_transaction_ids(client)
        assert transaction_id.encode() in page.data
        resp = client.post(
            "/authorize",
            query_string=_query(request=REQUEST_OBJECT),
            data={"transaction_id": transaction_id, "username": "admin", "password": "admin"},
        )
        assert resp.status_code == 400
        assert resp.headers.get("Location") is None
        assert json.loads(resp.data)["error"] == "invalid_request"

    def test_the_refusal_comes_before_response_type(self, client):
        """A request inside an object is answered with the one error that
        says why nothing in it was read, whatever else the query says."""
        resp = client.get(
            "/authorize", query_string=_query(response_type="token", request=REQUEST_OBJECT)
        )
        assert _loc_params(resp)["error"] == ["request_not_supported"]

    def test_a_request_without_an_object_is_untouched(self, client):
        resp = client.get("/authorize", query_string=_query())
        assert resp.status_code == 200
        assert len(pending_transaction_ids(client)) == 1


class TestAudit:
    @pytest.mark.parametrize(
        ("shape", "client_id", "undeliverable"),
        [
            pytest.param({}, "registered-client", None, id="delivered"),
            pytest.param(
                {"redirect_uri": "http://localhost:3000/elsewhere"},
                "registered-client",
                "redirect_uri not registered for client",
                id="unregistered redirect_uri",
            ),
            pytest.param(
                {"redirect_uri": "not a uri"},
                "registered-client",
                "redirect_uri invalid",
                id="malformed",
            ),
            pytest.param(
                {"client_id": "no-such-client"}, "no-such-client", "Unknown client", id="unknown"
            ),
            pytest.param({"client_id": ""}, None, "client_id is required", id="no client_id"),
            pytest.param(
                {"redirect_uri": ""}, "registered-client", "redirect_uri is required", id="no uri"
            ),
        ],
    )
    def test_one_refusal_is_one_failed_event(self, client, app, shape, client_id, undeliverable):
        """The request is refused before any validator runs, so the audit
        log gains exactly one failed authorization_request event for it,
        the refusal's own (a client lookup may write its own
        client_metadata_document_refused, as for any request), with
        the client_id the request named or None (review round 2: the first
        cut ran the validators for their verdict and kept their audit
        entries, two events per refusal). What those validators used to
        say is in the event instead: whether the refusal was delivered,
        and why not, in the words the validators use (review rounds 4
        and 5)."""
        before = len(_failed_authorization_events(app))
        client.get("/authorize", query_string=_query(request=REQUEST_OBJECT, **shape))
        events = _failed_authorization_events(app)
        assert len(events) == before + 1
        details = events[0]["details"]
        assert details["reason"] == "request parameter is not supported"
        assert events[0]["client_id"] == client_id
        assert details["delivered"] is (undeliverable is None)
        assert details.get("undeliverable") == undeliverable

    def test_a_client_is_looked_up_as_any_request_s_is(self, client, monkeypatch):
        """A client_id that is a URL names a client this server learns by
        fetching its document (#196). The refusal looks it up exactly as
        the ordinary validation does, the fetch included: a refusal that
        read only the cache answered 302 or 400 by whether the document
        was cached, which disclosed that the client had been here lately
        (review round 6). Here the document cannot be learned, so the
        refusal stays local."""
        import nanoidp.routes.oauth as oauth

        looked_up = []
        monkeypatch.setattr(
            oauth, "_client_from_metadata_document", lambda config, cid: looked_up.append(cid)
        )
        resp = client.get(
            "/authorize",
            query_string=_query(client_id="https://rp.example/client", request=REQUEST_OBJECT),
        )
        assert looked_up == ["https://rp.example/client"]
        assert resp.status_code == 400
        assert resp.headers.get("Location") is None
        assert json.loads(resp.data)["error"] == "request_not_supported"

    def test_the_reason_names_the_parameter_and_records_no_value(self, client, app):
        client.get("/authorize", query_string=_query(request=REQUEST_OBJECT))
        client.get("/authorize", query_string=_query(request_uri=REQUEST_URI))
        # Newest first.
        reasons = [entry["details"]["reason"] for entry in _failed_authorization_events(app)]
        assert reasons[:2] == [
            "request_uri parameter is not supported",
            "request parameter is not supported",
        ]
        recorded = json.dumps(_failed_authorization_events(app))
        assert REQUEST_OBJECT not in recorded
        assert REQUEST_URI not in recorded
        last = _failed_authorization_events(app)[0]
        assert last["client_id"] == "registered-client"
        assert last["endpoint"] == "/authorize"


class TestTheValidatorsKeepTheirAuditHistory:
    """The verdict helpers the refusal reads were extracted from the
    validators; the validators must audit exactly as before: an unknown
    client is a failed event, a missing required parameter never was."""

    def test_an_unknown_client_is_still_one_failed_event(self, client, app):
        before = len(_failed_authorization_events(app))
        resp = client.get("/authorize", query_string=_query(client_id="no-such-client"))
        assert resp.status_code == 400
        events = _failed_authorization_events(app)
        assert len(events) == before + 1
        assert events[0]["details"] == {"reason": "Unknown client"}

    @pytest.mark.parametrize("field", ["client_id", "redirect_uri"])
    def test_a_missing_required_parameter_is_still_not_audited(self, client, app, field):
        before = len(_failed_authorization_events(app))
        resp = client.get("/authorize", query_string=_query(**{field: ""}))
        assert resp.status_code == 400
        assert json.loads(resp.data)["error_description"] == f"{field} is required"
        assert len(_failed_authorization_events(app)) == before

    def test_details_never_overwrite_the_audit_reason(self, client, app):
        """The helpers merge the caller's details under the reason, so no
        caller can replace the reason by accident."""
        from nanoidp.routes import oauth

        with app.test_request_context("/authorize"):
            oauth._authorize_reject(
                "registered-client", "the reason", "invalid_request", "x", details={"reason": "no"}
            )
        assert _failed_authorization_events(app)[0]["details"]["reason"] == "the reason"
