"""
One request, one client identity (#277).

/token has always resolved the client as body-or-Basic and rejected a
mismatch between the two channels. /introspect, /revoke and
/device_authorization used to resolve header-first and check nothing, so
HTTP Basic for client A plus client_id=B in the body was silently processed
as A. All four endpoints now share _request_client_identity(): a request
naming two different clients is invalid_client everywhere.

Uses the shipped config's demo-client (unrestricted) and scoped-client;
both confidential with client_secret_basic, so Basic alone stays the valid
authentication and only the contradictory body client_id trips the check.
"""

import base64
import json

import pytest


@pytest.fixture(autouse=True)
def _cleanup_device_codes():
    yield
    from nanoidp.services.device_code import get_device_code_store

    get_device_code_store().clear()


def _basic(client_id: str, secret: str) -> dict:
    credentials = base64.b64encode(f"{client_id}:{secret}".encode()).decode()
    return {"Authorization": f"Basic {credentials}"}


DEMO_AUTH = _basic("demo-client", "demo-secret")


def _mint_token(client) -> str:
    resp = client.post(
        "/token",
        data={"grant_type": "password", "username": "admin", "password": "admin"},
        headers=DEMO_AUTH,
    )
    assert resp.status_code == 200
    return json.loads(resp.data)["access_token"]


class TestMismatchRejectedEverywhere:
    def test_token_mismatch_rejected(self, client):
        """The pre-existing /token behavior, pinned for parity."""
        resp = client.post(
            "/token",
            data={
                "grant_type": "password",
                "username": "admin",
                "password": "admin",
                "client_id": "scoped-client",
            },
            headers=DEMO_AUTH,
        )
        # §5.2 JSON with the Basic challenge since #310 (the old
        # status-only assertion was exactly the kind of pin #308 blamed).
        assert resp.status_code == 401
        assert resp.get_json()["error"] == "invalid_client"
        assert resp.headers.get("WWW-Authenticate", "").startswith("Basic")

    def test_introspect_mismatch_rejected(self, client):
        token = _mint_token(client)
        resp = client.post(
            "/introspect",
            data={"token": token, "client_id": "scoped-client"},
            headers=DEMO_AUTH,
        )
        assert resp.status_code == 401
        assert json.loads(resp.data)["error"] == "invalid_client"

    def test_revoke_mismatch_rejected_and_revokes_nothing(self, client):
        token = _mint_token(client)
        resp = client.post(
            "/revoke",
            data={"token": token, "client_id": "scoped-client"},
            headers=DEMO_AUTH,
        )
        assert resp.status_code == 401
        assert json.loads(resp.data)["error"] == "invalid_client"
        # The token must NOT have been revoked by the rejected request.
        check = client.post("/introspect", data={"token": token}, headers=DEMO_AUTH)
        assert check.status_code == 200
        assert json.loads(check.data)["active"] is True

    def test_device_authorization_mismatch_rejected(self, client):
        resp = client.post(
            "/device_authorization",
            data={"client_id": "scoped-client"},
            headers=DEMO_AUTH,
        )
        assert resp.status_code == 401
        assert json.loads(resp.data)["error"] == "invalid_client"


class TestMatchingBodyClientIdStillAccepted:
    """Basic plus a body client_id naming the SAME client is one identity,
    not two - it must keep working at every endpoint."""

    def test_introspect_matching_body_id_ok(self, client):
        token = _mint_token(client)
        resp = client.post(
            "/introspect",
            data={"token": token, "client_id": "demo-client"},
            headers=DEMO_AUTH,
        )
        assert resp.status_code == 200
        assert json.loads(resp.data)["active"] is True

    def test_device_authorization_matching_body_id_ok(self, client):
        resp = client.post(
            "/device_authorization",
            data={"client_id": "demo-client"},
            headers=DEMO_AUTH,
        )
        assert resp.status_code == 200
        assert "device_code" in json.loads(resp.data)
