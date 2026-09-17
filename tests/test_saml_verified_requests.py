"""The Redirect AuthnRequests a browser has had verified (#375).

With `saml.want_authn_requests_signed`, the Redirect signature cannot
survive the login form's round trip, so a verified GET is remembered in the
browser's own session and the login leg is admitted only for a request that
set says was verified. It used to be one slot, so a second signed request in
the same browser made the first non-continuable. These tests hold the fix,
the bounds, and the property that nothing here is shared between browsers.
"""

import base64
import time
import zlib
from urllib.parse import quote

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from nanoidp.config import get_config
from nanoidp.services import saml_verified_requests as verified_module
from nanoidp.services.saml_verified_requests import (
    VerificationState,
    remember_verified,
    request_digest,
    state_of,
)
from tests.test_saml_signed_authnrequests import AUTHN_REQUEST, RSA_SHA256, SP_CERT, SP_KEY


@pytest.fixture
def signed_mode(app, tmp_path):
    """Verification on, with the SP certificate registered."""
    cert_path = tmp_path / "sp-cert.pem"
    cert_path.write_bytes(SP_CERT.public_bytes(serialization.Encoding.PEM))
    with app.app_context():
        settings = get_config().settings
        settings.saml_want_authn_requests_signed = True
        settings.saml_sp_certificates = [str(cert_path)]
    yield settings
    settings.saml_want_authn_requests_signed = False
    settings.saml_sp_certificates = []


def _request_b64(request_id: bytes) -> str:
    deflated = zlib.compress(AUTHN_REQUEST.replace(b"_sig-test-1", request_id), 9)[2:-4]
    return base64.b64encode(deflated).decode()


def _signed_query(request_id: bytes = b"_sig-test-1", relay_state="RS") -> str:
    """A signed HTTP-Redirect query string for this request id."""
    parts = [f"SAMLRequest={quote(_request_b64(request_id), safe='')}"]
    if relay_state is not None:
        parts.append(f"RelayState={quote(relay_state, safe='')}")
    parts.append(f"SigAlg={quote(RSA_SHA256, safe='')}")
    signature = SP_KEY.sign("&".join(parts).encode(), padding.PKCS1v15(), hashes.SHA256())
    return "&".join(parts) + f"&Signature={quote(base64.b64encode(signature).decode(), safe='')}"


def _login_leg(client, request_id: bytes = b"_sig-test-1", relay_state="RS"):
    return client.post(
        "/saml/sso",
        data={
            "SAMLRequest": _request_b64(request_id),
            "RelayState": relay_state,
            "saml_original_verb": "GET",
            "username": "admin",
            "password": "admin",
        },
    )


def _remembered(client):
    with client.session_transaction() as session:
        return list(session.get("saml_verified_redirects") or [])


class TestConcurrentFlows:
    def test_two_signed_requests_in_one_browser_both_stay_continuable(
        self, client, signed_mode
    ):
        """The defect: tab B's verified GET used to make tab A's request
        non-continuable."""
        assert client.get(f"/saml/sso?{_signed_query(b'_tab-a')}").status_code == 200
        assert client.get(f"/saml/sso?{_signed_query(b'_tab-b')}").status_code == 200

        for request_id in (b"_tab-a", b"_tab-b"):
            response = _login_leg(client, request_id)
            assert response.status_code == 200
            assert b"SAMLResponse" in response.data

    def test_another_browsers_verification_does_not_admit_this_one(
        self, app, client, signed_mode
    ):
        other = app.test_client()
        assert other.get(f"/saml/sso?{_signed_query()}").status_code == 200

        response = _login_leg(client)

        assert response.status_code == 400
        assert b"signature-verified request" in response.data

    def test_a_relay_state_of_another_flow_is_not_admitted(self, client, signed_mode):
        assert client.get(f"/saml/sso?{_signed_query(relay_state='one')}").status_code == 200

        response = _login_leg(client, relay_state="two")

        assert response.status_code == 400
        assert b"signature-verified request" in response.data

    def test_nothing_is_shared_between_browsers(self, app, client, signed_mode):
        """#375: the state lives in each browser's own session, so a client
        that keeps discarding its cookie cannot affect anyone else. The
        server-side store this replaced could be filled by replaying one
        signed URL, which then refused every browser."""
        query = _signed_query()
        for _ in range(3 * verified_module.MAX_VERIFIED_REQUESTS):
            assert app.test_client().get(f"/saml/sso?{query}").status_code == 200

        assert client.get(f"/saml/sso?{query}").status_code == 200
        assert b"SAMLResponse" in _login_leg(client).data


class TestBounds:
    def test_a_browsers_eleventh_request_drops_its_oldest(self, client, signed_mode):
        ids = [f"_flow-{n}".encode() for n in range(verified_module.MAX_VERIFIED_REQUESTS)]
        for request_id in ids:
            assert client.get(f"/saml/sso?{_signed_query(request_id)}").status_code == 200

        assert client.get(f"/saml/sso?{_signed_query(b'_flow-new')}").status_code == 200

        assert len(_remembered(client)) == verified_module.MAX_VERIFIED_REQUESTS
        assert _login_leg(client, ids[0]).status_code == 400
        assert b"SAMLResponse" in _login_leg(client, ids[1]).data
        assert b"SAMLResponse" in _login_leg(client, b"_flow-new").data

    def test_re_verifying_the_same_request_frees_no_room(self, client, signed_mode):
        for _ in range(3):
            assert client.get(f"/saml/sso?{_signed_query(b'_same')}").status_code == 200

        assert len(_remembered(client)) == 1
        assert b"SAMLResponse" in _login_leg(client, b"_same").data

    def test_a_verification_expires(self, client, signed_mode, monkeypatch):
        assert client.get(f"/saml/sso?{_signed_query()}").status_code == 200
        later = time.time() + verified_module.VERIFIED_REQUEST_LIFETIME_SECONDS + 1
        monkeypatch.setattr(verified_module.time, "time", lambda: later)

        response = _login_leg(client)

        assert response.status_code == 400
        assert b"expired" in response.data

    def test_continuing_a_flow_keeps_it_alive(self, app, client, signed_mode, monkeypatch):
        """A login can take several screens: each leg refreshes it."""
        with app.app_context():
            get_config().settings.two_step = True
        assert client.get(f"/saml/sso?{_signed_query()}").status_code == 200

        clock = time.time()
        monkeypatch.setattr(verified_module.time, "time", lambda: clock)
        for _ in range(4):
            clock += verified_module.VERIFIED_REQUEST_LIFETIME_SECONDS - 60
            username_step = client.post(
                "/saml/sso",
                data={
                    "SAMLRequest": _request_b64(b"_sig-test-1"),
                    "RelayState": "RS",
                    "saml_original_verb": "GET",
                    "username": "admin",
                },
            )
            assert username_step.status_code == 200
            assert b'name="password"' in username_step.data

        assert b"SAMLResponse" in _login_leg(client).data

    def test_an_already_signed_in_browser_remembers_nothing(self, client, signed_mode):
        """#375: a browser that completes the SSO on the GET itself has no
        continuation to remember."""
        with client.session_transaction() as session:
            session["user"] = "admin"

        response = client.get(f"/saml/sso?{_signed_query()}")

        assert b"SAMLResponse" in response.data
        assert _remembered(client) == []


    def test_a_post_binding_entry_remembers_nothing(self, client, signed_mode):
        """Only a verified Redirect GET is remembered. A POST-binding entry
        carries its signature inside the XML and is verified again on every
        leg, so remembering it would let a Redirect-leg continuation of the
        same request skip that verification."""
        from tests.test_saml_signed_authnrequests import _signed_post_request

        signed_xml = _signed_post_request()
        page = client.post("/saml/sso", data={"SAMLRequest": signed_xml})
        assert page.status_code == 200
        assert b"username" in page.data

        assert _remembered(client) == []
        refused = client.post(
            "/saml/sso",
            data={
                "SAMLRequest": signed_xml,
                "saml_original_verb": "GET",
                "username": "admin",
                "password": "admin",
            },
        )
        assert refused.status_code == 400
        assert b"SAMLResponse" not in refused.data


class TestTheRememberedSet:
    """The bounded expiring set itself, without Flask."""

    def test_the_digest_covers_the_request_and_the_relay_state_only(self):
        assert request_digest("r", "s") == request_digest("r", "s")
        assert request_digest("r", "s") != request_digest("r", "t")
        assert request_digest("rs", "") != request_digest("r", "s")
        # base64url of a full SHA-256, unpadded.
        assert len(request_digest("r", "s")) == 43

    def test_verified_then_expired_then_unknown(self):
        entries = remember_verified([], "d", now=1000.0)

        assert state_of(entries, "d", now=1000.0)[0] is VerificationState.VERIFIED
        assert state_of(entries, "other", now=1000.0)[0] is VerificationState.UNKNOWN
        late = 1000.0 + verified_module.VERIFIED_REQUEST_LIFETIME_SECONDS + 1
        state, live = state_of(entries, "d", now=late)
        assert state is VerificationState.EXPIRED
        assert live == []

    def test_re_verifying_refreshes_instead_of_appending(self):
        entries = remember_verified([], "d", now=1000.0)
        entries = remember_verified(entries, "d", now=1500.0)

        assert entries == [["d", 1500.0]]

    def test_the_oldest_is_dropped_past_the_cap(self):
        entries = []
        for n in range(verified_module.MAX_VERIFIED_REQUESTS + 2):
            entries = remember_verified(entries, f"d{n}", now=1000.0 + n)

        assert len(entries) == verified_module.MAX_VERIFIED_REQUESTS
        assert state_of(entries, "d0", now=1100.0)[0] is VerificationState.UNKNOWN
        assert state_of(entries, "d2", now=1100.0)[0] is VerificationState.VERIFIED

    @pytest.mark.parametrize(
        "remembered",
        ["not-a-list", None, [["d"]], [{"digest": "d"}], [["d", "not-a-number"]], [["d", True]]],
    )
    def test_anything_else_under_the_key_reads_as_nothing_remembered(self, remembered):
        """The session is signed, not trusted to have this shape: an older
        build or a hand-edited test session must read as empty, not raise."""
        assert state_of(remembered, "d")[0] is VerificationState.UNKNOWN
        assert remember_verified(remembered, "d", now=1000.0) == [["d", 1000.0]]
