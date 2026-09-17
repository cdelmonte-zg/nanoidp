"""Verified SAML Redirect AuthnRequests, one per flow (#375).

With `saml.want_authn_requests_signed`, the Redirect signature cannot
survive the login form's round trip, so a verified GET is remembered and the
login leg asks whether this browser had exactly that request verified. It
used to be remembered in one session slot, so a second signed request in the
same browser made the first non-continuable. These tests hold the fix and
the bounds the issue states.
"""

import base64
import time
import zlib
from urllib.parse import quote

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from nanoidp.config import get_config
from nanoidp.services import saml_verified_requests as store_module
from nanoidp.services.saml_verified_requests import (
    VerifiedRequestStoreFull,
    get_verified_request_store,
    request_digest,
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


def _records():
    return get_verified_request_store()._repository.list()


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


class TestBounds:
    def test_a_browsers_eleventh_request_drops_its_oldest(self, client, signed_mode):
        ids = [f"_flow-{n}".encode() for n in range(store_module.MAX_VERIFIED_REQUESTS_PER_BROWSER)]
        for request_id in ids:
            assert client.get(f"/saml/sso?{_signed_query(request_id)}").status_code == 200

        assert client.get(f"/saml/sso?{_signed_query(b'_flow-new')}").status_code == 200

        assert len(_records()) == store_module.MAX_VERIFIED_REQUESTS_PER_BROWSER
        assert _login_leg(client, ids[0]).status_code == 400
        assert b"SAMLResponse" in _login_leg(client, ids[1]).data
        assert b"SAMLResponse" in _login_leg(client, b"_flow-new").data

    def test_re_verifying_the_same_request_refreshes_it_and_frees_no_room(
        self, client, signed_mode
    ):
        for _ in range(3):
            assert client.get(f"/saml/sso?{_signed_query(b'_same')}").status_code == 200

        assert len(_records()) == 1
        assert b"SAMLResponse" in _login_leg(client, b"_same").data

    def test_a_verification_expires(self, client, signed_mode, monkeypatch):
        assert client.get(f"/saml/sso?{_signed_query()}").status_code == 200
        later = time.time() + store_module.VERIFIED_REQUEST_LIFETIME_SECONDS + 1
        monkeypatch.setattr(store_module.time, "time", lambda: later)

        response = _login_leg(client)

        assert response.status_code == 400
        assert b"signature-verified request" in response.data

    def test_a_full_store_refuses_the_new_verification(self, client, signed_mode, monkeypatch):
        monkeypatch.setattr(store_module, "MAX_VERIFIED_REQUESTS", 1)
        assert client.get(f"/saml/sso?{_signed_query(b'_first')}").status_code == 200

        refused = client.get(f"/saml/sso?{_signed_query(b'_second')}")

        assert refused.status_code == 503
        # The flow already verified is untouched.
        assert b"SAMLResponse" in _login_leg(client, b"_first").data


class TestStore:
    def _remember(self, binding="browser-a", request="req", relay="RS"):
        return get_verified_request_store().remember_verified(binding, request, relay)

    def test_the_digest_covers_the_request_and_the_relay_state_only(self):
        assert request_digest("r", "s") == request_digest("r", "s")
        assert request_digest("r", "s") != request_digest("r", "t")
        assert request_digest("rs", "") != request_digest("r", "s")

    def test_a_verification_belongs_to_one_browser(self):
        self._remember(binding="browser-a")
        store = get_verified_request_store()

        assert store.is_verified("browser-a", "req", "RS")
        assert not store.is_verified("browser-b", "req", "RS")
        assert not store.is_verified(None, "req", "RS")
        assert not store.is_verified("browser-a", "other", "RS")

    def test_the_same_request_in_two_browsers_is_two_records(self):
        self._remember(binding="browser-a")
        self._remember(binding="browser-b")
        store = get_verified_request_store()

        assert len(_records()) == 2
        assert store.is_verified("browser-a", "req", "RS")
        assert store.is_verified("browser-b", "req", "RS")

    def test_eviction_only_drops_the_same_browsers_oldest(self, monkeypatch):
        monkeypatch.setattr(store_module, "MAX_VERIFIED_REQUESTS_PER_BROWSER", 2)
        self._remember(binding="browser-b", request="theirs")
        self._remember(request="first")
        self._remember(request="second")

        self._remember(request="third")

        store = get_verified_request_store()
        assert not store.is_verified("browser-a", "first", "RS")
        assert store.is_verified("browser-a", "second", "RS")
        assert store.is_verified("browser-a", "third", "RS")
        assert store.is_verified("browser-b", "theirs", "RS")

    def test_the_global_cap_refuses_rather_than_dropping_another_browser(self, monkeypatch):
        monkeypatch.setattr(store_module, "MAX_VERIFIED_REQUESTS", 1)
        self._remember(binding="browser-a", request="first")

        with pytest.raises(VerifiedRequestStoreFull):
            self._remember(binding="browser-b", request="second")

        assert get_verified_request_store().is_verified("browser-a", "first", "RS")

    def test_expired_records_are_pruned_and_make_room(self, monkeypatch):
        monkeypatch.setattr(store_module, "MAX_VERIFIED_REQUESTS", 1)
        self._remember(request="old")
        later = time.time() + store_module.VERIFIED_REQUEST_LIFETIME_SECONDS + 1
        monkeypatch.setattr(store_module.time, "time", lambda: later)

        assert self._remember(request="new") is not None
        assert get_verified_request_store().is_verified("browser-a", "new", "RS")

    def test_a_record_holds_no_request_content(self):
        record = self._remember(request="the-whole-authn-request")

        assert "the-whole-authn-request" not in record.model_dump_json()
