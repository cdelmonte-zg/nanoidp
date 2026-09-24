"""Pending second factors on /login, /saml/sso and /device (#373).

A verified password waiting for its TOTP code is recorded on the server and
the code screen carries only an opaque reference. These tests hold the rules
the issue states: no secret in a record or a page, bound to the browser, the
surface and the context, single use, the current secret, fail closed, the
lifecycle transitions, the bounded store, and the stateless combined POST.
"""

import base64
import json
import re
import time

import pytest

from nanoidp.config import get_config
from nanoidp.services import pending_second_factors as pending_module
from nanoidp.services.pending_second_factors import (
    PendingSecondFactor,
    PendingSecondFactorStoreFull,
    context_digest,
    get_pending_second_factor_store,
)
from nanoidp.services.totp import generate_totp

_SECRET = base64.b32encode(b"12345678901234567890").decode("ascii")
_OTHER_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"


@pytest.fixture(autouse=True)
def totp(app):
    with app.app_context():
        get_config().settings.totp = True
        get_config().users["admin"].totp_secret = _SECRET


def _records():
    return get_pending_second_factor_store()._repository.list()


def _pending_id(response):
    match = re.search(r'name="pending_second_factor" value="([^"]+)"', response.get_data(as_text=True))
    assert match, "the page names no pending second factor"
    return match.group(1)


def _authn_request(request_id="_pending_test", acs_url="http://localhost:9999/sp/acs"):
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{request_id}" Version="2.0" IssueInstant="2025-01-01T00:00:00Z"
    AssertionConsumerServiceURL="{acs_url}">
    <saml:Issuer>http://sp.example.com</saml:Issuer>
</samlp:AuthnRequest>"""
    return base64.b64encode(xml.encode("utf-8")).decode("ascii")


class Surface:
    """One surface's form fields, and how to tell that its login completed."""

    name = ""
    path = ""

    def context_fields(self, client, auth_header):
        return {}

    def completed(self, app, client, response):
        raise NotImplementedError

    def not_completed(self, app, client, response):
        raise NotImplementedError


class Login(Surface):
    name = "login"
    path = "/login"

    def completed(self, app, client, response):
        with client.session_transaction() as session:
            return (
                response.status_code == 302
                and session.get("user") == "admin"
                and session.get("auth_method") == "password_otp"
            )

    def not_completed(self, app, client, response):
        with client.session_transaction() as session:
            return session.get("user") is None


class SamlSso(Surface):
    name = "saml_sso"
    path = "/saml/sso"

    def context_fields(self, client, auth_header):
        return {"SAMLRequest": _authn_request(), "RelayState": "relay-1"}

    def completed(self, app, client, response):
        match = re.search(rb'name="SAMLResponse" value="([^"]+)"', response.data)
        if not match:
            return False
        xml = base64.b64decode(match.group(1))
        return b"TimeSyncToken" in xml

    def not_completed(self, app, client, response):
        with client.session_transaction() as session:
            return b"SAMLResponse" not in response.data and session.get("user") is None


class Device(Surface):
    name = "device"
    path = "/device"

    def context_fields(self, client, auth_header):
        response = client.post("/device_authorization", headers=auth_header)
        data = json.loads(response.data)
        self.device_code = data["device_code"]
        return {"user_code": data["user_code"]}

    def completed(self, app, client, response):
        return b"the device has been authorized" in response.data.lower()

    def not_completed(self, app, client, response):
        return b"the device has been authorized" not in response.data.lower()


SURFACES = [Login(), SamlSso(), Device()]


@pytest.fixture(params=SURFACES, ids=lambda s: s.name)
def surface(request):
    return request.param


def _code_screen(client, surface, context):
    screen = client.post(surface.path, data={**context, "username": "admin", "password": "admin"})
    assert screen.status_code == 200
    assert b'name="totp_code"' in screen.data
    return screen


class TestStore:
    def _create(self, store, binding="browser-a", purpose="login", context=None):
        return store.create(
            browser_binding=binding,
            purpose=purpose,
            context=context or {},
            username="admin",
            amr=["pwd"],
        )

    def test_the_context_digest_is_canonical(self):
        assert context_digest({"a": "1", "b": "2"}) == context_digest({"b": "2", "a": "1"})
        # No concatenation collision: "ab"+"c" and "a"+"bc" read the same.
        assert context_digest({"ab": "c"}) != context_digest({"a": "bc"})

    def test_a_record_is_only_for_its_browser_surface_and_context(self):
        store = get_pending_second_factor_store()
        record = self._create(store, purpose="device", context={"user_code": "ABCD1234"})
        get = store.get_bound

        assert get(record.id, "browser-a", purpose="device", context={"user_code": "ABCD1234"})
        assert not get(record.id, "browser-b", purpose="device", context={"user_code": "ABCD1234"})
        assert not get(record.id, "browser-a", purpose="login", context={"user_code": "ABCD1234"})
        assert not get(record.id, "browser-a", purpose="device", context={"user_code": "WXYZ9876"})

    def test_consume_succeeds_exactly_once(self):
        store = get_pending_second_factor_store()
        record = self._create(store)

        assert store.consume(record.id, "browser-a", purpose="login", context={}) is not None
        assert store.consume(record.id, "browser-a", purpose="login", context={}) is None

    def test_discard_only_drops_this_browsers_record_for_its_surface_and_context(self):
        store = get_pending_second_factor_store()
        record = self._create(store)

        discard = store.discard
        assert discard(record.id, "browser-b", purpose="login", context={}) is None
        assert discard(record.id, None, purpose="login", context={}) is None
        assert discard(record.id, "browser-a", purpose="device", context={}) is None
        assert discard(record.id, "browser-a", purpose="login", context={"x": "y"}) is None
        assert discard(record.id, "browser-a", purpose="login", context={}) is not None
        assert _records() == []

    def test_an_expired_record_is_not_found_and_makes_room(self, monkeypatch):
        monkeypatch.setattr(pending_module, "MAX_PENDING_SECOND_FACTORS", 1)
        store = get_pending_second_factor_store()
        record = self._create(store)
        later = time.time() + pending_module.PENDING_SECOND_FACTOR_LIFETIME_SECONDS + 1
        monkeypatch.setattr(pending_module.time, "time", lambda: later)

        assert store.get_bound(record.id, "browser-a", purpose="login", context={}) is None
        assert self._create(store) is not None

    def test_live_records_are_never_evicted_and_a_full_store_refuses(self, monkeypatch):
        monkeypatch.setattr(pending_module, "MAX_PENDING_SECOND_FACTORS", 1)
        store = get_pending_second_factor_store()
        first = self._create(store)

        with pytest.raises(PendingSecondFactorStoreFull):
            self._create(store)
        assert store.get_bound(first.id, "browser-a", purpose="login", context={}) is not None

    def test_a_record_has_no_credential_field(self):
        fields = set(PendingSecondFactor.model_fields)
        assert not {"password", "totp_secret", "user", "client_secret"} & fields


class TestCodeScreen:
    def test_the_page_and_the_record_hold_no_secret(self, app, client, auth_header, surface):
        with app.app_context():
            get_config().users["admin"].password = "pw-373-marker"
        context = surface.context_fields(client, auth_header)

        screen = client.post(
            surface.path, data={**context, "username": "admin", "password": "pw-373-marker"}
        )

        assert b'name="totp_code"' in screen.data
        assert b"pw-373-marker" not in screen.data
        assert b'name="password"' not in screen.data
        assert screen.headers["Cache-Control"] == "no-store"
        (record,) = _records()
        assert record.purpose == surface.name
        assert "pw-373-marker" not in record.model_dump_json()
        assert _SECRET not in record.model_dump_json()

    def test_the_code_alone_completes_and_a_username_in_the_form_is_ignored(
        self, app, client, auth_header, surface
    ):
        context = surface.context_fields(client, auth_header)
        pending = _pending_id(_code_screen(client, surface, context))

        response = client.post(
            surface.path,
            data={
                **context,
                "pending_second_factor": pending,
                "username": "user1",
                "totp_code": generate_totp(_SECRET),
            },
        )

        assert surface.completed(app, client, response)
        assert _records() == []

    def test_a_wrong_code_keeps_the_record_and_a_right_one_then_completes(
        self, app, client, auth_header, surface
    ):
        context = surface.context_fields(client, auth_header)
        pending = _pending_id(_code_screen(client, surface, context))

        wrong = client.post(
            surface.path, data={**context, "pending_second_factor": pending, "totp_code": "000000"}
        )
        assert b"Invalid code" in wrong.data
        assert _pending_id(wrong) == pending

        right = client.post(
            surface.path,
            data={**context, "pending_second_factor": pending, "totp_code": generate_totp(_SECRET)},
        )
        assert surface.completed(app, client, right)

    def test_the_current_secret_applies(self, app, client, auth_header, surface):
        context = surface.context_fields(client, auth_header)
        pending = _pending_id(_code_screen(client, surface, context))
        with app.app_context():
            get_config().users["admin"].totp_secret = _OTHER_SECRET

        stale = client.post(
            surface.path,
            data={**context, "pending_second_factor": pending, "totp_code": generate_totp(_SECRET)},
        )
        assert b"Invalid code" in stale.data

        current = client.post(
            surface.path,
            data={
                **context,
                "pending_second_factor": pending,
                "totp_code": generate_totp(_OTHER_SECRET),
            },
        )
        assert surface.completed(app, client, current)

    def test_a_completed_record_cannot_be_replayed(self, app, client, auth_header, surface):
        if surface.name == "device":
            pytest.skip("a used user_code is refused by the device store before the record")
        context = surface.context_fields(client, auth_header)
        pending = _pending_id(_code_screen(client, surface, context))
        data = {**context, "pending_second_factor": pending, "totp_code": generate_totp(_SECRET)}
        assert surface.completed(app, client, client.post(surface.path, data=data))
        with client.session_transaction() as session:
            session.pop("user", None)
            session.pop("auth_method", None)

        replay = client.post(surface.path, data=data)

        assert b"Your sign-in has expired" in replay.data
        assert surface.not_completed(app, client, replay)

    def test_a_record_from_another_browser_is_refused(self, app, client, auth_header, surface):
        context = surface.context_fields(client, auth_header)
        pending = _pending_id(_code_screen(client, surface, context))

        attacker = app.test_client()
        stolen = attacker.post(
            surface.path,
            data={**context, "pending_second_factor": pending, "totp_code": generate_totp(_SECRET)},
        )

        assert b"Your sign-in has expired" in stolen.data
        assert surface.not_completed(app, attacker, stolen)
        assert len(_records()) == 1

    def test_an_expired_record_is_refused(self, app, client, auth_header, surface, monkeypatch):
        context = surface.context_fields(client, auth_header)
        pending = _pending_id(_code_screen(client, surface, context))
        later = time.time() + pending_module.PENDING_SECOND_FACTOR_LIFETIME_SECONDS + 1
        monkeypatch.setattr(pending_module.time, "time", lambda: later)

        response = client.post(
            surface.path,
            data={**context, "pending_second_factor": pending, "totp_code": generate_totp(_SECRET)},
        )

        assert b"Your sign-in has expired" in response.data
        assert surface.not_completed(app, client, response)

    @pytest.mark.parametrize("change", ["user_deleted", "secret_removed", "totp_off", "persona_on"])
    def test_a_verified_password_never_completes_on_its_own(
        self, app, client, auth_header, surface, change
    ):
        context = surface.context_fields(client, auth_header)
        pending = _pending_id(_code_screen(client, surface, context))
        with app.app_context():
            config = get_config()
            if change == "user_deleted":
                del config.users["admin"]
            elif change == "secret_removed":
                config.users["admin"].totp_secret = None
            elif change == "totp_off":
                config.settings.totp = False
            else:
                config.settings.login_mode = "persona"

        response = client.post(
            surface.path,
            data={**context, "pending_second_factor": pending, "totp_code": generate_totp(_SECRET)},
        )

        assert b"could not be completed" in response.data
        assert surface.not_completed(app, client, response)
        assert _records() == []

    def test_change_username_discards_the_record(self, app, client, auth_header, surface):
        context = surface.context_fields(client, auth_header)
        pending = _pending_id(_code_screen(client, surface, context))

        response = client.post(
            surface.path, data={**context, "pending_second_factor": pending, "change_username": "1"}
        )

        assert response.status_code == 200
        assert b'name="totp_code"' not in response.data
        assert _records() == []

    def test_a_full_store_refuses_the_code_screen(self, app, client, auth_header, surface, monkeypatch):
        monkeypatch.setattr(pending_module, "MAX_PENDING_SECOND_FACTORS", 0)
        context = surface.context_fields(client, auth_header)

        response = client.post(surface.path, data={**context, "username": "admin", "password": "admin"})

        assert b"Too many sign-ins are waiting for a code" in response.data
        assert b'name="totp_code"' not in response.data

    def test_password_and_code_together_stay_stateless(self, app, client, auth_header, surface):
        context = surface.context_fields(client, auth_header)

        response = client.post(
            surface.path,
            data={**context, "username": "admin", "password": "admin", "totp_code": generate_totp(_SECRET)},
        )

        assert surface.completed(app, client, response)
        assert _records() == []


class TestContextBinding:
    def test_a_login_record_is_refused_by_saml_sso(self, client):
        pending = _pending_id(_code_screen(client, Login(), {}))

        response = client.post(
            "/saml/sso",
            data={
                "SAMLRequest": _authn_request(),
                "pending_second_factor": pending,
                "totp_code": generate_totp(_SECRET),
            },
        )

        assert b"Your sign-in has expired" in response.data
        assert b"SAMLResponse" not in response.data

    @pytest.mark.parametrize(
        "field, value",
        [("RelayState", "another-relay"), ("SAMLRequest", _authn_request("_another_request"))],
    )
    def test_a_saml_record_is_refused_for_another_request(self, client, field, value):
        context = {"SAMLRequest": _authn_request(), "RelayState": "relay-1"}
        pending = _pending_id(_code_screen(client, SamlSso(), context))

        response = client.post(
            "/saml/sso",
            data={
                **context,
                field: value,
                "pending_second_factor": pending,
                "totp_code": generate_totp(_SECRET),
            },
        )

        assert b"Your sign-in has expired" in response.data
        assert b"SAMLResponse" not in response.data

    def test_a_device_record_is_refused_for_another_user_code(self, client, auth_header):
        device = Device()
        first = device.context_fields(client, auth_header)
        second = device.context_fields(client, auth_header)
        pending = _pending_id(_code_screen(client, device, first))

        response = client.post(
            "/device",
            data={**second, "pending_second_factor": pending, "totp_code": generate_totp(_SECRET)},
        )

        assert b"Your sign-in has expired" in response.data
        assert not device.completed(None, client, response)


class TestDiscardRespectsTheBinding:
    """Discarding is bound like every other access (#376 review): a record
    is dropped only by its own surface and context, so a "Change username"
    or a deny elsewhere in the same browser leaves another flow intact."""

    def _login_pending(self, client):
        return _pending_id(_code_screen(client, Login(), {}))

    def _assert_login_still_completes(self, app, client, pending):
        response = client.post(
            "/login", data={"pending_second_factor": pending, "totp_code": generate_totp(_SECRET)}
        )
        assert Login().completed(app, client, response)

    def test_a_saml_change_username_does_not_discard_a_login_record(self, app, client):
        pending = self._login_pending(client)

        client.post(
            "/saml/sso",
            data={
                "SAMLRequest": _authn_request(),
                "pending_second_factor": pending,
                "change_username": "1",
            },
        )

        assert len(_records()) == 1
        self._assert_login_still_completes(app, client, pending)

    def test_a_device_deny_does_not_discard_a_login_record(self, app, client, auth_header):
        pending = self._login_pending(client)
        context = Device().context_fields(client, auth_header)

        denied = client.post(
            "/device", data={**context, "pending_second_factor": pending, "action": "deny"}
        )

        # The deny itself needs no credentials and still happens.
        assert b"denied" in denied.data.lower()
        assert len(_records()) == 1
        self._assert_login_still_completes(app, client, pending)

    def test_a_change_username_with_an_altered_context_leaves_the_original(
        self, app, client, auth_header
    ):
        device = Device()
        first = device.context_fields(client, auth_header)
        second = device.context_fields(client, auth_header)
        pending = _pending_id(_code_screen(client, device, first))

        client.post(
            "/device", data={**second, "pending_second_factor": pending, "change_username": "1"}
        )

        assert len(_records()) == 1
        done = client.post(
            "/device",
            data={**first, "pending_second_factor": pending, "totp_code": generate_totp(_SECRET)},
        )
        assert device.completed(app, client, done)


class TestDevice:
    def test_deny_from_the_code_screen_discards_and_denies(self, client, auth_header):
        device = Device()
        context = device.context_fields(client, auth_header)
        pending = _pending_id(_code_screen(client, device, context))

        response = client.post(
            "/device", data={**context, "pending_second_factor": pending, "action": "deny"}
        )

        assert b"denied" in response.data.lower()
        assert _records() == []
        from nanoidp.services.audit import get_audit_log

        (denied,) = [
            entry
            for entry in get_audit_log().get_entries(event_type="device_verification")
            if entry["status"] == "denied"
        ]
        assert denied["username"] == "admin"

    @pytest.mark.parametrize("two_step", [False, True])
    def test_a_dead_user_code_on_the_code_screen_is_reported_as_such(
        self, app, client, auth_header, two_step
    ):
        with app.app_context():
            get_config().settings.two_step = two_step
        device = Device()
        context = device.context_fields(client, auth_header)
        if two_step:
            client.post("/device", data={**context, "username": "admin"})
        pending = _pending_id(_code_screen(client, device, context))
        from nanoidp.services import get_device_code_store

        with app.app_context():
            get_device_code_store().verify(context["user_code"], "deny", None)

        response = client.post(
            "/device",
            data={**context, "pending_second_factor": pending, "totp_code": generate_totp(_SECRET)},
        )

        assert b"already been used" in response.data
        assert _records() == []

    def test_the_user_code_is_read_only_on_the_code_screen(self, client, auth_header):
        device = Device()
        screen = _code_screen(client, device, device.context_fields(client, auth_header))

        user_code_input = re.search(r'<input[^>]*name="user_code"[^>]*>', screen.get_data(as_text=True), re.S)
        assert user_code_input and "readonly" in user_code_input.group(0)
