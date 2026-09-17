"""Authorization transactions for /authorize (#346).

A valid GET creates one server-side transaction bound to the browser; the
login POST continues it and issuing the code consumes it. These tests hold
the rules the issue states: the binding, single use, expiry and the cap,
no secret in a record, snapshot semantics across configuration changes,
the TOTP step without the password, and the "exactly one" rule for a
request that names no transaction.
"""

import re
import time

import pytest

from nanoidp.config import OAuthClient, get_config
from nanoidp.services import authorization_transactions as transactions_module
from nanoidp.services.authorization_transactions import (
    AuthorizationParameters,
    AuthorizationTransaction,
    ClientSnapshot,
    LookupOutcome,
    TransactionState,
    TransactionStoreFull,
    get_authorization_transaction_store,
)
from nanoidp.services.totp import generate_totp
from tests.conftest import (
    authorization_response_params,
    pending_transaction_ids,
    transaction_id_of,
)

AUTHORIZE_QS = (
    "response_type=code&client_id=demo-client"
    "&redirect_uri=http://localhost:3000/callback&scope=openid&state=tx"
)
_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


def _params(**overrides):
    values = {
        "response_type": "code",
        "client_id": "demo-client",
        "redirect_uri": "http://localhost:3000/callback",
        "scope": "openid",
        "state": "",
        "code_challenge": "",
        "code_challenge_method": "",
        "nonce": "",
        "claims": "",
        "resources": [],
    }
    values.update(overrides)
    return AuthorizationParameters(**values)


def _create(store, binding="browser-a"):
    return store.create(
        browser_binding=binding,
        params=_params(),
        requested={"client_id": ["demo-client"]},
        client=OAuthClient(client_id="demo-client", client_secret="demo-secret"),
        client_origin="declared",
    )


class TestStore:
    def test_a_transaction_is_only_found_by_the_browser_that_created_it(self):
        store = get_authorization_transaction_store()
        transaction = _create(store)

        assert store.get_bound(transaction.id, "browser-a") is not None
        assert store.get_bound(transaction.id, "browser-b") is None
        assert store.get_bound(transaction.id, None) is None

    def test_consume_succeeds_exactly_once(self):
        store = get_authorization_transaction_store()
        transaction = _create(store)

        assert store.consume(transaction.id, "browser-b") is None
        assert store.consume(transaction.id, "browser-a") is not None
        assert store.consume(transaction.id, "browser-a") is None

    def test_an_expired_transaction_is_not_found(self, monkeypatch):
        store = get_authorization_transaction_store()
        transaction = _create(store)
        later = time.time() + transactions_module.TRANSACTION_LIFETIME_SECONDS + 1
        monkeypatch.setattr(transactions_module.time, "time", lambda: later)

        assert store.get_bound(transaction.id, "browser-a") is None
        assert store.find_unique_for_binding("browser-a").outcome is LookupOutcome.NONE
        assert store.consume(transaction.id, "browser-a") is None

    def test_primary_verification_is_a_one_way_step_until_reset(self):
        store = get_authorization_transaction_store()
        transaction = _create(store)

        verified = store.mark_primary_verified(
            transaction.id, "browser-a", username="admin", amr=["pwd"]
        )
        assert verified is not None
        assert verified.state is TransactionState.PRIMARY_VERIFIED
        assert verified.primary_username == "admin"
        # Already verified: a second password cannot re-target it.
        assert (
            store.mark_primary_verified(transaction.id, "browser-a", username="other", amr=["pwd"])
            is None
        )

        reset = store.reset_login(transaction.id, "browser-a")
        assert reset is not None
        assert reset.state is TransactionState.PENDING
        assert reset.primary_username is None

    def test_live_transactions_are_never_evicted_and_a_full_store_refuses(self, monkeypatch):
        monkeypatch.setattr(transactions_module, "MAX_PENDING_TRANSACTIONS", 2)
        store = get_authorization_transaction_store()
        first = _create(store)
        _create(store)

        with pytest.raises(TransactionStoreFull):
            _create(store)
        assert store.get_bound(first.id, "browser-a") is not None

    def test_expired_transactions_make_room(self, monkeypatch):
        monkeypatch.setattr(transactions_module, "MAX_PENDING_TRANSACTIONS", 1)
        store = get_authorization_transaction_store()
        _create(store)
        later = time.time() + transactions_module.TRANSACTION_LIFETIME_SECONDS + 1
        monkeypatch.setattr(transactions_module.time, "time", lambda: later)

        assert _create(store) is not None

    def test_the_lookup_refuses_to_guess_between_several(self):
        store = get_authorization_transaction_store()
        _create(store)
        assert store.find_unique_for_binding("browser-a").outcome is LookupOutcome.UNIQUE
        _create(store)
        assert store.find_unique_for_binding("browser-a").outcome is LookupOutcome.AMBIGUOUS
        assert store.find_unique_for_binding("browser-b").outcome is LookupOutcome.NONE

    def test_a_runtime_store_reset_takes_the_transactions_with_it(self):
        from nanoidp.services import runtime_identities

        store = get_authorization_transaction_store()
        transaction = _create(store)
        runtime_identities._runtime_identity_store = None

        assert get_authorization_transaction_store().get_bound(transaction.id, "browser-a") is None


class TestNoSecretInARecord:
    def test_the_client_snapshot_has_no_secret(self):
        snapshot = ClientSnapshot.of(
            OAuthClient(client_id="c", client_secret="very-secret", description="d")
        )
        assert "client_secret" not in ClientSnapshot.model_fields
        assert "very-secret" not in snapshot.model_dump_json()

    def test_the_transaction_has_no_credential_field(self):
        fields = set(AuthorizationTransaction.model_fields)
        assert not {"password", "totp_secret", "client_secret", "user", "client"} & fields

    def test_a_verified_password_is_not_stored(self, app, client):
        with app.app_context():
            get_config().settings.totp = True
            get_config().users["admin"].password = "pw-346-marker"
            get_config().users["admin"].totp_secret = _SECRET
        client.get(f"/authorize?{AUTHORIZE_QS}")
        screen = client.post("/authorize", data={"username": "admin", "password": "pw-346-marker"})

        (stored,) = get_authorization_transaction_store()._repository.list()
        assert stored.state is TransactionState.PRIMARY_VERIFIED
        assert "pw-346-marker" not in stored.model_dump_json()
        assert _SECRET not in stored.model_dump_json()
        assert b"pw-346-marker" not in screen.data


class TestBinding:
    def test_a_transaction_id_from_another_browser_is_refused(self, app, client):
        page = client.get(f"/authorize?{AUTHORIZE_QS}")
        stolen = transaction_id_of(page)

        attacker = app.test_client()
        response = attacker.post(
            f"/authorize?{AUTHORIZE_QS}",
            data={"username": "admin", "password": "admin", "transaction_id": stolen},
        )
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_request"

        # The owner's transaction is untouched.
        response = client.post(
            "/authorize",
            data={"username": "admin", "password": "admin", "transaction_id": stolen},
        )
        assert response.status_code == 302
        assert "code" in authorization_response_params(response)

    def test_the_session_holds_one_key_whatever_the_number_of_requests(self, client):
        client.get(f"/authorize?{AUTHORIZE_QS}")
        client.get(f"/authorize?{AUTHORIZE_QS.replace('state=tx', 'state=other')}")

        with client.session_transaction() as session:
            keys = set(session.keys())
        assert keys == {"authorize_binding"}
        assert len(pending_transaction_ids(client)) == 2


class TestSingleUse:
    def test_a_completed_transaction_cannot_be_replayed(self, client):
        page = client.get(f"/authorize?{AUTHORIZE_QS}")
        data = {"username": "admin", "password": "admin", "transaction_id": transaction_id_of(page)}

        assert client.post("/authorize", data=data).status_code == 302
        replay = client.post("/authorize", data=data)
        assert replay.status_code == 400
        assert pending_transaction_ids(client) == []

    def test_an_expired_transaction_is_refused(self, client, monkeypatch):
        page = client.get(f"/authorize?{AUTHORIZE_QS}")
        later = time.time() + transactions_module.TRANSACTION_LIFETIME_SECONDS + 1
        monkeypatch.setattr(transactions_module.time, "time", lambda: later)

        response = client.post(
            "/authorize",
            data={"username": "admin", "password": "admin", "transaction_id": transaction_id_of(page)},
        )
        assert response.status_code == 400

    def test_a_query_string_that_is_not_the_transactions_request_is_refused(self, client):
        page = client.get(f"/authorize?{AUTHORIZE_QS}")
        other = AUTHORIZE_QS.replace("state=tx", "state=swapped")

        response = client.post(
            f"/authorize?{other}",
            data={"username": "admin", "password": "admin", "transaction_id": transaction_id_of(page)},
        )
        assert response.status_code == 400
        assert pending_transaction_ids(client) == [transaction_id_of(page)]

    def test_a_full_store_refuses_a_new_request_through_the_redirect(self, client, monkeypatch):
        monkeypatch.setattr(transactions_module, "MAX_PENDING_TRANSACTIONS", 1)
        assert client.get(f"/authorize?{AUTHORIZE_QS}").status_code == 200

        refused = client.get(f"/authorize?{AUTHORIZE_QS.replace('state=tx', 'state=second')}")

        assert refused.status_code == 302
        params = authorization_response_params(refused)
        assert params["error"] == ["temporarily_unavailable"]
        assert params["state"] == ["second"]


class TestSnapshotSemantics:
    def test_a_changed_client_does_not_revalidate_an_open_transaction(self, app, client):
        page = client.get(f"/authorize?{AUTHORIZE_QS}")
        with app.app_context():
            get_config().get_client("demo-client").redirect_uris = ["http://localhost:9999/elsewhere"]

        response = client.post(
            "/authorize",
            data={"username": "admin", "password": "admin", "transaction_id": transaction_id_of(page)},
        )

        assert response.status_code == 302
        assert response.headers["Location"].startswith("http://localhost:3000/callback?")
        assert "code" in authorization_response_params(response)
        # A new request sees the new configuration.
        assert client.get(f"/authorize?{AUTHORIZE_QS}").status_code == 400

    def test_a_removed_client_ends_the_transaction(self, app, client):
        page = client.get(f"/authorize?{AUTHORIZE_QS}")
        with app.app_context():
            settings = get_config().settings
            settings.clients = [c for c in settings.clients if c.client_id != "demo-client"]

        response = client.post(
            "/authorize",
            data={"username": "admin", "password": "admin", "transaction_id": transaction_id_of(page)},
        )

        assert response.status_code == 302
        params = authorization_response_params(response)
        assert params["error"] == ["temporarily_unavailable"]
        assert "code" not in params
        assert pending_transaction_ids(client) == []


class TestSecondFactor:
    @pytest.fixture(autouse=True)
    def totp(self, app):
        with app.app_context():
            get_config().settings.totp = True
            get_config().users["admin"].totp_secret = _SECRET

    def _to_code_screen(self, client):
        page = client.get(f"/authorize?{AUTHORIZE_QS}")
        screen = client.post(
            "/authorize",
            data={"username": "admin", "password": "admin", "transaction_id": transaction_id_of(page)},
        )
        assert b'name="totp_code"' in screen.data
        return transaction_id_of(page)

    def test_the_code_screen_needs_no_password_and_ignores_a_username(self, app, client):
        transaction_id = self._to_code_screen(client)

        response = client.post(
            "/authorize",
            data={
                "transaction_id": transaction_id,
                "username": "someone-else",
                "totp_code": generate_totp(_SECRET),
            },
        )

        assert response.status_code == 302
        code = authorization_response_params(response)["code"][0]
        from nanoidp.services.auth_code import get_auth_code_store

        with app.app_context():
            info = get_auth_code_store().get_code_info(code)
        assert info.username == "admin"
        assert list(info.amr) == ["pwd", "otp"]

    def test_the_current_secret_applies(self, app, client):
        transaction_id = self._to_code_screen(client)
        new_secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
        with app.app_context():
            get_config().users["admin"].totp_secret = new_secret

        stale = client.post(
            "/authorize", data={"transaction_id": transaction_id, "totp_code": generate_totp(_SECRET)}
        )
        assert stale.status_code == 200
        assert b"Invalid code" in stale.data

        current = client.post(
            "/authorize", data={"transaction_id": transaction_id, "totp_code": generate_totp(new_secret)}
        )
        assert current.status_code == 302

    @pytest.mark.parametrize("change", ["user_deleted", "secret_removed", "totp_off", "persona_on"])
    def test_a_verified_password_never_completes_on_its_own(self, app, client, change):
        transaction_id = self._to_code_screen(client)
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
            "/authorize",
            data={"transaction_id": transaction_id, "totp_code": generate_totp(_SECRET), "username": "admin"},
        )

        assert response.status_code == 302
        params = authorization_response_params(response)
        assert params["error"] == ["access_denied"]
        assert "code" not in params
        assert pending_transaction_ids(client) == []

    @pytest.mark.parametrize(("concurrent_user", "expected"), [("admin", 200), ("user1", 400)])
    def test_a_concurrent_password_submission_on_the_same_transaction(
        self, app, client, monkeypatch, concurrent_user, expected
    ):
        """A double-clicked password form: both POSTs read the transaction as
        pending, and the first verifies it while the second is still checking
        the password. The second shows the code screen for the same user and
        is refused for a different one."""
        from nanoidp.routes import oauth as oauth_routes

        page = client.get(f"/authorize?{AUTHORIZE_QS}")
        transaction_id = transaction_id_of(page)
        with client.session_transaction() as session:
            binding = session["authorize_binding"]
        original = oauth_routes.authenticate_interactively

        def first_submission_wins(config, *, username, password):
            get_authorization_transaction_store().mark_primary_verified(
                transaction_id, binding, username=concurrent_user, amr=["pwd"]
            )
            return original(config, username=username, password=password)

        monkeypatch.setattr(oauth_routes, "authenticate_interactively", first_submission_wins)

        response = client.post(
            "/authorize",
            data={"username": "admin", "password": "admin", "transaction_id": transaction_id},
        )

        assert response.status_code == expected
        if expected == 200:
            assert b'name="totp_code"' in response.data

    def test_a_code_is_not_issued_after_a_concurrent_change_username(
        self, app, client, monkeypatch
    ):
        """The code POST read the transaction as verified; a "Change
        username" reset it before the code was checked. The completion is
        refused under the lock rather than issued on a reset transaction."""
        from nanoidp.routes import oauth as oauth_routes

        transaction_id = self._to_code_screen(client)
        with client.session_transaction() as session:
            binding = session["authorize_binding"]
        original = oauth_routes.check_second_factor

        def reset_meanwhile(config, user):
            get_authorization_transaction_store().reset_login(transaction_id, binding)
            return original(config, user)

        monkeypatch.setattr(oauth_routes, "check_second_factor", reset_meanwhile)

        response = client.post(
            "/authorize", data={"transaction_id": transaction_id, "totp_code": generate_totp(_SECRET)}
        )

        assert response.status_code == 400
        assert pending_transaction_ids(client) == [transaction_id]

    def test_change_username_forgets_the_verified_password(self, client):
        transaction_id = self._to_code_screen(client)

        page = client.post(
            "/authorize", data={"transaction_id": transaction_id, "change_username": "1"}
        )
        assert b'name="totp_code"' not in page.data
        assert b'name="password"' in page.data

        # Without the password again, a code is not enough.
        response = client.post(
            "/authorize",
            data={"transaction_id": transaction_id, "username": "admin", "totp_code": generate_totp(_SECRET)},
        )
        assert response.status_code == 200
        assert "code=" not in response.headers.get("Location", "")


class TestRequestsThatNameNoTransaction:
    def test_a_bare_post_with_nothing_pending_is_refused(self, client):
        response = client.post("/authorize", data={"username": "admin", "password": "admin"})
        assert response.status_code == 400
        assert response.get_json()["error_description"] == "No pending authorization request"

    def test_a_bare_get_resumes_the_one_pending_request(self, client):
        page = client.get(f"/authorize?{AUTHORIZE_QS}")

        resumed = client.get("/authorize")

        assert resumed.status_code == 200
        assert transaction_id_of(resumed) == transaction_id_of(page)

    def test_a_hint_only_get_applies_to_the_one_pending_request(self, app, client):
        with app.app_context():
            get_config().settings.login_mode = "persona"
            get_config().settings.auto_login = True
        client.get(f"/authorize?{AUTHORIZE_QS}")

        response = client.get("/authorize?login_hint=persona-auto-login:admin")

        assert response.status_code == 302
        params = authorization_response_params(response)
        assert params["state"] == ["tx"]
        assert "code" in params
        assert pending_transaction_ids(client) == []

    def test_a_hint_only_get_with_several_pending_is_refused(self, app, client):
        with app.app_context():
            get_config().settings.login_mode = "persona"
            get_config().settings.auto_login = True
        client.get(f"/authorize?{AUTHORIZE_QS}")
        client.get(f"/authorize?{AUTHORIZE_QS.replace('state=tx', 'state=other')}")

        response = client.get("/authorize?login_hint=persona-auto-login:admin")

        assert response.status_code == 400
        assert len(pending_transaction_ids(client)) == 2

    def test_an_auto_login_on_its_own_get_creates_no_transaction(self, app, client):
        with app.app_context():
            get_config().settings.login_mode = "persona"
            get_config().settings.auto_login = True

        response = client.get(f"/authorize?{AUTHORIZE_QS}&login_hint=persona-auto-login:admin")

        assert response.status_code == 302
        assert pending_transaction_ids(client) == []

    def test_every_form_on_the_page_names_the_transaction(self, app, client):
        with app.app_context():
            get_config().settings.two_step = True
        page = client.get(f"/authorize?{AUTHORIZE_QS}")
        step2 = client.post(
            "/authorize", data={"username": "admin", "transaction_id": transaction_id_of(page)}
        )

        for response in (page, step2):
            html = response.get_data(as_text=True)
            forms = re.findall(r"<form\b.*?</form>", html, re.S)
            assert forms
            for form in forms:
                assert f'name="transaction_id" value="{transaction_id_of(page)}"' in form
