"""The runtime-client lifecycle is one synchronization boundary (#403).

A dynamically registered client is two records, the client and its RFC 7592
credential, linked by name. Creating, deleting and resetting clients,
registering one, and authenticating a registration credential are each
correct alone; these tests pin that they are also correct against each
other: a credential issued for one client never reads or deletes a different
client created later under the same id.

They are tests of what a caller can observe, at the entry points, not of how
the guarantee is provided. Today that is a process-local critical section;
the joint design of #404 and #405 replaces it with instance identity and
atomic store operations, and these tests are meant to pass unchanged across
that move. So each one only says where the concurrent request lands, lets it
run for as long as the implementation allows, and then checks the outcome.

The concurrent request runs in its own thread: the critical section is
reentrant, so a request nested in the same thread would walk straight in.
The window is placed at the repository, the one seam every implementation of
the lifecycle has to go through.
"""

import shutil
import threading
from pathlib import Path

import pytest
import yaml

from nanoidp.app import create_app
from nanoidp.config import get_config
from nanoidp.services import identities as identities_module
from nanoidp.services.dynamic_registration import registrations
from nanoidp.services.runtime_identities import (
    MemoryRuntimeRepository,
    get_runtime_identity_store,
)

_REPO = Path(__file__).resolve().parent.parent
REDIRECT = "http://localhost:9000/cb"
OPERATOR_SECRET = "the-operators-own-secret"
# How long the window stays open for the concurrent request. An
# implementation that serialises the lifecycle keeps it waiting for all of
# it; one that does not needs a few milliseconds.
WINDOW_SECONDS = 0.5


@pytest.fixture
def application(tmp_path):
    config_dir = tmp_path / "config"
    config_dir.mkdir(parents=True)
    for name in ("settings.yaml", "users.yaml"):
        shutil.copy(_REPO / "config" / name, config_dir / name)
    settings = config_dir / "settings.yaml"
    document = yaml.safe_load(settings.read_text())
    document["jwt"]["keys_dir"] = str(tmp_path / "keys")
    document["oauth"]["dynamic_registration"] = {"enabled": True, "max_clients": 100}
    settings.write_text(yaml.safe_dump(document))
    app = create_app(str(config_dir))
    app.config["TESTING"] = True
    return app


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


def _register(application):
    body = application.test_client().post("/register", json={"redirect_uris": [REDIRECT]}).get_json()
    return body["client_id"], body["registration_access_token"]


class Operator:
    """Someone else using the instance at the same time: takes the id of a
    dynamically registered client for a runtime client of their own."""

    def __init__(self, application, client_id=None, token=None, delete_first=False, reset=False):
        self.application = application
        self.client_id = client_id
        self.token = token
        self.delete_first = delete_first
        self.reset = reset
        self.created = None
        self.old_credential_read = None
        self._thread = threading.Thread(target=self._run)

    def _run(self):
        client = self.application.test_client()
        if self.reset:
            client.delete("/api/runtime")
            return
        if self.delete_first:
            client.delete(f"/api/runtime/clients/{self.client_id}")
        self.created = self._create(client)
        # What the credential of the first client sees of the second, as
        # early as anyone could ask.
        self.old_credential_read = client.get(
            f"/register/{self.client_id}", headers=_bearer(self.token)
        )

    def _create(self, client):
        return client.post(
            "/api/runtime/clients",
            json={
                "client_id": self.client_id,
                "client_secret": OPERATOR_SECRET,
                "redirect_uris": ["http://localhost:1/operator"],
            },
        ).status_code

    def create_later(self, client_id):
        self.client_id = client_id
        self.created = self._create(self.application.test_client())

    def arrive(self):
        self._thread.start()
        self._thread.join(WINDOW_SECONDS)

    def finish(self):
        self._thread.join()


def _open_window(monkeypatch, repository, method, when, operator):
    """Let ``operator`` arrive once, right before or right after the first
    call of ``method`` on ``repository``."""
    original = getattr(MemoryRuntimeRepository, method)
    state = {"open": True}

    def placed(self, *args, **kwargs):
        mine = self is repository and state["open"]
        if mine:
            state["open"] = False
            if when == "before":
                operator.arrive()
        result = original(self, *args, **kwargs)
        if mine and when == "after":
            operator.arrive()
        return result

    monkeypatch.setattr(MemoryRuntimeRepository, method, placed)


def _runtime_clients():
    return get_runtime_identity_store().clients


def _assert_the_old_credential_is_dead(application, client_id, token):
    client = application.test_client()
    read = client.get(f"/register/{client_id}", headers=_bearer(token))
    assert read.status_code == 401
    assert client.delete(f"/register/{client_id}", headers=_bearer(token)).status_code == 401


def _assert_the_operators_client_is_untouched(application, operator):
    assert operator.created == 201
    summary = application.test_client().get(f"/api/runtime/clients/{operator.client_id}")
    assert summary.status_code == 200
    assert summary.get_json().get("source") != "dcr"


def _assert_never_read(operator):
    read = operator.old_credential_read
    assert read is not None
    assert read.status_code == 401
    assert OPERATOR_SECRET not in read.get_data(as_text=True)


class TestAnOldCredentialNeverReadsARecreatedClient:
    def test_while_the_runtime_api_deletes_the_client(self, application, monkeypatch):
        """W1: the client is gone and its record not yet."""
        client_id, token = _register(application)
        operator = Operator(application, client_id, token)
        _open_window(monkeypatch, _runtime_clients(), "delete", "after", operator)

        deleted = application.test_client().delete(f"/api/runtime/clients/{client_id}")
        operator.finish()

        assert deleted.status_code == 200
        _assert_never_read(operator)
        _assert_the_operators_client_is_untouched(application, operator)
        _assert_the_old_credential_is_dead(application, client_id, token)

    def test_while_its_own_registration_is_deleted(self, application, monkeypatch):
        """W2: the same window, opened by RFC 7592's delete."""
        client_id, token = _register(application)
        operator = Operator(application, client_id, token)
        _open_window(monkeypatch, _runtime_clients(), "delete", "after", operator)

        deleted = application.test_client().delete(f"/register/{client_id}", headers=_bearer(token))
        operator.finish()

        assert deleted.status_code == 204
        _assert_never_read(operator)
        _assert_the_operators_client_is_untouched(application, operator)
        _assert_the_old_credential_is_dead(application, client_id, token)

    def test_while_it_is_being_authenticated(self, application, monkeypatch):
        """W7: the credential was checked against the first client; what is
        read next must be that client, not whoever holds the id by then."""
        client_id, token = _register(application)
        operator = Operator(application, client_id, token, delete_first=True)
        _open_window(monkeypatch, registrations(), "get", "after", operator)

        read = application.test_client().get(f"/register/{client_id}", headers=_bearer(token))
        operator.finish()

        assert OPERATOR_SECRET not in read.get_data(as_text=True)
        if read.status_code == 200:
            assert read.get_json()["redirect_uris"] == [REDIRECT]
        else:
            assert read.status_code == 401
        _assert_never_read(operator)
        _assert_the_operators_client_is_untouched(application, operator)
        _assert_the_old_credential_is_dead(application, client_id, token)


class TestAnOldCredentialNeverDeletesARecreatedClient:
    def test_while_it_is_being_authenticated(self, application, monkeypatch):
        """W6: authenticated as the first client, the delete must not land
        on the second."""
        client_id, token = _register(application)
        operator = Operator(application, client_id, token, delete_first=True)
        # Right after the credential's record is read, as for the read above:
        # any later and the resolver's own lock already holds the window shut.
        _open_window(monkeypatch, registrations(), "get", "after", operator)

        deleted = application.test_client().delete(f"/register/{client_id}", headers=_bearer(token))
        operator.finish()

        assert deleted.status_code in (204, 401)
        _assert_never_read(operator)
        _assert_the_operators_client_is_untouched(application, operator)
        _assert_the_old_credential_is_dead(application, client_id, token)

    def test_a_reset_leaves_no_registration_to_inherit(self, application, monkeypatch):
        """W3: the clients are gone and the sweep has not run. A client
        created now must not keep the record alive through the sweep."""
        client_id, token = _register(application)
        operator = Operator(application, client_id, token)
        # At the sweep's first visit, not right after the clients go: the
        # reset itself holds creations off until it returns.
        _open_window(monkeypatch, registrations(), "list", "before", operator)

        reset = application.test_client().delete("/api/runtime")
        operator.finish()

        assert reset.status_code == 200
        _assert_never_read(operator)
        _assert_the_operators_client_is_untouched(application, operator)
        _assert_the_old_credential_is_dead(application, client_id, token)
        _assert_the_operators_client_is_untouched(application, operator)


class TestRegisterIsOneOperation:
    def test_a_reset_in_the_middle_leaves_no_registration_behind(self, application, monkeypatch):
        """W5: the client exists and its record does not yet. A reset landing
        there must not leave a record for a client that is gone, waiting for
        the next client of that id."""
        operator = Operator(application, reset=True)
        # At the record's creation, not right after the client's: creating a
        # client holds a reset off until it returns.
        _open_window(monkeypatch, registrations(), "create", "before", operator)

        response = application.test_client().post("/register", json={"redirect_uris": [REDIRECT]})
        operator.finish()

        assert response.status_code == 201
        registered = response.get_json()
        client_id, token = registered["client_id"], registered["registration_access_token"]
        # Nobody asks for the registration in between, so no lazy check
        # gets the chance to tidy up before the id is reused.
        operator.create_later(client_id)

        _assert_the_operators_client_is_untouched(application, operator)
        _assert_the_old_credential_is_dead(application, client_id, token)
        _assert_the_operators_client_is_untouched(application, operator)


class TestARefusedDeleteHasNoEffect:
    """Why the two steps keep their order (client, then record) and the
    whole block is made atomic instead: with the record dropped first, a
    delete refused for a promotion would already have ended the
    registration it answered 409 about."""

    @pytest.mark.parametrize("surface", ["runtime", "rfc7592"])
    def test_a_delete_refused_for_a_promotion_keeps_the_registration(self, application, surface):
        client_id, token = _register(application)
        client = application.test_client()
        # A promotion whose entry reached the file and whose reload failed:
        # the state in which the mark outlives the promotion request.
        identities_module._promoting[("client", client_id)] = identities_module._Promotion(
            {}, written=True
        )

        if surface == "runtime":
            refused = client.delete(f"/api/runtime/clients/{client_id}")
        else:
            refused = client.delete(f"/register/{client_id}", headers=_bearer(token))

        assert refused.status_code == 409
        read = client.get(f"/register/{client_id}", headers=_bearer(token))
        assert read.status_code == 200
        assert read.get_json()["client_id"] == client_id


    def test_nor_does_one_refused_only_once_inside_the_scope(self, application, monkeypatch):
        """The runtime API asks about a promotion before it waits for the
        scope, so the refusal that matters for the order is the second one:
        a promotion that started right after the first check, wrote its
        entry and failed its reload leaves the mark behind, and the delete
        finds it once inside."""
        client_id, token = _register(application)
        client = application.test_client()
        asked_first = identities_module.IdentityResolver.refuse_while_promoting

        def then_a_promotion_fails_its_reload(self, kind, name):
            asked_first(self, kind, name)
            identities_module._promoting[(kind, name)] = identities_module._Promotion({}, written=True)

        monkeypatch.setattr(
            identities_module.IdentityResolver, "refuse_while_promoting", then_a_promotion_fails_its_reload
        )

        refused = client.delete(f"/api/runtime/clients/{client_id}")

        assert refused.status_code == 409
        assert client.get(f"/register/{client_id}", headers=_bearer(token)).status_code == 200


def _delete_while_promoting(application, monkeypatch, client_id, delete):
    """Run ``delete`` while a promotion of ``client_id`` is writing the file.
    Returns the delete's response, whether it answered before the promotion
    was let through, and the promotion's status."""
    from nanoidp.services.yaml_writer import get_yaml_writer

    writer = get_yaml_writer()
    real_save_client = writer.save_client
    writing, release = threading.Event(), threading.Event()

    def slow_save_client(client, **kwargs):
        writing.set()
        release.wait(5)
        return real_save_client(client, **kwargs)

    monkeypatch.setattr(writer, "save_client", slow_save_client)
    results = {}

    def promote():
        results["promote"] = (
            application.test_client().post(f"/api/runtime/clients/{client_id}/promote").status_code
        )

    def run_delete():
        results["delete"] = delete(application.test_client())

    promoting = threading.Thread(target=promote)
    promoting.start()
    assert writing.wait(5)
    deleting = threading.Thread(target=run_delete)
    deleting.start()
    deleting.join(1)
    answered_at_once = not deleting.is_alive()
    release.set()
    promoting.join()
    deleting.join()
    return results["delete"], answered_at_once, results["promote"]


class TestADeleteDuringAPromotion:
    def test_the_runtime_api_still_answers_at_once(self, application, monkeypatch):
        """#192's contract, which entering the lifecycle scope must not
        change: a promotion holds the scope for as long as it writes the
        file, and a delete of the client it is promoting answers 409 now,
        not 404 once the promotion is through."""
        client_id, _ = _register(application)

        deleted, answered_at_once, promoted = _delete_while_promoting(
            application, monkeypatch, client_id,
            lambda client: client.delete(f"/api/runtime/clients/{client_id}"),
        )

        assert answered_at_once
        assert deleted.status_code == 409
        assert deleted.get_json()["kind"] == "promotion_in_progress"
        assert promoted == 200

    def test_the_registration_never_deletes_the_client_it_became(self, application, monkeypatch):
        """RFC 7592's delete checks a credential first, which is part of the
        scope, so it answers when the promotion is through: by then the
        client is declared, the registration has ended, and the answer is
        the one any unknown registration gets."""
        client_id, token = _register(application)

        deleted, _, promoted = _delete_while_promoting(
            application, monkeypatch, client_id,
            lambda client: client.delete(f"/register/{client_id}", headers=_bearer(token)),
        )

        assert promoted == 200
        assert deleted.status_code in (401, 409)
        assert any(c.client_id == client_id for c in get_config().settings.clients)


class TestAReloadIsAlreadySafe:
    def test_no_client_is_created_between_the_reconciliation_and_the_sweep(
        self, application, tmp_path, monkeypatch
    ):
        """W4, pinned because nothing had to change for it: the sweep after
        a load runs inside the load, which a client creation waits for, and
        by then the promoted name is declared. Whoever removes either reason
        finds out here."""
        client_id, token = _register(application)
        operator = Operator(application, client_id, token)
        _open_window(monkeypatch, _runtime_clients(), "delete", "after", operator)

        promoted = application.test_client().post(f"/api/runtime/clients/{client_id}/promote")
        operator.finish()

        assert promoted.status_code == 200
        assert operator.created == 409
        _assert_never_read(operator)
        _assert_the_old_credential_is_dead(application, client_id, token)
