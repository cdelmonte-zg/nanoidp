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

The concurrent request runs in its own thread, as a concurrent request is.
The window is placed at the repository's two lowest operations, which every
implementation of the lifecycle goes through whatever it is built from:
``entry``/``entries`` for a read and ``transact`` for a change. (Placed at
``get`` or ``delete``, the windows stopped opening when the lifecycle moved
onto ``consume`` and ``create_within``, and the tests went quiet.)
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
from nanoidp.services.runtime_store import (
    MemoryRuntimeRepository,
    get_runtime_store,
)
from tests.conftest import claim_for_promotion  # noqa: E402

_REPO = Path(__file__).resolve().parent.parent
REDIRECT = "http://localhost:9000/cb"
OPERATOR_SECRET = "the-operators-own-secret"
# How long the window stays open for the concurrent request. An
# implementation that serialises the lifecycle keeps it waiting for all of
# it; one that does not needs a few milliseconds.
WINDOW_SECONDS = 0.5


@pytest.fixture
def application(tmp_path):
    return _application(tmp_path)


def _application(tmp_path, max_clients=100):
    config_dir = tmp_path / "config"
    config_dir.mkdir(parents=True)
    for name in ("settings.yaml", "users.yaml"):
        shutil.copy(_REPO / "config" / name, config_dir / name)
    settings = config_dir / "settings.yaml"
    document = yaml.safe_load(settings.read_text())
    document["jwt"]["keys_dir"] = str(tmp_path / "keys")
    document["oauth"]["dynamic_registration"] = {"enabled": True, "max_clients": max_clients}
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

    def __init__(
        self, application, client_id=None, token=None, delete_first=False, reset=False, register=False
    ):
        self.application = application
        self.client_id = client_id
        self.token = token
        self.delete_first = delete_first
        self.reset = reset
        self.register = register
        self.take_the_other_id = False
        self.and_then = None
        self.and_then_created = None
        self.leave_alone = set()
        self.registered = None
        self.created = None
        self.old_credential_read = None
        self.arrived = False
        self._thread = threading.Thread(target=self._run)

    def _run(self):
        client = self.application.test_client()
        if self.reset:
            client.delete("/api/runtime")
            return
        if self.register:
            before = {c["client_id"] for c in client.get("/api/runtime/clients").get_json()["clients"]}
            response = client.post("/register", json={"redirect_uris": [REDIRECT]})
            self.registered = response.status_code
            if self.and_then is not None:
                self.and_then()
            if self.take_the_other_id:
                # The registration under way created a client and has no
                # record for it yet: the one id here that is nobody's.
                mine = response.get_json()["client_id"]
                (self.client_id,) = before - self.leave_alone - {mine}
                client.delete(f"/api/runtime/clients/{self.client_id}")
                self.created = self._create(client)
            return
        if self.delete_first:
            client.delete(f"/api/runtime/clients/{self.client_id}")
        self.created = self._create(client)
        if self.and_then_created is not None:
            self.and_then_created()
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
        self.arrived = True
        self._thread.start()
        self._thread.join(WINDOW_SECONDS)
        # Whether it got through while the window was open, or is being
        # kept waiting by an implementation that serialises the two.
        self.landed_in_the_window = not self._thread.is_alive()

    def finish(self, may_not_arrive=False):
        """``may_not_arrive`` is for a window placed at a later read of the
        record, which an implementation need not make. A window that never
        opens is otherwise a test that checked nothing, and says so."""
        if not self.arrived:
            if may_not_arrive:
                pytest.skip("this implementation does not read the record that many times")
            pytest.fail("the window never opened: the test placed it where nothing goes through")
        self._thread.join()


def _open_window(monkeypatch, repository, method, when, operator, nth=1):
    """Let ``operator`` arrive once, right before or right after the
    ``nth`` call of ``method`` on ``repository``."""
    original = getattr(MemoryRuntimeRepository, method)
    state = {"open": True, "calls": 0}

    def placed(self, *args, **kwargs):
        if self is repository and state["open"]:
            state["calls"] += 1
        mine = self is repository and state["open"] and state["calls"] == nth
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
    return get_runtime_store().clients


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


# On the way to an answer the credential's record and the client it is about
# are each read, possibly more than once. The swap must be harmless after
# every one of those reads, whichever an implementation makes: a window at a
# read it does not make is skipped, one at a first read must open.
READS = [
    pytest.param(("record", 1), id="after-the-record-is-read"),
    pytest.param(("record", 2), id="after-the-record-is-read-again"),
    pytest.param(("client", 1), id="after-the-client-is-read"),
    pytest.param(("client", 2), id="after-the-client-is-read-again"),
    pytest.param(("client", 3), id="after-the-client-is-read-a-third-time"),
]


# How many times the client is read while a credential is checked: the
# window of the test that needs to land after the last one.
LAST_CLIENT_READ = 2


def _open_window_at_read(monkeypatch, at, operator):
    which, nth = at
    repository = registrations() if which == "record" else _runtime_clients()
    _open_window(monkeypatch, repository, "entry", "after", operator, nth)


class TestAnOldCredentialNeverReadsARecreatedClient:
    def test_while_the_runtime_api_deletes_the_client(self, application, monkeypatch):
        """W1: the client is gone and its record not yet."""
        client_id, token = _register(application)
        operator = Operator(application, client_id, token)
        _open_window(monkeypatch, _runtime_clients(), "transact", "after", operator)

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
        _open_window(monkeypatch, _runtime_clients(), "transact", "after", operator)

        deleted = application.test_client().delete(f"/register/{client_id}", headers=_bearer(token))
        operator.finish()

        assert deleted.status_code == 204
        _assert_never_read(operator)
        _assert_the_operators_client_is_untouched(application, operator)
        _assert_the_old_credential_is_dead(application, client_id, token)

    @pytest.mark.parametrize("at", READS)
    def test_while_it_is_being_authenticated(self, application, monkeypatch, at):
        """W7: the credential was checked against the first client; what is
        read next must be that client, not whoever holds the id by then."""
        client_id, token = _register(application)
        operator = Operator(application, client_id, token, delete_first=True)
        _open_window_at_read(monkeypatch, at, operator)

        read = application.test_client().get(f"/register/{client_id}", headers=_bearer(token))
        operator.finish(may_not_arrive=at[1] > 1)

        assert OPERATOR_SECRET not in read.get_data(as_text=True)
        if read.status_code == 200:
            assert read.get_json()["redirect_uris"] == [REDIRECT]
        else:
            assert read.status_code == 401
        _assert_never_read(operator)
        _assert_the_operators_client_is_untouched(application, operator)
        _assert_the_old_credential_is_dead(application, client_id, token)


    def test_nor_once_it_has_been_authenticated(self, application, monkeypatch):
        """The read is over when the client has been resolved, by value. A
        swap that lands after that, while the response is being built,
        cannot change it: the answer is the first client, which is a read
        that already happened, and never the second one's secret."""
        from nanoidp.routes import registration as registration_routes

        client_id, token = _register(application)
        operator = Operator(application, client_id, token, delete_first=True)
        build = registration_routes.registration_response

        def swapped_first(*args, **kwargs):
            operator.arrive()
            return build(*args, **kwargs)

        monkeypatch.setattr(registration_routes, "registration_response", swapped_first)

        read = application.test_client().get(f"/register/{client_id}", headers=_bearer(token))
        operator.finish()

        assert read.status_code == 200
        assert read.get_json()["redirect_uris"] == [REDIRECT]
        assert OPERATOR_SECRET not in read.get_data(as_text=True)
        _assert_never_read(operator)
        _assert_the_operators_client_is_untouched(application, operator)
        _assert_the_old_credential_is_dead(application, client_id, token)


class TestAnOldCredentialNeverDeletesARecreatedClient:
    @pytest.mark.parametrize("at", READS)
    def test_while_it_is_being_authenticated(self, application, monkeypatch, at):
        """W6: authenticated as the first client, the delete must not land
        on the second."""
        client_id, token = _register(application)
        operator = Operator(application, client_id, token, delete_first=True)
        # Right after the credential's record is read, as for the read above:
        # any later and the resolver's own lock already holds the window shut.
        _open_window_at_read(monkeypatch, at, operator)

        deleted = application.test_client().delete(f"/register/{client_id}", headers=_bearer(token))
        operator.finish(may_not_arrive=at[1] > 1)

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
        _open_window(monkeypatch, registrations(), "entries", "before", operator)

        reset = application.test_client().delete("/api/runtime")
        operator.finish()

        assert reset.status_code == 200
        _assert_never_read(operator)
        _assert_the_operators_client_is_untouched(application, operator)
        _assert_the_old_credential_is_dead(application, client_id, token)
        _assert_the_operators_client_is_untouched(application, operator)


class TestRegisterIsOneOperation:
    @pytest.mark.parametrize("when", ["before", "after"])
    def test_a_reset_in_the_middle_leaves_no_registration_behind(self, application, monkeypatch, when):
        """W5: the client exists and its record does not yet ("before"), or
        both do and the registration has not yet looked back at its client
        ("after"). A reset landing there must not leave a record for a
        client that is gone, waiting for the next client of that id, and
        must not be answered with a registration of a client that never
        existed together with its record.

        Which answer is right depends on whether the reset got in. An
        implementation that keeps it waiting registers first: 201, and the
        reset simply came next. One that lets it in has, by the time it
        answers, no client to announce, and refuses."""
        operator = Operator(application, reset=True)
        _open_window(monkeypatch, registrations(), "transact", when, operator)

        response = application.test_client().post("/register", json={"redirect_uris": [REDIRECT]})
        operator.finish()

        assert response.status_code == (400 if operator.landed_in_the_window else 201)
        if response.status_code == 201:
            registered = response.get_json()
            client_id, token = registered["client_id"], registered["registration_access_token"]
            # Nobody asks for the registration in between, so no lazy check
            # gets the chance to tidy up before the id is reused.
            operator.create_later(client_id)
            _assert_the_operators_client_is_untouched(application, operator)
            _assert_the_old_credential_is_dead(application, client_id, token)
            _assert_the_operators_client_is_untouched(application, operator)
        else:
            assert response.status_code == 400
            assert "registration_access_token" not in response.get_data(as_text=True)
            assert registrations().list() == [], "a record was left for a client that is gone"
            assert _runtime_clients().list() == []

    def test_a_registration_that_loses_the_last_slot_leaves_no_client_behind(self, tmp_path, monkeypatch):
        """The client is created before its record, because the record is
        about that instance. When a concurrent registration takes the last
        slot in between, the client that got no record goes again: the
        limit bounds the clients an open endpoint creates, not only the
        records."""
        application = _application(tmp_path, max_clients=2)
        _register(application)
        rival = Operator(application, register=True)
        # Once the client is there and before its record is: not right after
        # the client's creation, which holds loads off, and with them the
        # rival's own client, for as long as the window is open.
        _open_window(monkeypatch, registrations(), "transact", "before", rival)

        response = application.test_client().post("/register", json={"redirect_uris": [REDIRECT]})
        rival.finish()

        assert rival.landed_in_the_window
        assert (response.status_code, rival.registered) == (429, 201)
        assert len(registrations().list()) == 2
        assert sorted(client.client_id for client in _runtime_clients().list()) == sorted(
            record.client_id for record in registrations().list()
        )


    def test_nor_does_it_take_away_a_client_that_took_its_id(self, tmp_path, monkeypatch):
        """The client that gets no record goes by instance. If the id has
        changed hands by then, what holds it is somebody else's client."""
        application = _application(tmp_path, max_clients=2)
        first, _ = _register(application)
        rival = Operator(application, register=True)
        rival.take_the_other_id, rival.leave_alone = True, {first}
        _open_window(monkeypatch, registrations(), "transact", "before", rival)

        response = application.test_client().post("/register", json={"redirect_uris": [REDIRECT]})
        rival.finish()

        assert rival.landed_in_the_window
        assert (response.status_code, rival.registered) == (429, 201)
        _assert_the_operators_client_is_untouched(application, rival)

    def test_nor_a_client_an_operator_has_started_promoting(self, tmp_path, monkeypatch):
        """A client is visible as soon as it is created, so an operator can
        promote it before its registration is through. The client that gets
        no record goes the way every runtime client goes, which honours the
        promotion: removed behind its back, it would end up declared with no
        promoted event and a 429 for an answer."""
        application = _application(tmp_path, max_clients=2)
        first, _ = _register(application)
        rival = Operator(application, register=True)
        marked = []

        def and_the_operator_promotes_it(*args, **kwargs):
            taken = {record.client_id for record in registrations().list()}
            (unrecorded,) = {c.client_id for c in _runtime_clients().list()} - taken
            claim_for_promotion("client", unrecorded, "writing")
            marked.append(unrecorded)

        rival.and_then = and_the_operator_promotes_it
        _open_window(monkeypatch, registrations(), "transact", "before", rival)

        response = application.test_client().post("/register", json={"redirect_uris": [REDIRECT]})
        rival.finish()

        assert (response.status_code, rival.registered) == (429, 201)
        assert _runtime_clients().get(marked[0]) is not None, "a client being promoted was removed"

    def test_a_deleted_client_takes_its_record_with_it(self, application):
        """At once, not at the next sweep. An orphan record matches nothing,
        so this is not what keeps a credential from being inherited; it is
        what keeps the repository saying what is so."""
        client_id, token = _register(application)

        assert application.test_client().delete(f"/api/runtime/clients/{client_id}").status_code == 200
        assert registrations().list() == []

        client_id, token = _register(application)
        deleted = application.test_client().delete(f"/register/{client_id}", headers=_bearer(token))
        assert deleted.status_code == 204
        assert registrations().list() == []


class TestTheManagementViewDescribesOneInstance:
    """``/api/runtime/clients`` shows a client and says whether somebody
    registered it (``source: dcr``). Both have to be about the same
    instance: the fields of a client an operator created, labelled with the
    registration of a client that took its id while the answer was being
    put together, describe a client that never existed."""

    OPERATORS = ["http://localhost:1/operator"]

    def _swap_in(self, application, client_id, registered):
        """Replace whatever holds ``client_id`` with a new client that is, or
        is not, dynamically registered under that same id."""
        from nanoidp.config import OAuthClient
        from nanoidp.services.dynamic_registration import (
            new_registration_token,
            record_registration,
        )
        from nanoidp.services.identities import identities_for

        def swap():
            identities = identities_for(get_config(), get_config().snapshot)
            application.test_client().delete(f"/api/runtime/clients/{client_id}")
            created = identities.create_runtime_client_entry(
                OAuthClient(
                    client_id=client_id,
                    token_endpoint_auth_method="none",
                    redirect_uris=[REDIRECT] if registered else self.OPERATORS,
                )
            )
            if registered:
                record_registration(created, ["authorization_code"], new_registration_token(), 100)

        return swap

    def _read(self, application, client_id, listing):
        client = application.test_client()
        if not listing:
            return client.get(f"/api/runtime/clients/{client_id}").get_json()
        (found,) = [c for c in client.get("/api/runtime/clients").get_json()["clients"] if c["client_id"] == client_id]
        return found

    @pytest.mark.parametrize("listing", [False, True], ids=["one", "list"])
    def test_an_operators_client_is_never_labelled_with_its_successors_registration(
        self, application, monkeypatch, listing
    ):
        client_id = "shared-id"
        application.test_client().post(
            "/api/runtime/clients",
            json={"client_id": client_id, "client_secret": OPERATOR_SECRET, "redirect_uris": self.OPERATORS},
        )
        successor = Operator(application)
        successor._thread = threading.Thread(target=self._swap_in(application, client_id, registered=True))
        _open_window(monkeypatch, _runtime_clients(), "entries" if listing else "entry", "after", successor)

        shown = self._read(application, client_id, listing)
        successor.finish()

        assert successor.landed_in_the_window
        assert shown["redirect_uris"] == self.OPERATORS
        assert shown.get("source") != "dcr"
        assert self._read(application, client_id, listing).get("source") == "dcr"

    @pytest.mark.parametrize("listing", [False, True], ids=["one", "list"])
    def test_nor_an_operators_successor_with_the_registration_it_replaced(
        self, application, monkeypatch, listing
    ):
        client_id, _ = _register(application)
        successor = Operator(application)
        successor._thread = threading.Thread(target=self._swap_in(application, client_id, registered=False))
        _open_window(monkeypatch, _runtime_clients(), "entries" if listing else "entry", "after", successor)

        shown = self._read(application, client_id, listing)
        successor.finish()

        assert successor.landed_in_the_window
        assert shown["redirect_uris"] == [REDIRECT]
        assert self._read(application, client_id, listing).get("source") != "dcr"


class TestAnOrphanCredentialLearnsNothingAboutItsSuccessor:
    def test_not_even_that_it_is_being_promoted(self, application, monkeypatch):
        """The id changed hands and the operator is promoting the new client
        when the old credential asks for a delete. The instance it names is
        gone, and that is the whole answer: 401, like any unknown
        registration, not the 409 that belongs to somebody else's client."""
        client_id, token = _register(application)
        operator = Operator(application, client_id, token, delete_first=True)

        def promoting():
            claim_for_promotion("client", client_id)

        operator.and_then_created = promoting
        # After the last look at the client, when the credential has been
        # accepted and only the delete is left.
        _open_window(monkeypatch, _runtime_clients(), "entry", "after", operator, nth=LAST_CLIENT_READ)

        deleted = application.test_client().delete(f"/register/{client_id}", headers=_bearer(token))
        operator.finish()

        assert deleted.status_code == 401
        _assert_the_operators_client_is_untouched(application, operator)

    def test_and_a_record_found_orphaned_at_the_delete_is_dropped(self, application, monkeypatch):
        """The client went, behind the registration's back, between the
        check of the credential and the delete: nothing to manage, 401, and
        the record does not stay to count against the limit."""
        client_id, token = _register(application)
        found = identities_module.IdentityResolver.delete_runtime_client

        def gone_by_then(self, name, instance_id=None):
            self.store.clients.delete(name)
            return found(self, name, instance_id)

        monkeypatch.setattr(identities_module.IdentityResolver, "delete_runtime_client", gone_by_then)

        deleted = application.test_client().delete(f"/register/{client_id}", headers=_bearer(token))

        assert deleted.status_code == 401
        assert registrations().list() == []


class TestALoadThatDeclaresTheId:
    """Between a load that declares a registered client's id and the
    reconciliation that retires the runtime client, both exist. The client
    that answers to the id is already the declared one."""

    def _declare(self, application, tmp_path, client_id, during):
        import nanoidp.app as app_module

        settings = tmp_path / "config" / "settings.yaml"
        document = yaml.safe_load(settings.read_text())
        document["oauth"]["clients"].append(
            {"client_id": client_id, "client_secret": "the-declared-secret", "redirect_uris": [REDIRECT]}
        )
        settings.write_text(yaml.safe_dump(document))
        reconcile = app_module.reconcile_runtime_identities
        seen = []

        def before_reconciling(config):
            seen.append(during())
            return reconcile(config)

        return app_module, before_reconciling, seen

    def test_the_registration_has_already_ended(self, application, tmp_path, monkeypatch):
        client_id, token = _register(application)
        app_module, before_reconciling, seen = self._declare(
            application, tmp_path, client_id,
            lambda: application.test_client().get(f"/register/{client_id}", headers=_bearer(token)),
        )
        monkeypatch.setattr(app_module, "reconcile_runtime_identities", before_reconciling)

        assert application.test_client().post("/api/config/reload").status_code == 200

        assert seen[0].status_code == 401

    def test_a_delete_that_got_in_first_is_the_only_thing_the_audit_says(
        self, application, tmp_path, monkeypatch
    ):
        """The runtime client is deleted after the reconciliation has listed
        what the load shadows and before it retires it. It finds nothing to
        retire and must not claim it did."""
        from nanoidp.services.audit import get_audit_log

        client_id, _ = _register(application)
        app_module, _, _ = self._declare(application, tmp_path, client_id, lambda: None)
        listed = MemoryRuntimeRepository.entries
        once = []

        def then_somebody_deletes_it(self):
            found = listed(self)
            if self is _runtime_clients() and not once and any(e.name == client_id for e in found):
                once.append(True)
                monkeypatch.setattr(MemoryRuntimeRepository, "entries", listed)
                assert application.test_client().delete(f"/api/runtime/clients/{client_id}").status_code == 200
            return found

        monkeypatch.setattr(MemoryRuntimeRepository, "entries", then_somebody_deletes_it)

        assert application.test_client().post("/api/config/reload").status_code == 200

        assert once == [True]
        assert len(get_audit_log().get_entries(event_type="runtime_identity_deleted")) == 1
        assert get_audit_log().get_entries(event_type="runtime_identity_removed_on_reload") == []


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
        claim_for_promotion("client", client_id)

        if surface == "runtime":
            refused = client.delete(f"/api/runtime/clients/{client_id}")
        else:
            refused = client.delete(f"/register/{client_id}", headers=_bearer(token))

        assert refused.status_code == 409
        read = client.get(f"/register/{client_id}", headers=_bearer(token))
        assert read.status_code == 200
        assert read.get_json()["client_id"] == client_id


def _while_promoting(application, monkeypatch, client_id, delete):
    """Run a request while a promotion of ``client_id`` is writing the file.
    Returns the request's response, whether it answered before the promotion
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

        deleted, answered_at_once, promoted = _while_promoting(
            application, monkeypatch, client_id,
            lambda client: client.delete(f"/api/runtime/clients/{client_id}"),
        )

        assert answered_at_once
        assert deleted.status_code == 409
        assert deleted.get_json()["kind"] == "promotion_in_progress"
        assert promoted == 200

    def test_the_registration_never_deletes_the_client_it_became(self, application, monkeypatch):
        """While the operator's promotion of the client is writing the file,
        the registration's own delete of it is refused, like the runtime
        API's, and the client ends up declared."""
        client_id, token = _register(application)

        deleted, answered_at_once, promoted = _while_promoting(
            application, monkeypatch, client_id,
            lambda client: client.delete(f"/register/{client_id}", headers=_bearer(token)),
        )

        assert promoted == 200
        # At once, and refused: nothing keeps this delete waiting for the
        # promotion any more, and the client it names is being promoted.
        assert answered_at_once
        assert deleted.status_code == 409
        assert any(c.client_id == client_id for c in get_config().settings.clients)


class TestAnOpenEndpointDoesNotQueueBehindALoad:
    """A promotion holds loads off while it writes the file, and a reload
    while it runs its hooks. ``/register/<id>`` is open: whoever has no
    credential for it must be told so without waiting for either. And
    nothing an open request triggers (an audit entry runs hooks) may run
    while loads are held off. When the lifecycle was one critical section
    on that lock (#408) both took care; they hold by construction now, and
    stay pinned.

    ``POST /register`` is not claimed here: it creates a runtime client,
    and creating one waits for a load in progress, as it always has
    (#235), because the name has to be checked against what is declared."""

    @pytest.mark.parametrize("verb", ["get", "delete"])
    @pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer not-the-token"}])
    def test_a_caller_without_the_credential_is_answered_at_once(
        self, application, monkeypatch, headers, verb
    ):
        client_id, _ = _register(application)

        refused, answered_at_once, promoted = _while_promoting(
            application, monkeypatch, client_id,
            lambda client: getattr(client, verb)(f"/register/{client_id}", headers=headers),
        )

        assert answered_at_once
        assert refused.status_code == 401
        assert promoted == 200

    def test_a_refused_registration_is_audited_with_loads_free(self, tmp_path, monkeypatch):
        """An audit entry runs the on_audit_event hooks. With loads held
        off a slow one would stall every reload and every client creation,
        for a request anyone can send."""
        from nanoidp.routes import registration as registration_routes

        config_dir = tmp_path / "config"
        config_dir.mkdir(parents=True)
        for name in ("settings.yaml", "users.yaml"):
            shutil.copy(_REPO / "config" / name, config_dir / name)
        settings = config_dir / "settings.yaml"
        document = yaml.safe_load(settings.read_text())
        document["jwt"]["keys_dir"] = str(tmp_path / "keys")
        document["oauth"]["dynamic_registration"] = {"enabled": True, "max_clients": 1}
        settings.write_text(yaml.safe_dump(document))
        full = create_app(str(config_dir))
        full.config["TESTING"] = True
        _register(full)
        audit = registration_routes._audit
        scope_was_free = []

        def audited(event_type, *args, **kwargs):
            if event_type == "client_registration_refused":
                free = []

                def another_operation():
                    with get_config().holding_loads():
                        free.append(True)

                thread = threading.Thread(target=another_operation)
                thread.start()
                thread.join(WINDOW_SECONDS)
                scope_was_free.append(bool(free))
            return audit(event_type, *args, **kwargs)

        monkeypatch.setattr(registration_routes, "_audit", audited)

        refused = full.test_client().post("/register", json={"redirect_uris": [REDIRECT]})

        assert refused.status_code == 429
        assert scope_was_free == [True]


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
        _open_window(monkeypatch, _runtime_clients(), "transact", "after", operator)

        promoted = application.test_client().post(f"/api/runtime/clients/{client_id}/promote")
        operator.finish()

        assert promoted.status_code == 200
        assert operator.created == 409
        _assert_never_read(operator)
        _assert_the_old_credential_is_dead(application, client_id, token)
