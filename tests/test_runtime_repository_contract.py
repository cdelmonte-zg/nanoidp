"""The runtime repository contract beyond create/get/list/delete (#404):
entries with an instance identity, holds, and the one atomic decision
primitive every composed operation is written on.

Written against the interface and parameterised over the store factories, so
a later backend (#354) owes all of it by adding its factory to
``tests/runtime_store_contract.py``. The concurrent tests are the point: each
states a property that a composition of single calls under a lock of the
caller's own cannot give to a second process.
"""

import threading
import time

import pytest

from nanoidp.services.runtime_repository import (
    EntryHeld,
    MemoryRuntimeRepository,
    NestedRepositoryUse,
    RepositoryFull,
    RuntimeObjectExists,
    RuntimeObjectMissing,
    TransactionClosed,
    consume,
    create_within,
    delete_if,
    replace,
)
from tests.runtime_store_contract import REPOSITORIES, STORE_FACTORIES

THREADS = 8


def _give_way():
    """Called from inside a decision by the concurrent tests. A decision is
    a few bytecodes long, which threads of one interpreter hardly ever
    interleave on their own: the tests would pass with no atomicity at all.
    Letting the other threads run while the decision is open is what makes
    them fail without it, every time."""
    time.sleep(0.002)


def _race(work):
    """Run ``work(index)`` on THREADS threads released together."""
    barrier = threading.Barrier(THREADS)
    failures = []

    def run(index):
        barrier.wait()
        try:
            work(index)
        except BaseException as failure:  # noqa: BLE001 - reported below
            failures.append(failure)

    threads = [threading.Thread(target=run, args=(index,)) for index in range(THREADS)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert failures == []


@pytest.fixture(params=["once", "twice"], autouse=True)
def decisions_run(request, monkeypatch):
    """A decision may be run again (a busy retry on a backend with real
    transactions), and a backend that never does would let every test here
    pass with a decision that is not safe to repeat. So the whole contract
    runs a second time with each decision run twice, the first against a
    view that is then thrown away."""
    if request.param == "twice":
        monkeypatch.setattr(MemoryRuntimeRepository, "run_decisions_twice", True)


@pytest.fixture(params=STORE_FACTORIES)
def store(request):
    return request.param()


@pytest.fixture(params=REPOSITORIES)
def kit(request, store):
    get_repo, make, name_of, field = request.param
    return get_repo(store), make, name_of, field


class TestEntries:
    def test_an_entry_carries_the_value_and_an_identity(self, kit):
        repo, make, name_of, _ = kit

        created = repo.create_entry(make("alice"))

        assert created.name == "alice"
        assert name_of(created.value) == "alice"
        assert created.instance_id
        assert created.hold is None
        assert repo.entry("alice") == created
        assert repo.entries() == [created]
        assert repo.entry("missing") is None

    def test_create_is_create_entry_without_the_envelope(self, kit):
        repo, make, name_of, _ = kit

        assert name_of(repo.create(make("alice"))) == "alice"
        assert repo.entry("alice").instance_id

    def test_an_identity_is_never_reused(self, kit):
        """Not for another name, and not for the same name created again:
        that second case is what a record naming its client cannot see."""
        repo, make, _, _field = kit

        first = repo.create_entry(make("alice")).instance_id
        other = repo.create_entry(make("bob")).instance_id
        repo.delete("alice")
        again = repo.create_entry(make("alice")).instance_id

        assert len({first, other, again}) == 3

    def test_an_entry_is_by_value(self, kit):
        repo, make, _, field = kit
        created = repo.create_entry(make("alice"))

        field(created.value).append("MUTATED")
        field(repo.entry("alice").value).append("MUTATED")
        field(repo.entries()[0].value).append("MUTATED")

        assert "MUTATED" not in field(repo.get("alice"))


class TestTransact:
    def test_what_decide_returns_is_the_result(self, kit):
        repo, make, _, _field = kit
        repo.create(make("alice"))

        assert repo.transact(lambda view: view.entry("alice") is not None) is True

    def test_the_view_creates_replaces_and_deletes(self, kit):
        repo, make, name_of, field = kit
        repo.create(make("gone"))
        kept = repo.create_entry(make("kept"))

        def decide(view):
            changed = view.entry("kept").value
            field(changed).append("CHANGED")
            return view.create(make("new")), view.replace("kept", changed), view.delete("gone")

        created, replaced, deleted = repo.transact(decide)

        assert deleted is True
        assert [name_of(obj) for obj in repo.list()] == ["kept", "new"]
        assert "CHANGED" in field(repo.get("kept"))
        assert created == repo.entry("new")
        assert replaced == repo.entry("kept")
        assert replaced.instance_id == kept.instance_id

    def test_a_replace_keeps_the_identity_the_hold_and_the_place(self, kit):
        repo, make, name_of, field = kit
        repo.create(make("first"))
        before = repo.create_entry(make("alice"))
        repo.create(make("last"))
        held = repo.transact(lambda view: view.hold("alice", {"why": "test"}))
        changed = make("alice")
        field(changed).append("CHANGED")

        after = repo.transact(lambda view: view.replace("alice", changed))

        assert after.instance_id == before.instance_id
        assert after.hold == held
        assert [name_of(obj) for obj in repo.list()] == ["first", "alice", "last"]

    def test_a_replace_cannot_rename(self, kit):
        repo, make, _, _field = kit
        repo.create(make("alice"))

        with pytest.raises(ValueError):
            repo.transact(lambda view: view.replace("alice", make("bob")))

    def test_the_view_refuses_what_the_repository_refuses(self, kit):
        repo, make, _, _field = kit
        repo.create(make("alice"))

        with pytest.raises(RuntimeObjectExists):
            repo.transact(lambda view: view.create(make("alice")))
        with pytest.raises(RuntimeObjectMissing):
            repo.transact(lambda view: view.replace("missing", make("missing")))
        assert repo.transact(lambda view: view.delete("missing")) is False

    def test_a_decision_that_raises_changes_nothing(self, kit):
        repo, make, name_of, _ = kit
        repo.create(make("alice"))
        before = repo.entries()

        def decide(view):
            view.create(make("bob"))
            view.delete("alice")
            view.hold("bob", {})
            raise LookupError("changed my mind")

        with pytest.raises(LookupError):
            repo.transact(decide)

        assert repo.entries() == before
        assert [name_of(obj) for obj in repo.list()] == ["alice"]

    def test_the_view_is_by_value(self, kit):
        repo, make, _, field = kit
        repo.create(make("alice"))

        def decide(view):
            field(view.entry("alice").value).append("MUTATED")
            field(view.entries()[0].value).append("MUTATED")
            handed_in = make("bob")
            created = view.create(handed_in)
            field(handed_in).append("MUTATED")
            field(created.value).append("MUTATED")

        repo.transact(decide)

        assert "MUTATED" not in field(repo.get("alice"))
        assert "MUTATED" not in field(repo.get("bob"))

    def test_a_decision_sees_its_own_changes(self, kit):
        repo, make, name_of, _ = kit

        def decide(view):
            view.create(make("alice"))
            return [name_of(entry.value) for entry in view.entries()], view.entry("alice") is not None

        assert repo.transact(decide) == (["alice"], True)

    def test_a_decision_works_on_the_view_and_nothing_else(self, kit, store):
        """No other repository, and not this one by the side door: on a
        backend with real transactions that is a nested one, and a decision
        that may be run again must have no effect outside the view."""
        repo, make, _, _field = kit
        repo.create(make("alice"))

        for side_door in (
            lambda: repo.get("alice"),
            lambda: repo.create(make("bob")),
            lambda: repo.transact(lambda view: None),
            lambda: store.users.list(),
            lambda: store.repository("another", lambda obj: str(obj)).list(),
        ):
            with pytest.raises(NestedRepositoryUse):
                repo.transact(lambda view, side_door=side_door: side_door())

        assert repo.get("alice") is not None
        assert repo.get("bob") is None

    def test_a_view_is_of_no_use_once_its_decision_is_over(self, kit):
        """Kept past the call, it would change the repository with no
        atomicity and no lock, or lose what it was told, depending on what
        the decision happened to do."""
        repo, make, name_of, _ = kit
        repo.create(make("alice"))
        kept = []

        repo.transact(lambda view: kept.append(view) or view.create(make("bob")))
        with pytest.raises(LookupError):
            repo.transact(lambda view: kept.append(view) or view.hold("missing", {}))

        for view in kept:
            for late in (
                lambda view=view: view.entry("alice"),
                lambda view=view: view.entries(),
                lambda view=view: view.create(make("carol")),
                lambda view=view: view.replace("alice", make("alice")),
                lambda view=view: view.delete("alice"),
                lambda view=view: view.hold("alice", {}),
                lambda view=view: view.update_hold("alice", "any", {}),
                lambda view=view: view.release_hold("alice", "any"),
            ):
                with pytest.raises(TransactionClosed):
                    late()
        assert [name_of(obj) for obj in repo.list()] == ["alice", "bob"]
        assert repo.entry("alice").hold is None

    def test_a_decision_run_twice_leaves_what_one_run_leaves(self, kit, monkeypatch):
        repo, make, name_of, _ = kit
        monkeypatch.setattr(MemoryRuntimeRepository, "run_decisions_twice", True)
        runs = []

        def decide(view):
            runs.append(len(view.entries()))
            return view.create(make("alice"))

        created = repo.transact(decide)

        assert runs == [0, 0]
        assert repo.entries() == [created]

    def test_the_repository_works_again_after_a_refused_side_door(self, kit):
        repo, make, _, _field = kit
        with pytest.raises(NestedRepositoryUse):
            repo.transact(lambda view: repo.list())

        assert repo.create(make("alice")) is not None


class TestHolds:
    def test_a_hold_is_a_claim_with_its_own_identity(self, kit):
        repo, make, _, _field = kit
        repo.create(make("alice"))

        hold = repo.transact(lambda view: view.hold("alice", {"state": "writing"}))

        assert hold.hold_id
        assert hold.since > 0
        assert hold.payload == {"state": "writing"}
        assert repo.entry("alice").hold == hold

    def test_an_entry_is_held_once(self, kit):
        repo, make, _, _field = kit
        repo.create(make("alice"))
        first = repo.transact(lambda view: view.hold("alice", {}))

        with pytest.raises(EntryHeld):
            repo.transact(lambda view: view.hold("alice", {}))
        with pytest.raises(RuntimeObjectMissing):
            repo.transact(lambda view: view.hold("missing", {}))
        assert repo.entry("alice").hold == first

    def test_a_hold_is_changed_and_released_by_its_own_id_only(self, kit):
        """A continuation or a recovery acts on the hold it installed, not
        on one somebody installed later."""
        repo, make, _, _field = kit
        repo.create(make("alice"))
        hold = repo.transact(lambda view: view.hold("alice", {"state": "writing"}))

        assert repo.transact(lambda view: view.update_hold("alice", "not-it", {})) is False
        assert repo.transact(lambda view: view.release_hold("alice", "not-it")) is False
        assert repo.entry("alice").hold == hold

        assert repo.transact(lambda view: view.update_hold("alice", hold.hold_id, {"state": "written"}))
        updated = repo.entry("alice").hold
        assert (updated.hold_id, updated.since, updated.payload) == (
            hold.hold_id,
            hold.since,
            {"state": "written"},
        )

        assert repo.transact(lambda view: view.release_hold("alice", hold.hold_id)) is True
        assert repo.entry("alice").hold is None
        assert repo.transact(lambda view: view.release_hold("alice", hold.hold_id)) is False
        assert repo.transact(lambda view: view.release_hold("missing", hold.hold_id)) is False

    def test_a_payload_is_by_value(self, kit):
        repo, make, _, _field = kit
        repo.create(make("alice"))
        payload = {"context": {"endpoint": "/x"}}
        hold = repo.transact(lambda view: view.hold("alice", payload))

        payload["context"]["endpoint"] = "MUTATED"
        hold.payload["context"]["endpoint"] = "MUTATED"
        repo.entry("alice").hold.payload["context"]["endpoint"] = "MUTATED"

        assert repo.entry("alice").hold.payload == {"context": {"endpoint": "/x"}}

    def test_a_payload_is_what_any_backend_could_keep(self, kit):
        """A JSON object: a backend that serializes must be able to store
        it, so the one that does not must not accept more."""
        import datetime

        repo, make, _, _field = kit
        repo.create(make("alice"))

        for payload in ({"at": datetime.datetime.now()}, {"who": make("bob")}, {1: "int key"}, ["a list"]):
            with pytest.raises(ValueError):
                repo.transact(lambda view, payload=payload: view.hold("alice", payload))
        hold = repo.transact(lambda view: view.hold("alice", {"n": 1, "nested": {"list": [1, "a", None]}}))
        with pytest.raises(ValueError):
            repo.transact(lambda view: view.update_hold("alice", hold.hold_id, {"at": object()}))

        assert repo.entry("alice").hold == hold

    def test_the_store_attaches_no_meaning_to_a_hold(self, kit):
        """It keeps the claim and compares it; refusing to delete a held
        object is a rule of whoever installed the hold."""
        repo, make, _, _field = kit
        repo.create(make("alice"))
        repo.transact(lambda view: view.hold("alice", {}))

        assert repo.delete("alice") is True


class TestReplace:
    def test_the_change_is_applied_to_the_current_value(self, kit):
        repo, make, _, field = kit
        before = repo.create_entry(make("alice"))

        def change(value):
            field(value).append("CHANGED")
            return value

        after = replace(repo, "alice", change)

        assert "CHANGED" in field(repo.get("alice"))
        assert after == repo.entry("alice")
        assert after.instance_id == before.instance_id
        assert replace(repo, "missing", change) is None

    def test_no_reader_ever_finds_the_object_absent(self, kit):
        """What delete and create could not give: a reader between the two
        saw a live object as gone."""
        # No mutant of the backend reaches this one: it is here for the
        # backend that implements replace as two statements (#354).
        repo, make, _, field = kit
        repo.create(make("alice"))
        stop = threading.Event()
        absences = []

        def read():
            while not stop.is_set():
                if repo.get("alice") is None:
                    absences.append(True)

        reader = threading.Thread(target=read)
        reader.start()
        try:
            for _ in range(300):
                replace(repo, "alice", lambda value: value)
        finally:
            stop.set()
            reader.join()

        assert absences == []

    def test_concurrent_changes_are_all_applied(self, kit):
        """Each change starts from the value the one before left."""
        repo, make, _, field = kit
        repo.create(make("alice"))

        def work(index):
            def change(value):
                _give_way()
                field(value).append(f"by-{index}")
                return value

            replace(repo, "alice", change)

        _race(work)

        assert sorted(item for item in field(repo.get("alice")) if item.startswith("by-")) == sorted(
            f"by-{index}" for index in range(THREADS)
        )


class TestConsume:
    def test_an_object_is_consumed_once(self, kit):
        repo, make, name_of, _ = kit
        created = repo.create_entry(make("alice"))

        assert consume(repo, "alice") == created
        assert consume(repo, "alice") is None
        assert repo.get("alice") is None

    def test_a_predicate_that_says_no_consumes_nothing(self, kit):
        repo, make, _, _field = kit
        created = repo.create_entry(make("alice"))

        assert consume(repo, "alice", lambda entry: False) is None
        assert repo.entry("alice") == created
        assert consume(repo, "alice", lambda entry: entry.instance_id == created.instance_id) == created

    def test_concurrent_consumers_have_one_winner(self, kit):
        repo, make, _, _field = kit
        repo.create(make("alice"))
        winners = []

        def accept(entry):
            _give_way()
            return True

        def work(index):
            if consume(repo, "alice", accept) is not None:
                winners.append(index)

        _race(work)

        assert len(winners) == 1


class TestDeleteIf:
    def test_only_the_named_instance_is_deleted(self, kit):
        """The object somebody recreated under the name is not the one that
        was meant."""
        repo, make, _, _field = kit
        first = repo.create_entry(make("alice"))
        repo.delete("alice")
        second = repo.create_entry(make("alice"))

        assert delete_if(repo, "alice", first.instance_id) is False
        assert repo.entry("alice") == second
        assert delete_if(repo, "alice", second.instance_id) is True
        assert delete_if(repo, "alice", second.instance_id) is False
        assert delete_if(repo, "missing", second.instance_id) is False

    def test_a_held_instance_needs_its_hold_named(self, kit):
        repo, make, _, _field = kit
        created = repo.create_entry(make("alice"))
        hold = repo.transact(lambda view: view.hold("alice", {}))

        assert delete_if(repo, "alice", created.instance_id) is False
        assert delete_if(repo, "alice", created.instance_id, hold_id="not-it") is False
        assert repo.entry("alice") is not None
        assert delete_if(repo, "alice", created.instance_id, hold_id=hold.hold_id) is True

    def test_naming_a_hold_the_instance_does_not_carry_deletes_nothing(self, kit):
        repo, make, _, _field = kit
        created = repo.create_entry(make("alice"))

        assert delete_if(repo, "alice", created.instance_id, hold_id="released-meanwhile") is False
        assert repo.entry("alice") == created


class TestCreateWithin:
    def test_the_limit_refuses_the_one_too_many(self, kit):
        repo, make, name_of, _ = kit
        create_within(repo, make("a"), limit=2)
        created = create_within(repo, make("b"), limit=2)

        with pytest.raises(RepositoryFull):
            create_within(repo, make("c"), limit=2)

        assert created == repo.entry("b")
        assert [name_of(obj) for obj in repo.list()] == ["a", "b"]

    def test_expired_objects_make_room_first(self, kit):
        repo, make, name_of, _ = kit
        create_within(repo, make("stale"), limit=2)
        create_within(repo, make("live"), limit=2)

        create_within(repo, make("new"), limit=2, is_expired=lambda value: name_of(value) == "stale")

        assert [name_of(obj) for obj in repo.list()] == ["live", "new"]

    def test_a_refusal_still_drops_what_expired(self, kit):
        repo, make, name_of, _ = kit
        for name in ("stale", "live-1", "live-2"):
            repo.create(make(name))

        with pytest.raises(RepositoryFull):
            create_within(repo, make("new"), limit=2, is_expired=lambda value: name_of(value) == "stale")

        assert [name_of(obj) for obj in repo.list()] == ["live-1", "live-2"]

    @pytest.mark.parametrize("limit", [10, 2])
    def test_a_taken_name_is_refused_as_ever(self, kit, limit):
        """The same answer for the same request whether or not there was
        room, and what expired goes all the same."""
        repo, make, name_of, _ = kit
        repo.create(make("stale"))
        repo.create(make("alice"))
        repo.create(make("other"))

        with pytest.raises(RuntimeObjectExists):
            create_within(repo, make("alice"), limit=limit, is_expired=lambda value: name_of(value) == "stale")

        assert [name_of(obj) for obj in repo.list()] == ["alice", "other"]

    def test_the_limit_holds_under_concurrent_creates(self, kit):
        repo, make, _, _field = kit
        repo.create(make("already-there"))
        accepted = [True]
        gave_way = threading.local()

        def never_expired(value):
            # Once per decision, however many objects it looks at.
            if not getattr(gave_way, "done", False):
                gave_way.done = True
                _give_way()
            return False

        def work(index):
            for attempt in range(5):
                gave_way.done = False
                try:
                    create_within(repo, make(f"c-{index}-{attempt}"), limit=10, is_expired=never_expired)
                    accepted.append(True)
                except RepositoryFull:
                    pass

        _race(work)

        assert len(accepted) == 10
        assert len(repo.list()) == 10
