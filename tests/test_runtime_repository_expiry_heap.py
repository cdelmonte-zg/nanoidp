"""A cleanup of the in-memory repository costs what is due, not what is kept
(#417).

``delete_expired(now)`` sits inside the writing decision of every service that
keeps expiring state, so every write paid a scan of the whole collection under
the store's one lock. The backend now keeps a lazy min-heap of the expiries:
items ``(expires_at, instance_id, name)``, pushed when an entry gets a time and
never looked for again, recognised as stale (the entry gone, recreated, or its
time moved) when they reach the top.

Nothing here is pinned by timing. That an entry which is not due is not looked
at: by counting the items a cleanup settles. That the heap is transactional
state like the index: by decisions that raise and decisions run twice. And that
nothing else changed: by driving the repository through every operation that
touches an expiry, next to a model that always looks at everything.

(An earlier design, a lower bound on the earliest expiry, was built and
dropped: with a fixed TTL and steady writes one entry comes due before nearly
every write, so it scanned nearly every time, and dearer than before. See the
issue.)
"""

import dataclasses
import random
import threading

import pytest

from nanoidp.services import runtime_repository
from nanoidp.services.runtime_repository import (
    MemoryRuntimeRepository,
    RuntimeObjectExists,
    consume,
    delete_expired,
)


@dataclasses.dataclass
class Thing:
    name: str


class ThingCodec:
    def copy(self, value):
        return dataclasses.replace(value)

    def dump(self, value):
        return dataclasses.asdict(value)

    def load(self, data):
        return Thing(**data)


def _repository():
    return MemoryRuntimeRepository(threading.RLock(), lambda thing: thing.name, ThingCodec())


@pytest.fixture
def settled(monkeypatch):
    """The names of the items a cleanup looked at, in order."""
    looked_at = []
    settle = runtime_repository._MemoryTransaction._settle

    def watching(self, item, held):
        looked_at.append(item[2])
        return settle(self, item, held)

    monkeypatch.setattr(runtime_repository._MemoryTransaction, "_settle", watching)
    return looked_at


def _per_decision(names):
    """What one decision looks at: the suite also runs with every decision
    run twice, the first time against a view that is thrown away."""
    return names * (2 if MemoryRuntimeRepository.run_decisions_twice else 1)


def _heap(repository):
    return sorted(repository._due)


class TestACleanupLooksAtWhatIsDueAndNothingElse:
    def test_nothing_is_looked_at_when_nothing_is_due(self, settled):
        repository = _repository()
        for index in range(50):
            repository.create(Thing(f"t{index}"), expires_at=1000.0 + index)
        repository.create(Thing("forever"))

        assert [delete_expired(repository, 999.0) for _ in range(3)] == [0, 0, 0]
        assert settled == []

    def test_only_what_is_due_is_looked_at(self, settled):
        repository = _repository()
        for index in range(50):
            repository.create(Thing(f"t{index:02}"), expires_at=1000.0 + index)

        assert delete_expired(repository, 1002.5) == 3
        assert settled == _per_decision(["t00", "t01", "t02"])
        assert len(repository.list()) == 47

    def test_steady_state_looks_at_one_entry_per_write(self, settled):
        """The workload the first design failed: a fixed lifetime and steady
        writes, so that one entry comes due before every write."""
        repository = _repository()
        for index in range(200):
            repository.create(Thing(f"t{index:03}"), expires_at=1000.0 + index)

        for index in range(100):
            assert delete_expired(repository, 1000.5 + index) == 1

        assert len(settled) == len(_per_decision(list(range(100))))

    def test_at_its_very_time_an_entry_is_not_due(self, settled):
        """Due is strictly past its time (#413)."""
        repository = _repository()
        repository.create(Thing("t"), expires_at=1000.0)

        assert delete_expired(repository, 1000.0) == 0
        assert settled == []
        assert repository.get("t") is not None
        assert delete_expired(repository, 1000.001) == 1

    def test_an_entry_that_never_expires_is_never_on_the_heap(self):
        repository = _repository()
        repository.create(Thing("forever"))
        repository.create(Thing("t"), expires_at=1000.0)
        repository.transact(lambda view: view.set_expires_at("t", None))

        assert delete_expired(repository, 1e12) == 0
        assert [thing.name for thing in repository.list()] == ["forever", "t"]
        assert _heap(repository) == []


class TestItemsThatNoLongerSayAnythingTrue:
    def test_an_item_of_an_earlier_instance_does_not_remove_the_successor(self, settled):
        repository = _repository()
        repository.create(Thing("t"), expires_at=1000.0)
        repository.delete("t")
        successor = repository.create_entry(Thing("t"), expires_at=5000.0)

        assert delete_expired(repository, 2000.0) == 0
        assert settled == _per_decision(["t"])
        assert repository.entry("t").instance_id == successor.instance_id

    def test_a_successor_with_the_very_same_time_is_not_taken_for_its_predecessor(self):
        """Same name, same time, another instance: the predecessor's item is
        stale, the successor's own is what removes it, once."""
        repository = _repository()
        repository.create(Thing("t"), expires_at=1000.0)
        repository.delete("t")
        repository.create(Thing("t"), expires_at=1000.0)
        repository.create(Thing("other"), expires_at=1000.0)

        assert delete_expired(repository, 2000.0) == 2
        assert repository.list() == []

    def test_an_item_of_an_earlier_instance_is_not_kept_alive_by_a_held_successor(self):
        """The successor has the predecessor's very time and is held. Told
        apart by the time alone, the predecessor's item would pass for the
        successor's, be set aside as held and go back on the heap with it,
        cleanup after cleanup. The instance says whose it is."""
        repository = _repository()
        repository.create(Thing("t"), expires_at=1000.0)
        repository.delete("t")
        successor = repository.create_entry(Thing("t"), expires_at=1000.0)
        repository.transact(lambda view: view.hold("t", {"why": "test"}))

        for _ in range(3):
            assert delete_expired(repository, 2000.0) == 0

        assert _heap(repository) == [(1000.0, successor.instance_id, "t")]

    def test_a_time_moved_later_is_not_due_at_the_earlier_one(self, settled):
        repository = _repository()
        repository.create(Thing("t"), expires_at=1000.0)
        repository.transact(lambda view: view.set_expires_at("t", 3000.0))

        assert delete_expired(repository, 2000.0) == 0
        assert repository.get("t") is not None
        assert delete_expired(repository, 3000.5) == 1

    def test_a_time_brought_forward_is_due_at_the_earlier_one(self):
        repository = _repository()
        repository.create(Thing("t"), expires_at=3000.0)
        repository.create(Thing("forever"))
        repository.transact(lambda view: view.set_expires_at("t", 1000.0))
        repository.transact(lambda view: view.set_expires_at("forever", 1200.0))

        assert delete_expired(repository, 1500.0) == 2
        # The item of 3000 is still there, and is nobody's when its turn comes.
        assert delete_expired(repository, 3500.0) == 0

    def test_a_time_moved_away_and_back_is_removed_once(self):
        repository = _repository()
        repository.create(Thing("t"), expires_at=1000.0)
        repository.transact(lambda view: view.set_expires_at("t", 3000.0))
        repository.transact(lambda view: view.set_expires_at("t", 1000.0))

        assert delete_expired(repository, 1500.0) == 1
        assert repository.list() == []

    def test_a_replace_and_a_hold_keep_the_entry_on_the_heap(self):
        repository = _repository()
        repository.create(Thing("t"), expires_at=1000.0)
        runtime_repository.replace(repository, "t", lambda thing: thing)
        held = repository.transact(lambda view: view.hold("t", {"why": "test"}))
        repository.transact(lambda view: view.release_hold("t", held.hold_id))

        assert delete_expired(repository, 1500.0) == 1

    def test_a_consumed_entry_leaves_an_item_that_removes_nothing(self):
        repository = _repository()
        repository.create(Thing("t"), expires_at=1000.0)
        assert consume(repository, "t") is not None

        assert delete_expired(repository, 1500.0) == 0
        assert _heap(repository) == []


class TestHeldEntries:
    def test_a_held_entry_that_is_due_stays_and_the_others_go(self, settled):
        """Put back when the loop is over: put back at once it would be on
        top again, and the loop would never get to the others."""
        repository = _repository()
        repository.create(Thing("held"), expires_at=1000.0)
        for index in range(5):
            repository.create(Thing(f"t{index}"), expires_at=1100.0 + index)
        held = repository.transact(lambda view: view.hold("held", {"why": "test"}))

        assert delete_expired(repository, 2000.0) == 5
        assert [thing.name for thing in repository.list()] == ["held"]
        # It waits on the heap, looked at by each cleanup and by nothing else.
        assert [item[2] for item in _heap(repository)] == ["held"]
        assert delete_expired(repository, 2000.0) == 0
        repository.transact(lambda view: view.release_hold("held", held.hold_id))
        assert delete_expired(repository, 2000.0) == 1
        assert _heap(repository) == []

    def test_a_held_entry_is_on_the_heap_once_however_often_it_is_looked_at(self):
        repository = _repository()
        repository.create(Thing("held"), expires_at=1000.0)
        repository.transact(lambda view: view.hold("held", {"why": "test"}))

        for _ in range(20):
            assert delete_expired(repository, 2000.0) == 0

        assert len(_heap(repository)) == 1

    def test_twice_in_one_decision_a_held_entry_is_still_there_once(self):
        repository = _repository()
        repository.create(Thing("held"), expires_at=1000.0)
        repository.create(Thing("t"), expires_at=1000.0)
        repository.transact(lambda view: view.hold("held", {"why": "test"}))

        assert repository.transact(lambda view: (view.delete_expired(2000.0), view.delete_expired(2000.0))) == (1, 0)
        assert [item[2] for item in _heap(repository)] == ["held"]


class TestTheHeapIsTransactionalState:
    def test_a_decision_that_raises_leaves_the_entries_and_the_heap_as_they_were(self):
        repository = _repository()
        for index in range(5):
            repository.create(Thing(f"t{index}"), expires_at=1000.0 + index)
        repository.create(Thing("held"), expires_at=1000.0)
        repository.transact(lambda view: view.hold("held", {"why": "test"}))
        entries, heap = repository.entries(), _heap(repository)

        def decide(view):
            view.create(Thing("added"), expires_at=500.0)
            view.set_expires_at("t4", 900.0)
            assert view.delete_expired(1002.5) == 5  # t0 t1 t2, and the two above; not the held one
            view.create(Thing("added after the cleanup"), expires_at=9000.0)
            raise RuntimeError("no")

        with pytest.raises(RuntimeError):
            repository.transact(decide)

        assert repository.entries() == entries
        assert _heap(repository) == heap
        assert delete_expired(repository, 1002.5) == 3

    def test_something_other_than_an_exception_puts_the_pops_back_too(self):
        repository = _repository()
        repository.create(Thing("t"), expires_at=1000.0)
        heap = _heap(repository)

        def decide(view):
            view.delete_expired(2000.0)
            raise KeyboardInterrupt

        with pytest.raises(KeyboardInterrupt):
            repository.transact(decide)

        assert _heap(repository) == heap
        assert delete_expired(repository, 2000.0) == 1

    def test_an_interrupt_while_an_item_is_taken_off_does_not_lose_it(self, monkeypatch):
        """Written down before it is taken off. The other way round, an
        interrupt between the two would leave an entry with a time and no
        item, which no cleanup would ever find again; this way it leaves,
        at worst, an item twice."""
        repository = _repository()
        repository.create(Thing("t"), expires_at=1000.0)
        heappop = runtime_repository.heappop

        def interrupted(heap):
            heappop(heap)
            raise KeyboardInterrupt

        monkeypatch.setattr(runtime_repository, "heappop", interrupted)
        with pytest.raises(KeyboardInterrupt):
            delete_expired(repository, 2000.0)
        monkeypatch.undo()

        assert repository.get("t") is not None
        assert delete_expired(repository, 2000.0) == 1

    def test_an_interrupt_while_a_decision_is_adopted_does_not_leave_an_entry_without_its_item(self, monkeypatch):
        """The items first, then the index: interrupted in between, there
        are items for entries that are not there, which are stale ones."""
        repository = _repository()

        def interrupted(heap, item):
            raise KeyboardInterrupt

        monkeypatch.setattr(runtime_repository, "heappush", interrupted)
        with pytest.raises(KeyboardInterrupt):
            repository.create(Thing("t"), expires_at=1000.0)
        monkeypatch.undo()

        on_the_heap = {item[1] for item in repository._due}
        assert all(entry.instance_id in on_the_heap for entry in repository.entries())

    def test_a_decision_run_twice_pushes_once_and_loses_no_pop(self, monkeypatch):
        monkeypatch.setattr(MemoryRuntimeRepository, "run_decisions_twice", True)
        repository = _repository()
        repository.create(Thing("due"), expires_at=1000.0)
        repository.create(Thing("later"), expires_at=3000.0)

        def decide(view):
            removed = view.delete_expired(2000.0)
            view.create(Thing("new"), expires_at=4000.0)
            return removed

        assert repository.transact(decide) == 1
        assert [item[2] for item in _heap(repository)] == ["later", "new"]
        assert [thing.name for thing in repository.list()] == ["later", "new"]

    def test_what_a_decision_added_is_not_due_at_its_very_time_either(self):
        repository = _repository()

        def decide(view):
            view.create(Thing("t"), expires_at=1000.0)
            return view.delete_expired(1000.0), view.delete_expired(1000.001)

        assert repository.transact(decide) == (0, 1)

    def test_what_a_decision_added_is_due_within_it(self):
        repository = _repository()

        def decide(view):
            view.create(Thing("a"), expires_at=1000.0)
            first = view.delete_expired(1500.0)
            view.create(Thing("b"), expires_at=1200.0)
            view.create(Thing("c"), expires_at=2000.0)
            return first, view.delete_expired(1500.0), view.delete_expired(1500.0)

        assert repository.transact(decide) == (1, 1, 0)
        assert [thing.name for thing in repository.list()] == ["c"]
        assert [item[2] for item in _heap(repository)] == ["c"]

    def test_a_create_that_is_refused_pushes_nothing(self):
        repository = _repository()
        repository.create(Thing("t"), expires_at=3000.0)
        with pytest.raises(RuntimeObjectExists):
            repository.create(Thing("t"), expires_at=1000.0)

        assert [item[0] for item in _heap(repository)] == [3000.0]

    def test_delete_all_empties_the_heap(self, settled):
        repository = _repository()
        for index in range(5):
            repository.create(Thing(f"t{index}"), expires_at=1000.0 + index)
        repository.delete_all()

        assert _heap(repository) == []
        assert delete_expired(repository, 5000.0) == 0
        assert settled == []


class TestStaleItemsAreBounded:
    def test_a_time_moved_again_and_again_does_not_grow_the_heap_without_bound(self):
        repository = _repository()
        repository.create(Thing("t"), expires_at=10_000.0)
        for step in range(5000):
            repository.transact(lambda view, step=step: view.set_expires_at("t", 10_000.0 + step))

        assert len(repository._due) <= 2 * 1 + runtime_repository._DUE_SLACK
        assert delete_expired(repository, 14_998.5) == 0
        assert delete_expired(repository, 15_000.0) == 1

    def test_entries_deleted_long_before_their_time_do_not_stay_as_items(self):
        repository = _repository()
        for step in range(5000):
            repository.create(Thing(f"t{step}"), expires_at=1e9)
            repository.delete(f"t{step}")

        assert len(repository._due) <= runtime_repository._DUE_SLACK

    def test_the_heap_is_rebuilt_past_the_bound_and_not_at_it(self):
        """A rebuild makes a new list, so the list being the same one says
        there was none. A small collection never rebuilds."""
        repository = _repository()
        heap = repository._due
        for step in range(runtime_repository._DUE_SLACK):
            repository.create(Thing(f"t{step}"), expires_at=1e9)
            repository.delete(f"t{step}")

        assert repository._due is heap and len(heap) == runtime_repository._DUE_SLACK  # at the bound
        repository.create(Thing("one more"), expires_at=1e9)
        repository.delete("one more")
        assert repository._due is not heap and repository._due == []

    def test_a_rebuilt_heap_is_the_heap_of_the_entries_there_are(self, monkeypatch):
        # So far below zero that every write rebuilds: what is there after
        # one is exactly what a rebuild makes.
        monkeypatch.setattr(runtime_repository, "_DUE_SLACK", -(10**6))
        repository = _repository()
        repository.create(Thing("forever"))
        repository.create(Thing("kept"), expires_at=2000.0)
        held = repository.create_entry(Thing("held"), expires_at=1000.0)
        repository.transact(lambda view: view.hold("held", {"why": "test"}))
        for step in range(20):
            repository.transact(lambda view, step=step: view.set_expires_at("kept", 2000.0 + step))

        kept = repository.entry("kept")
        assert _heap(repository) == [(1000.0, held.instance_id, "held"), (kept.expires_at, kept.instance_id, "kept")]


class TestNothingElseChanged:
    """The repository next to a model that always looks at everything."""

    @pytest.mark.parametrize("slack", [runtime_repository._DUE_SLACK, 3, -(10**6)])
    @pytest.mark.parametrize("seed", range(12))
    def test_every_cleanup_removes_exactly_what_is_due_and_unheld(self, seed, slack, monkeypatch):
        """With the slack of production, with one so small that the heap is
        rebuilt every few writes, and with one that rebuilds it on every
        write: the compaction changes no result."""
        monkeypatch.setattr(runtime_repository, "_DUE_SLACK", slack)
        rng = random.Random(seed)
        repository = _repository()
        model = {}  # name -> [expires_at, hold_id or None]
        now = 1000.0
        names_used = [f"n{index}" for index in range(25)]  # few, so that names come back

        def expiry():
            return rng.choice([None, now - 50, now, now + rng.randint(1, 300), now + rng.randint(1, 300)])

        actions = ["create", "create", "later", "sooner", "never", "delete", "consume", "hold", "release", "raise"]
        actions += ["cleanup", "cleanup", "tick"]
        for step in range(500):
            names = sorted(model)
            action = rng.choice(actions)
            if action == "create":
                name, when = rng.choice(names_used), expiry()
                if name in model:
                    with pytest.raises(RuntimeObjectExists):
                        repository.create(Thing(name), expires_at=when)
                else:
                    repository.create(Thing(name), expires_at=when)
                    model[name] = [when, None]
            elif action in ("later", "sooner", "never") and names:
                name = rng.choice(names)
                old = model[name][0]
                base = old if old is not None else now
                when = {"later": base + rng.randint(1, 200), "sooner": base - rng.randint(1, 200), "never": None}[action]
                repository.transact(lambda view, name=name, when=when: view.set_expires_at(name, when))
                model[name][0] = when
            elif action == "delete" and names:
                name = rng.choice(names)
                repository.delete(name)
                del model[name]
            elif action == "consume" and names:
                name = rng.choice(names)
                assert consume(repository, name) is not None
                del model[name]
            elif action == "hold" and names:
                name = rng.choice(names)
                if model[name][1] is None:
                    held = repository.transact(lambda view, name=name: view.hold(name, {"why": "test"}))
                    model[name][1] = held.hold_id
            elif action == "release" and names:
                name = rng.choice(names)
                if model[name][1] is not None:
                    hold_id = model[name][1]
                    repository.transact(lambda view, name=name, hold_id=hold_id: view.release_hold(name, hold_id))
                    model[name][1] = None
            elif action == "raise":

                def decide(view, moment=now, names=tuple(names)):
                    if "thrown-away" not in names:
                        view.create(Thing("thrown-away"), expires_at=moment - 500)
                    for name in names[:3]:
                        view.set_expires_at(name, moment - 1000)
                    view.delete_expired(moment + 10_000)
                    raise RuntimeError("thrown away")

                with pytest.raises(RuntimeError):
                    repository.transact(decide)
            elif action == "tick":
                now += rng.randint(1, 120)
            elif action == "cleanup":
                due = [name for name, (when, held) in model.items() if when is not None and when < now and held is None]
                assert delete_expired(repository, now) == len(due), (seed, step)
                for name in due:
                    del model[name]

            kept = {
                entry.name: (entry.expires_at, entry.hold.hold_id if entry.hold else None)
                for entry in repository.entries()
            }
            assert kept == {name: tuple(value) for name, value in model.items()}, (seed, step, action)
            # Every entry with a time has its item: nothing that is due can be missed.
            on_the_heap = {(item[1], item[0]) for item in repository._due}
            for entry in repository.entries():
                if entry.expires_at is not None:
                    assert (entry.instance_id, entry.expires_at) in on_the_heap, (seed, step, action, entry.name)

        # And whatever the sequence left, one cleanup far enough takes it.
        left = [name for name, (when, held) in model.items() if when is not None and held is None]
        assert delete_expired(repository, now + 10**6) == len(left)
