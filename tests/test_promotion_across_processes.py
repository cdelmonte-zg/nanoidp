"""A promotion's outcome has a durable owner (#405, step 4 of #404).

Promoting a runtime object is a small saga: claim it, write its entry into
the declared configuration, reload, retire the runtime object and record
that it was promoted. With one process the claim could live in that
process. With two sharing the runtime store it cannot: the process that
knows the claim need not be the one that retires the object, and then the
promotion is recorded as an ordinary removal, or not at all.

Here two nanoidp "processes" share **only the runtime store**: A is the
application, B is a second ``ConfigManager`` on the same directory with a
resolver of its own. They share no promotion state. For as long as that
state was a module global (``identities._promoting``), two resolvers in one
interpreter did share it, so B swaps in marks of its own while it acts;
with the claim kept on the entry there is nothing left to swap, and the
``hasattr`` keeps these tests failing on the old model and guarding against
its return.

Not claimed, and not tested: that a process whose configuration is stale
cannot create a runtime object under a name another has just declared. That
is the freshness of the declared configuration across processes (#354).
"""

import contextlib
import shutil
import threading
from pathlib import Path

import pytest
import yaml

import nanoidp.app as app_module
from nanoidp.app import create_app
from nanoidp.config import ConfigManager, OAuthClient, get_config
from nanoidp.services import identities as identities_module
from nanoidp.services.audit import get_audit_log
from nanoidp.services.identities import IdentityResolver, PromotionInProgress
from nanoidp.services.runtime_repository import MemoryRuntimeRepository, replace
from nanoidp.services.runtime_store import get_runtime_store
from nanoidp.services.yaml_writer import get_yaml_writer

_REPO = Path(__file__).resolve().parent.parent
PROMOTE = "/api/runtime/clients/shared/promote"


class OtherProcess:
    def __init__(self, config_dir):
        self._marks = {}
        with self.acting():
            self.config = ConfigManager(str(config_dir), after_load=app_module._after_load)
        self.resolver = IdentityResolver(self.config, self.config.snapshot, get_runtime_store())

    @contextlib.contextmanager
    def acting(self):
        """Nothing of the first process's but the store."""
        if not hasattr(identities_module, "_promoting"):
            yield
            return
        theirs, identities_module._promoting = identities_module._promoting, self._marks
        try:
            yield
        finally:
            self._marks, identities_module._promoting = identities_module._promoting, theirs


@pytest.fixture
def processes(tmp_path):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    for name in ("settings.yaml", "users.yaml"):
        shutil.copy(_REPO / "config" / name, config_dir / name)
    settings = config_dir / "settings.yaml"
    document = yaml.safe_load(settings.read_text())
    document["jwt"]["keys_dir"] = str(tmp_path / "keys")
    settings.write_text(yaml.safe_dump(document))
    application = create_app(str(config_dir))
    application.config["TESTING"] = True
    created = application.test_client().post(
        "/api/runtime/clients",
        json={
            "client_id": "shared",
            "client_secret": "the-first-process-made-this",
            "redirect_uris": ["http://localhost:1/as-claimed"],
        },
    )
    assert created.status_code == 201
    return application, OtherProcess(config_dir), config_dir


def _once(monkeypatch, method, when, then):
    """Run ``then`` once, right before or right after the first call of
    ``method`` on the runtime clients."""
    original = getattr(MemoryRuntimeRepository, method)
    clients = get_runtime_store().clients
    done = []

    def placed(self, *args, **kwargs):
        mine = self is clients and not done
        if mine:
            done.append(True)
            if when == "before":
                then()
        result = original(self, *args, **kwargs)
        if mine and when == "after":
            then()
        return result

    monkeypatch.setattr(MemoryRuntimeRepository, method, placed)
    return done


def _in_its_own_thread(other, action):
    failures = []

    def run():
        try:
            with other.acting():
                action()
        except BaseException as failure:  # noqa: BLE001 - reported below
            failures.append(failure)

    thread = threading.Thread(target=run)
    thread.start()
    thread.join()
    assert failures == []


def _events(kind):
    return [entry for entry in get_audit_log().get_entries(limit=200) if entry["event_type"] == kind]


def _declared(client_id="shared"):
    return next((c for c in get_config().settings.clients if c.client_id == client_id), None)


@contextlib.contextmanager
def _a_promotion_stopped_at_its_write(application, monkeypatch):
    """The first process promotes ``shared`` and is held at the moment it is
    about to write the file; leaving the block lets it through."""
    writer = get_yaml_writer()
    write = writer.save_client
    writing, release = threading.Event(), threading.Event()

    def held(client, **kwargs):
        writing.set()
        assert release.wait(5)
        return write(client, **kwargs)

    monkeypatch.setattr(writer, "save_client", held)
    outcome = {}
    promoting = threading.Thread(
        target=lambda: outcome.setdefault("status", application.test_client().post(PROMOTE).status_code)
    )
    promoting.start()
    assert writing.wait(5)
    try:
        yield outcome
    finally:
        release.set()
        promoting.join()


class TestTheOtherProcessSeesTheClaim:
    def test_it_cannot_delete_what_is_being_promoted(self, processes, monkeypatch):
        """P1. Refused there as it is here, so it cannot put another object
        under the name for the promotion to retire in its place."""
        application, other, _ = processes

        with _a_promotion_stopped_at_its_write(application, monkeypatch) as promotion:
            with other.acting(), pytest.raises(PromotionInProgress):
                other.resolver.delete_runtime_client("shared")
            with other.acting(), pytest.raises(PromotionInProgress):
                other.resolver.promote_runtime_client("shared", {"endpoint": "/other"})

        assert promotion["status"] == 200
        assert len(_events("runtime_identity_promoted")) == 1
        assert get_runtime_store().clients.get("shared") is None

    def test_two_promotions_that_both_looked_first_are_still_one(self, processes, monkeypatch):
        """Both looked, neither saw a claim, and one claims in between. The
        look is a courtesy, so that a second promotion need not wait to be
        refused; the claim is what decides, and it says the same thing."""
        application, other, _ = processes
        outcome = {}

        def the_first_process_claims():
            stopped = _a_promotion_stopped_at_its_write(application, monkeypatch)
            outcome["first"] = stopped.__enter__()
            outcome["let_through"] = lambda: stopped.__exit__(None, None, None)

        _once(monkeypatch, "entry", "after", the_first_process_claims)

        with other.acting(), pytest.raises(PromotionInProgress):
            other.resolver.promote_runtime_client("shared", {"endpoint": "/other"})
        outcome["let_through"]()

        assert outcome["first"]["status"] == 200
        assert len(_events("runtime_identity_promoted")) == 1

    def test_its_reload_leaves_a_promotion_that_is_still_writing(self, processes, monkeypatch):
        """The name is not declared yet because the entry is not written
        yet. That is a promotion in the middle of its write, not one to
        give up on."""
        application, other, _ = processes

        with _a_promotion_stopped_at_its_write(application, monkeypatch) as promotion:
            with other.acting():
                other.config.reload()
            assert get_runtime_store().clients.entry("shared").hold is not None
            assert _events("runtime_identity_promotion_abandoned") == []

        assert promotion["status"] == 200
        assert len(_events("runtime_identity_promoted")) == 1
        assert _events("runtime_identity_promotion_abandoned") == []

    def test_its_reset_leaves_what_is_being_promoted(self, processes, monkeypatch):
        """P3."""
        application, other, _ = processes
        get_runtime_store().clients.create(
            OAuthClient(client_id="bystander", token_endpoint_auth_method="none")
        )

        with _a_promotion_stopped_at_its_write(application, monkeypatch) as promotion:
            with other.acting():
                users, clients = other.resolver.reset_runtime_identities()
            assert get_runtime_store().clients.get("shared") is not None

        assert clients == 1, "the bystander goes, the claimed client stays"
        assert promotion["status"] == 200
        assert len(_events("runtime_identity_promoted")) == 1
        assert _declared() is not None


class TestWhoeverRetiresItSaysItWasPromoted:
    def test_when_the_other_process_reloads_first(self, processes, monkeypatch):
        """P2. The first process writes the file, and the other loads it
        before the first one's own reload. It used to retire the runtime
        object there and, knowing of no promotion, record a removal, so that
        nothing was ever recorded as promoted. It now sees a claim whose
        entry is being written, which is the writer's to resolve, and the
        writer's own reload retires it: once, as a promotion, with the
        promoting request's context."""
        application, other, _ = processes
        first = get_config()
        reload_local = first.reload_local
        once = []

        def the_other_one_first():
            if not once:
                once.append(True)
                # In a thread of its own, as another process is: the thread
                # that is writing the entry knows the declaration is its
                # own, and nobody else can know it that way.
                _in_its_own_thread(other, other.config.reload)
                # It saw the name declared and a claim still being written,
                # and cannot know the declaration is that claim's: left.
                assert get_runtime_store().clients.entry("shared") is not None
            return reload_local()

        monkeypatch.setattr(first, "reload_local", the_other_one_first)

        assert application.test_client().post(PROMOTE).status_code == 200

        assert once == [True]
        (promoted,) = _events("runtime_identity_promoted")
        assert promoted["endpoint"] == PROMOTE
        assert _events("runtime_identity_removed_on_reload") == []
        assert get_runtime_store().clients.get("shared") is None

    @pytest.mark.parametrize("declared", ["another-value", "the-very-value-that-was-claimed"])
    def test_a_declaration_that_is_somebody_elses_is_not_this_promotion(self, processes, monkeypatch, declared):
        """The object is claimed and its entry not yet written when somebody
        declares a client under the name, and the other process loads that.
        Nothing about what was declared proves who declared it, not even its
        being equal to what was claimed: the writer refuses a name that is
        taken whatever is under it. So a claim whose entry is still being
        written is its writer's to resolve, and the other process leaves it
        alone. The promotion then finds the name taken and answers 409, as
        it always has, with the object left where it was and free again; the
        next load that declares the name removes it, as the collision it is."""
        application, other, config_dir = processes
        settings = config_dir / "settings.yaml"
        entry = {"client_id": "shared", "client_secret": "declared-by-hand", "redirect_uris": ["http://localhost:1/x"]}
        if declared == "the-very-value-that-was-claimed":
            entry = {
                "client_id": "shared",
                "client_secret": "the-first-process-made-this",
                "redirect_uris": ["http://localhost:1/as-claimed"],
            }

        with _a_promotion_stopped_at_its_write(application, monkeypatch) as promotion:
            document = yaml.safe_load(settings.read_text())
            document["oauth"]["clients"].append(entry)
            settings.write_text(yaml.safe_dump(document))
            _in_its_own_thread(other, other.config.reload)
            assert get_runtime_store().clients.entry("shared").hold is not None

        assert promotion["status"] == 409
        assert _events("runtime_identity_promoted") == []
        assert _events("runtime_identity_removed_on_reload") == []
        kept = get_runtime_store().clients.entry("shared")
        assert kept is not None and kept.hold is None

        assert application.test_client().post("/api/config/reload").status_code == 200
        assert _events("runtime_identity_promoted") == []
        assert len(_events("runtime_identity_removed_on_reload")) == 1

    def test_an_entry_that_reached_the_file_is_a_promotion_whatever_it_says_now(self, processes):
        """The reload after the write failed, and the operator who repairs
        the file also edits the entry. It is loaded by whoever loads it, and
        it no longer equals what was claimed. It was written all the same:
        that is what ``written`` records, and it needs no second opinion."""
        application, other, config_dir = processes
        settings = config_dir / "settings.yaml"
        good = settings.read_text()
        document = yaml.safe_load(good)
        document["hooks"] = {"strict": True}
        document["plugins"] = {"no-such-plugin": {}}
        settings.write_text(yaml.safe_dump(document))
        assert application.test_client().post(PROMOTE).status_code == 500
        repaired = _with_the_entry_kept(settings, good)
        next(c for c in repaired["oauth"]["clients"] if c["client_id"] == "shared")["redirect_uris"] = [
            "http://localhost:1/edited-by-hand"
        ]
        settings.write_text(yaml.safe_dump(repaired))

        _in_its_own_thread(other, other.config.reload)

        assert len(_events("runtime_identity_promoted")) == 1
        assert _events("runtime_identity_removed_on_reload") == []

    def test_a_namesake_with_no_claim_is_removed_not_promoted(self, processes):
        """The rule about the name still holds: a runtime object under a
        name the configuration declares goes. What it is called depends on
        the entry that was retired, and this one nobody was promoting."""
        application, other, config_dir = processes
        settings = config_dir / "settings.yaml"
        document = yaml.safe_load(settings.read_text())
        document["oauth"]["clients"].append(
            {"client_id": "shared", "client_secret": "declared-by-hand", "redirect_uris": ["http://localhost:1/x"]}
        )
        settings.write_text(yaml.safe_dump(document))

        with other.acting():
            other.config.reload()
        assert application.test_client().post("/api/config/reload").status_code == 200

        assert len(_events("runtime_identity_removed_on_reload")) == 1
        assert _events("runtime_identity_promoted") == []


class TestAPromotionWritesWhatItClaimed:
    def test_a_change_made_after_the_claim_is_not_what_gets_declared(self, processes, monkeypatch):
        """The claim is of one value. Whoever may change a runtime object is
        the one that has to refuse a claimed one (#402); the repository's
        replace keeps a claim and gives it no meaning, on purpose."""
        application, _, _ = processes

        def changed_right_after_the_claim():
            replace(
                get_runtime_store().clients,
                "shared",
                lambda client: client.model_copy(update={"redirect_uris": ["http://localhost:1/changed-later"]}),
            )

        # After the claim's own change to the entry and before the writer is
        # handed anything: any later and what it was handed is already fixed.
        placed = _once(monkeypatch, "transact", "after", changed_right_after_the_claim)

        assert application.test_client().post(PROMOTE).status_code == 200

        assert placed == [True]
        assert _declared().redirect_uris == ["http://localhost:1/as-claimed"]
        assert len(_events("runtime_identity_promoted")) == 1


def _with_the_entry_kept(settings, good):
    """The repaired settings: ``good`` plus whatever the promotion wrote."""
    written = yaml.safe_load(settings.read_text())["oauth"]["clients"]
    repaired = yaml.safe_load(good)
    repaired["oauth"]["clients"] = written
    return repaired


class TestWhatAClaimDoesNotSay:
    def test_a_promotion_cut_short_has_written_nothing_that_anyone_knows_of(self, processes, monkeypatch):
        """The request is torn down inside the writer, here before anything
        was written. ``written`` means "the entry reached the file", and
        nobody knows that, so the claim stays as it was: ``writing``. When
        somebody then declares the name, the load that sees it must not
        call that a promotion, which it would if the uncertainty had been
        recorded as the very state that denies it.

        The price is a claim nothing in this process resolves: the object
        is refused until the process goes, which takes the claim with it.
        With a store that outlives the process that is the recovery #354
        owes, and it looks at the declared configuration first."""
        application, _, config_dir = processes
        writer = get_yaml_writer()

        def torn_down(client, **kwargs):
            raise SystemExit("the worker is going away")

        monkeypatch.setattr(writer, "save_client", torn_down)
        resolver = IdentityResolver(get_config(), get_config().snapshot, get_runtime_store())
        with pytest.raises(SystemExit):
            resolver.promote_runtime_client("shared", {"endpoint": PROMOTE})
        monkeypatch.undo()

        settings = config_dir / "settings.yaml"
        document = yaml.safe_load(settings.read_text())
        document["oauth"]["clients"].append(
            {"client_id": "shared", "client_secret": "declared-by-hand", "redirect_uris": ["http://localhost:1/x"]}
        )
        settings.write_text(yaml.safe_dump(document))
        assert application.test_client().post("/api/config/reload").status_code == 200

        assert _events("runtime_identity_promoted") == []
        assert _events("runtime_identity_promotion_abandoned") == []
        held = get_runtime_store().clients.entry("shared")
        assert held is not None and held.hold.payload["promotion"]["state"] == "writing"
        assert application.test_client().delete("/api/runtime/clients/shared").status_code == 409

    def test_a_hold_this_module_does_not_understand_is_not_a_promotion(self, processes):
        """Whatever put it there. The object under a declared name still
        goes, and the load that retires it must not fail after having
        removed it."""
        application, _, config_dir = processes
        get_runtime_store().clients.transact(lambda view: view.hold("shared", {"promotion": {}}))
        settings = config_dir / "settings.yaml"
        document = yaml.safe_load(settings.read_text())
        document["oauth"]["clients"].append(
            {"client_id": "shared", "client_secret": "declared-by-hand", "redirect_uris": ["http://localhost:1/x"]}
        )
        settings.write_text(yaml.safe_dump(document))

        assert application.test_client().post("/api/config/reload").status_code == 200

        assert get_runtime_store().clients.get("shared") is None
        assert len(_events("runtime_identity_removed_on_reload")) == 1
        assert _events("runtime_identity_promoted") == []


class TestAnAbandonedPromotionIsSaidOnce:
    def _written_then_reverted(self, application, config_dir):
        """A promotion whose entry reached the file and whose reload failed,
        after which the operator repairs the file and takes the entry out."""
        settings = config_dir / "settings.yaml"
        good = settings.read_text()
        document = yaml.safe_load(good)
        document["hooks"] = {"strict": True}
        document["plugins"] = {"no-such-plugin": {}}
        settings.write_text(yaml.safe_dump(document))
        assert application.test_client().post(PROMOTE).status_code == 500
        settings.write_text(good)

    def test_when_both_processes_have_seen_it(self, processes, monkeypatch):
        """Both list the runtime clients and see a promotion to give up on.
        One releases the claim. The other saw the same thing a moment ago,
        and what it saw is not what lets it say so."""
        application, other, config_dir = processes
        self._written_then_reverted(application, config_dir)

        def this_process_gets_there_first():
            assert application.test_client().post("/api/config/reload").status_code == 200

        placed = _once(monkeypatch, "entries", "after", this_process_gets_there_first)
        with other.acting():
            other.config.reload()

        assert placed == [True]
        assert len(_events("runtime_identity_promotion_abandoned")) == 1
        assert get_runtime_store().clients.entry("shared").hold is None

    def test_not_by_a_process_that_read_the_files_before_the_entry_was_written(self, processes, monkeypatch):
        """The other process read the files, then the promotion wrote its
        entry and lost its reload. What the other process loaded cannot say
        whether the entry is declared: it is older than the entry. It leaves
        the claim alone, and the next load that can tell says promoted."""
        application, other, config_dir = processes
        settings = config_dir / "settings.yaml"
        good = settings.read_text()
        after_load = other.config._after_load
        late = []

        def the_promotion_lands_first(config):
            if not late:
                late.append(True)
                document = yaml.safe_load(good)
                document["hooks"] = {"strict": True}
                document["plugins"] = {"no-such-plugin": {}}
                settings.write_text(yaml.safe_dump(document))
                assert application.test_client().post(PROMOTE).status_code == 500
                settings.write_text(yaml.safe_dump(_with_the_entry_kept(settings, good)))
            return after_load(config)

        monkeypatch.setattr(other.config, "_after_load", the_promotion_lands_first)
        with other.acting():
            other.config.reload()

        assert late == [True]
        assert _events("runtime_identity_promotion_abandoned") == []
        assert get_runtime_store().clients.entry("shared").hold is not None

        assert application.test_client().post("/api/config/reload").status_code == 200
        assert len(_events("runtime_identity_promoted")) == 1
        assert _events("runtime_identity_promotion_abandoned") == []

    @pytest.mark.parametrize("first_to_load", ["this", "other"])
    def test_whichever_process_loads_first(self, processes, first_to_load):
        application, other, config_dir = processes
        self._written_then_reverted(application, config_dir)
        assert application.test_client().delete("/api/runtime/clients/shared").status_code == 409

        def this():
            assert application.test_client().post("/api/config/reload").status_code == 200

        def that():
            with other.acting():
                other.config.reload()

        for load in (this, that) if first_to_load == "this" else (that, this):
            load()

        assert len(_events("runtime_identity_promotion_abandoned")) == 1
        assert _events("runtime_identity_promoted") == []
        assert get_runtime_store().clients.get("shared") is not None
        assert application.test_client().delete("/api/runtime/clients/shared").status_code == 200
