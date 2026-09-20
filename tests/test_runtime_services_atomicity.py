"""The services that compose operations on a runtime repository, against
themselves (#404 step 2): authorization transactions, pending second factors
and the client metadata cache.

Each of them used to make its operations whole with a lock of its own. They
are now decisions of the repository's, so that the guarantee holds for
whoever shares the store and not only for the threads of one process. These
tests state what the lock gave, at each service's own entry points: one
winner, a cap that holds, the later of two promises kept.

Threads of one interpreter hardly ever interleave inside a few bytecodes, so
the tests would pass with no atomicity at all. ``interleaved`` makes every
read of a repository give way, inside a decision and outside one: an
operation that reads and then acts in two visits lets the others in between,
every time, and one that is a single decision does not.
"""

import dataclasses
import threading
import time

import pytest

from nanoidp.config import OAuthClient
from nanoidp.services import authorization_transactions as transactions_module
from nanoidp.services import client_metadata as cimd
from nanoidp.services import pending_second_factors as second_factors_module
from nanoidp.services import runtime_repository
from nanoidp.services.auth_code import get_auth_code_store
from nanoidp.services.authorization_transactions import (
    AuthorizationParameters,
    TransactionState,
    TransactionStoreFull,
    get_authorization_transaction_store,
)
from nanoidp.services.device_code import (
    DeviceCodeStoreFull,
    DevicePollOutcome,
    DeviceVerifyOutcome,
    get_device_code_store,
)
from nanoidp.services.pending_second_factors import (
    PendingSecondFactorStoreFull,
    get_pending_second_factor_store,
)

THREADS = 8
CAP = 5


@pytest.fixture
def interleaved(monkeypatch):
    def giving_way(read):
        def reading(self, *args, **kwargs):
            result = read(self, *args, **kwargs)
            time.sleep(0.002)
            return result

        return reading

    for owner in (runtime_repository.MemoryRuntimeRepository, runtime_repository._MemoryTransaction):
        for method in ("entry", "entries"):
            monkeypatch.setattr(owner, method, giving_way(getattr(owner, method)))
    # And after a delete on the repository: a change made as a delete and a
    # create leaves the object absent between the two.
    repository = runtime_repository.MemoryRuntimeRepository
    monkeypatch.setattr(repository, "delete", giving_way(repository.delete))
    # And after every decision, once its lock is released: an operation made
    # of two decisions has no read between them to give way at, and whether
    # another thread gets in there would be the scheduler's to say. (A
    # mutant of exactly that shape was killed twice and survived once.)
    monkeypatch.setattr(repository, "transact", giving_way(repository.transact))


def _while_the_store_is_busy(seconds, work):
    """Run ``work`` so that it has to wait ``seconds`` for the repository: a
    backend that retries on busy can keep a caller waiting that long."""
    from nanoidp.services.runtime_identities import PydanticCodec, get_runtime_identity_store

    busy = get_runtime_identity_store().repository(
        "kept-busy", lambda client: client.client_id, PydanticCodec(OAuthClient)
    )
    holding = threading.Event()

    def hold(view):
        holding.set()
        time.sleep(seconds)

    holder = threading.Thread(target=lambda: busy.transact(hold))
    holder.start()
    assert holding.wait(5)
    result = work()
    holder.join()
    return result


def _race(work):
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


def _transaction(store, binding="browser-a"):
    return store.create(
        browser_binding=binding,
        params=AuthorizationParameters(
            response_type="code",
            client_id="demo-client",
            redirect_uri="http://localhost:3000/callback",
            scope="openid",
            state="",
            code_challenge="",
            code_challenge_method="",
            nonce="",
            claims="",
            resources=[],
        ),
        requested={"client_id": ["demo-client"]},
        client=OAuthClient(client_id="demo-client", client_secret="demo-secret"),
        client_origin="declared",
    )


def _second_factor(store, binding="browser-a"):
    return store.create(
        browser_binding=binding,
        purpose="login",
        context={"next": "/"},
        username="admin",
        amr=["pwd"],
    )


def _cached(url):
    return OAuthClient(
        client_id=url,
        token_endpoint_auth_method="none",
        redirect_uris=["http://localhost:3000/callback"],
    )


class TestExpiryIsJudgedWhenTheDecisionIsMade:
    """Not when the caller started waiting for the store. A record that
    expires during the wait is expired: a clock read before the wait would
    issue a code, or complete a second factor, past ``expires_at``."""

    def test_an_authorization_transaction(self, monkeypatch):
        monkeypatch.setattr(transactions_module, "TRANSACTION_LIFETIME_SECONDS", 0.3)
        store = get_authorization_transaction_store()
        consumed = _transaction(store)
        marked = _transaction(store)
        reset = _transaction(store)
        store.mark_primary_verified(reset.id, "browser-a", username="admin", amr=["pwd"])

        outcomes = _while_the_store_is_busy(
            0.6,
            lambda: (
                store.consume(consumed.id, "browser-a"),
                store.mark_primary_verified(marked.id, "browser-a", username="admin", amr=["pwd"]),
                store.reset_login(reset.id, "browser-a"),
            ),
        )

        assert outcomes == (None, None, None)

    @pytest.mark.parametrize("operation", ["consume"])
    def test_a_pending_second_factor(self, monkeypatch, operation):
        monkeypatch.setattr(second_factors_module, "PENDING_SECOND_FACTOR_LIFETIME_SECONDS", 0.3)
        store = get_pending_second_factor_store()
        record = _second_factor(store)

        taken = _while_the_store_is_busy(
            0.6,
            lambda: store.consume(record.id, "browser-a", purpose="login", context={"next": "/"}),
        )

        assert taken is None


@pytest.mark.usefixtures("interleaved")
class TestAuthorizationTransactions:
    def test_a_transaction_in_transition_is_never_read_as_gone(self):
        """A transition changes a record in place. Made as a delete and a
        create, it leaves a live transaction absent in between, and a read
        landing there tells a user in the middle of a login that the login
        does not exist."""
        store = get_authorization_transaction_store()
        transaction = _transaction(store)
        stop = threading.Event()
        gone = []

        def read():
            while not stop.is_set():
                if store.get_bound(transaction.id, "browser-a") is None:
                    gone.append(True)
                if store.find_unique_for_binding("browser-a").transaction is None:
                    gone.append(True)

        readers = [threading.Thread(target=read) for _ in range(2)]
        for reader in readers:
            reader.start()
        try:
            for _ in range(15):
                store.mark_primary_verified(transaction.id, "browser-a", username="admin", amr=["pwd"])
                store.reset_login(transaction.id, "browser-a")
        finally:
            stop.set()
            for reader in readers:
                reader.join()

        assert gone == []

    def test_a_transaction_is_consumed_once(self):
        store = get_authorization_transaction_store()
        transaction = _transaction(store)
        winners = []

        def work(index):
            if store.consume(transaction.id, "browser-a") is not None:
                winners.append(index)

        _race(work)

        assert len(winners) == 1

    def test_one_password_is_recorded(self):
        """Two submissions on one transaction: one is recorded, the other
        is told the transaction is no longer pending, and what is stored is
        the winner's, whole."""
        store = get_authorization_transaction_store()
        transaction = _transaction(store)
        recorded = []

        def work(index):
            if store.mark_primary_verified(
                transaction.id, "browser-a", username=f"user-{index}", amr=["pwd"]
            ):
                recorded.append(f"user-{index}")

        _race(work)

        assert len(recorded) == 1
        stored = store.get_bound(transaction.id, "browser-a")
        assert stored.state is TransactionState.PRIMARY_VERIFIED
        assert stored.primary_username == recorded[0]

    def test_a_code_is_never_issued_on_a_password_that_was_taken_back(self):
        """A completion resting on a verified password races a "Change
        username": whichever is first, the two never both succeed in a way
        that issues a code for a login that was reset."""
        for _ in range(5):
            store = get_authorization_transaction_store()
            transaction = _transaction(store)
            store.mark_primary_verified(transaction.id, "browser-a", username="admin", amr=["pwd"])
            outcome = {}

            def work(index, transaction=transaction, outcome=outcome, store=store):
                if index == 0:
                    outcome["consumed"] = store.consume(
                        transaction.id, "browser-a", verified_username="admin"
                    )
                elif index == 1:
                    outcome["reset"] = store.reset_login(transaction.id, "browser-a")

            _race(work)

            # One of them came first. If the completion did, the reset found
            # nothing; if the reset did, the completion found no verified
            # password. Both succeeding is a code for a login taken back.
            assert (outcome["consumed"] is None) != (outcome["reset"] is None)
            if outcome["consumed"] is None:
                assert store.get_bound(transaction.id, "browser-a").state is TransactionState.PENDING

    def test_the_cap_holds(self, monkeypatch):
        monkeypatch.setattr(transactions_module, "MAX_PENDING_TRANSACTIONS", CAP)
        store = get_authorization_transaction_store()
        accepted = []

        def work(index):
            for _ in range(3):
                try:
                    _transaction(store, binding=f"browser-{index}")
                    accepted.append(True)
                except TransactionStoreFull:
                    pass

        _race(work)

        assert len(accepted) == CAP
        assert len(store._repository.list()) == CAP


@pytest.mark.usefixtures("interleaved")
class TestAuthorizationCodes:
    """#363 step 2. The code store made its operations whole with a lock of
    its own; they are decisions of the repository's now."""

    REDIRECT = "http://localhost:3000/callback"

    def _code(self, store, **extra):
        return store.create_code(client_id="demo-client", redirect_uri=self.REDIRECT, username="alice", **extra)

    def test_a_code_is_redeemed_once(self):
        store = get_auth_code_store()
        code = self._code(store)
        redeemed = []

        def work(index):
            if store.consume_code(code, "demo-client", self.REDIRECT) is not None:
                redeemed.append(index)

        _race(work)

        assert len(redeemed) == 1

    def test_a_second_redemption_takes_the_code_away(self):
        store = get_auth_code_store()
        code = self._code(store)

        assert store.consume_code(code, "demo-client", self.REDIRECT).used is True
        assert store.get_code_info(code).used is True
        assert store.consume_code(code, "demo-client", self.REDIRECT) is None
        assert store.get_code_info(code) is None

    def test_a_used_code_goes_whoever_presents_it_again(self):
        """Used is looked at before anything about the request: a second
        presentation is the sign that a code leaked, and it is taken away
        even when the one presenting it is not the client it was for."""
        store = get_auth_code_store()
        code = self._code(store)
        store.consume_code(code, "demo-client", self.REDIRECT)

        assert store.consume_code(code, "another-client", self.REDIRECT) is None
        assert store.get_code_info(code) is None

    @pytest.mark.parametrize(
        "wrong",
        [
            {"client_id": "another-client"},
            {"redirect_uri": "http://localhost:3000/elsewhere"},
            {"code_verifier": "not-the-verifier"},
            {"code_verifier": None},
        ],
        ids=["client", "redirect", "pkce", "no-verifier"],
    )
    def test_a_mismatch_does_not_burn_the_code(self, wrong):
        store = get_auth_code_store()
        code = self._code(store, code_challenge="the-verifier", code_challenge_method="plain")
        attempt = {"client_id": "demo-client", "redirect_uri": self.REDIRECT, "code_verifier": "the-verifier"}

        assert store.consume_code(code, **{**attempt, **wrong}) is None
        assert store.get_code_info(code).used is False
        assert store.consume_code(code, **attempt) is not None

    def test_what_is_read_is_a_copy(self):
        """get_code_info handed out the stored object itself. It is a read,
        and reads of a runtime repository are by value."""
        store = get_auth_code_store()
        code = self._code(store, resource=["https://api.example/v1"], claims={"id_token": ["email"]})

        looked = store.get_code_info(code)
        looked.used = True
        looked.resource.append("https://evil.example")
        looked.claims["id_token"].append("phone")

        again = store.get_code_info(code)
        assert again.used is False
        assert again.resource == ["https://api.example/v1"]
        assert again.claims == {"id_token": ["email"]}

    def test_how_the_login_authenticated_comes_back_as_it_went_in(self):
        """A tuple, and datetimes: what JSON has no type for must survive
        being written down, which the suite's codec check enforces on every
        code any test creates."""
        store = get_auth_code_store()
        code = self._code(store, amr=("pwd", "otp"))

        redeemed = store.consume_code(code, "demo-client", self.REDIRECT)

        assert redeemed.amr == ("pwd", "otp")
        assert redeemed.expires_at > redeemed.created_at
        assert redeemed.expires_at.tzinfo is not None

    def test_a_list_of_methods_is_kept_as_the_tuple_it_means(self):
        """Callers pass either. Kept as one thing, so that what is written
        down reads back equal to what was stored, whichever it was."""
        store = get_auth_code_store()
        code = self._code(store, amr=["pwd"])

        assert store.get_code_info(code).amr == ("pwd",)

    def test_a_code_is_written_down_as_plain_json(self):
        """What the codec writes is JSON as it stands, not something
        ``json.dumps`` happens to accept and change on the way (a tuple
        goes in and a list comes out): a backend may keep what it is given
        without a round trip through text."""
        import json

        from nanoidp.services.auth_code import AuthorizationCodeCodec

        store = get_auth_code_store()
        code = self._code(store, amr=("pwd", "otp"), resource=["https://api.example/v1"])
        written = AuthorizationCodeCodec().dump(store.get_code_info(code))

        assert json.loads(json.dumps(written)) == written

    def test_a_string_is_not_a_list_of_methods(self):
        """``tuple("pwd")`` is three characters. The choke point that mints
        the token drops a value that is not a list or a tuple, and says so;
        a code must hand it what it was given, not something that now
        passes for a list."""
        store = get_auth_code_store()
        code = self._code(store, amr="pwd")

        assert store.consume_code(code, "demo-client", self.REDIRECT).amr == "pwd"

    def test_the_shape_of_a_code_is_the_codes_own_rule(self):
        """Wherever a code comes from, not only ``create_code``: the methods
        are a tuple and the resources a list, or what a backend writes down
        would not read back equal."""
        from nanoidp.services.auth_code import AuthorizationCode

        made = AuthorizationCode(
            code="c", client_id="x", redirect_uri=self.REDIRECT, scope="openid", username="alice",
            amr=["pwd", "otp"], resource=("https://api.example/v1",),
        )

        assert made.amr == ("pwd", "otp")
        assert made.resource == ["https://api.example/v1"]
        assert dataclasses.replace(made, amr=["pwd"]).amr == ("pwd",)

    @pytest.mark.parametrize(
        ("method", "verifier"),
        [("S512", "anything"), ("S256", "non-ascii-\u00e9")],
        ids=["unknown-method", "non-ascii-verifier"],
    )
    def test_a_verifier_that_cannot_be_checked_is_a_refusal_not_an_error(self, method, verifier, caplog):
        """Inside the decision nothing logs and nothing raises: an unknown
        method used to log from in there, once per run of the decision, and
        a verifier that is not ASCII raised out of it as a 500."""
        import logging

        store = get_auth_code_store()
        code = self._code(store, code_challenge="a-challenge", code_challenge_method=method)

        with caplog.at_level(logging.WARNING, logger="nanoidp.services.auth_code"):
            refused = store.consume_code(code, "demo-client", self.REDIRECT, code_verifier=verifier)

        assert refused is None
        assert store.get_code_info(code).used is False
        assert len(caplog.records) == 1

    def test_an_expired_code_is_refused_and_removed(self, monkeypatch):
        from nanoidp.services import auth_code as auth_code_module

        monkeypatch.setattr(auth_code_module, "CODE_LIFETIME_SECONDS", -1)
        store = get_auth_code_store()
        code = self._code(store)

        assert store.consume_code(code, "demo-client", self.REDIRECT) is None
        assert store.get_code_info(code) is None

    def test_creating_a_code_drops_the_ones_past_their_time(self, monkeypatch):
        from nanoidp.services import auth_code as auth_code_module

        store = get_auth_code_store()
        monkeypatch.setattr(auth_code_module, "CODE_LIFETIME_SECONDS", -1)
        stale = self._code(store)
        monkeypatch.undo()

        fresh = self._code(store)

        assert store.get_code_info(stale) is None
        assert store.get_code_info(fresh) is not None

    def test_two_views_are_one_store(self):
        """There is no store object to be the same one: the state is the
        runtime store's, and every view of it sees the same codes."""
        code = self._code(get_auth_code_store())

        assert get_auth_code_store().get_code_info(code) is not None


def _alice(name="alice"):
    from nanoidp.config import User

    return User(username=name, password="pw")


@pytest.mark.usefixtures("interleaved")
class TestDeviceCodes:
    """#363 step 3. Two keys for one grant (the device's code and the user's
    code), and a poll that needs the user: a grant repository, an index
    repository that names the grant's instance, and no lock around the two."""

    def _authorized(self, store, username="alice"):
        device_code, user_code = store.create("demo-client", "openid")
        outcome, _ = store.verify(user_code, "approve", _alice(username), amr=["pwd"])
        assert outcome is DeviceVerifyOutcome.AUTHORIZED
        return device_code, user_code

    def test_an_authorized_grant_is_claimed_once(self):
        store = get_device_code_store()
        device_code, _ = self._authorized(store)
        claimed = []

        def work(index):
            outcome, user, grant = store.poll(device_code, "demo-client", _alice)
            if outcome is DevicePollOutcome.AUTHORIZED:
                claimed.append((user.username, grant.username, grant.amr))

        _race(work)

        assert claimed == [("alice", "alice", ("pwd",))]
        assert store.poll(device_code, "demo-client", _alice)[0] is DevicePollOutcome.NOT_FOUND
        assert store._index.list() == [], "the user code outlived the grant it was for"

    def test_a_pending_code_is_authorized_once(self):
        store = get_device_code_store()
        _, user_code = store.create("demo-client", "openid")
        outcomes = []

        def work(index):
            outcomes.append(store.verify(user_code, "approve", _alice(), amr=("pwd",))[0])

        _race(work)

        assert outcomes.count(DeviceVerifyOutcome.AUTHORIZED) == 1
        assert outcomes.count(DeviceVerifyOutcome.ALREADY_USED) == THREADS - 1

    def test_the_user_is_looked_up_outside_the_decision(self):
        """A decision reaches no other repository (#404), and looking a user
        up reaches the runtime users. It used to happen under the store's
        own lock, where nothing minded."""
        from nanoidp.services.runtime_identities import get_runtime_identity_store

        store = get_device_code_store()
        device_code, _ = self._authorized(store)
        users = get_runtime_identity_store().users
        users.create(_alice())

        outcome, user, _ = store.poll(device_code, "demo-client", users.get)

        assert outcome is DevicePollOutcome.AUTHORIZED
        assert user.username == "alice"

    def test_a_grant_that_changed_under_the_poll_is_looked_at_again(self, monkeypatch):
        """Between seeing the grant authorized and claiming it the user is
        looked up, outside any decision. If by then the device code names
        another grant, authorized for somebody else, the poll must not
        claim that one as if it were the one it saw: it is answered for the
        grant that is there, with the user that grant names."""
        from nanoidp.services import device_code as device_code_module

        store = get_device_code_store()
        device_code, _ = self._authorized(store, "alice")
        swapped = []

        def get_user(name):
            if not swapped:
                swapped.append(name)
                store._grants.delete(device_code)
                monkeypatch.setattr(device_code_module.secrets, "token_urlsafe", lambda n: device_code)
                successor, user_code = store.create("demo-client", "openid")
                assert successor == device_code
                assert store.verify(user_code, "approve", _alice("bob"))[0] is DeviceVerifyOutcome.AUTHORIZED
            return _alice(name)

        outcome, user, grant = store.poll(device_code, "demo-client", get_user)

        assert swapped == ["alice"]
        assert outcome is DevicePollOutcome.AUTHORIZED
        assert (user.username, grant.username) == ("bob", "bob")

    def test_a_grant_that_ran_out_under_the_poll_is_not_claimed(self):
        store = get_device_code_store()
        device_code, _ = self._authorized(store)

        def get_user(name):
            runtime_repository.replace(
                store._grants, device_code, lambda grant: dataclasses.replace(grant, expires_at=time.time() - 1)
            )
            return _alice(name)

        assert store.poll(device_code, "demo-client", get_user)[0] is DevicePollOutcome.EXPIRED

    def test_a_pair_whose_grant_vanished_is_not_handed_out(self, monkeypatch):
        """The grant is there, its index entry is there, and before create
        looks back the grant is gone (a reset, another process). What comes
        back is a pair that exists, and the index entry of the one that does
        not went with it."""
        store = get_device_code_store()
        indexed = type(store)._index_for
        vanished = []

        def then_the_grant_goes(self, grant, expires_at):
            made = indexed(self, grant, expires_at)
            if not vanished:
                vanished.append(grant.value.user_code)
                self._grants.delete(grant.name)
            return made

        monkeypatch.setattr(type(store), "_index_for", then_the_grant_goes)

        device_code, user_code = store.create("demo-client", "openid")

        assert user_code != vanished[0]
        assert store.pending_status(user_code) is None
        assert [entry.user_code for entry in store._index.list()] == [user_code]
        assert [grant.device_code for grant in store._grants.list()] == [device_code]

    def test_a_user_code_checked_a_moment_ago_does_not_approve_a_successor(self, monkeypatch):
        """The user code was looked up and found its grant; before the
        decision the device code came to name another grant. The decision is
        on the instance the index named, so the successor is left alone."""
        from nanoidp.services import device_code as device_code_module

        store = get_device_code_store()
        device_code, old_user_code = store.create("demo-client", "openid")
        looked_up = type(store)._grant_for
        successors = []

        def then_the_device_code_changes_hands(self, user_code):
            found = looked_up(self, user_code)
            if not successors and user_code == old_user_code:
                self._grants.delete(device_code)
                monkeypatch.setattr(device_code_module.secrets, "token_urlsafe", lambda n: device_code)
                successors.append(self.create("demo-client", "openid")[1])
            return found

        monkeypatch.setattr(type(store), "_grant_for", then_the_device_code_changes_hands)

        assert store.verify(old_user_code, "approve", _alice())[0] is DeviceVerifyOutcome.INVALID_CODE
        assert store.pending_status(successors[0]) is None

    def test_an_approval_needs_a_user(self):
        store = get_device_code_store()
        _, user_code = store.create("demo-client", "openid")

        assert store.verify(user_code, "approve", None) == (DeviceVerifyOutcome.INVALID_CREDENTIALS, None)
        assert store.pending_status(user_code) is None

    def test_a_poll_marks_what_it_found_expired(self):
        store = get_device_code_store()
        device_code, user_code = store.create("demo-client", "openid", expires_in=-1)

        assert store.poll(device_code, "demo-client", _alice)[0] is DevicePollOutcome.EXPIRED
        assert store.pending_status(user_code) is DeviceVerifyOutcome.ALREADY_USED

    def test_a_user_who_is_gone_does_not_cost_the_grant(self):
        store = get_device_code_store()
        device_code, _ = self._authorized(store)

        assert store.poll(device_code, "demo-client", lambda name: None)[0] is DevicePollOutcome.USER_NOT_FOUND
        assert store.poll(device_code, "demo-client", _alice)[0] is DevicePollOutcome.AUTHORIZED

    def test_a_grant_past_its_time_says_expired_for_as_long_as_it_is_there(self, monkeypatch):
        """RFC 8628 has an error of its own for it. The store is told when
        the grant becomes removable, and until a cleanup takes it the grant
        answers for itself, to the device and to the user alike."""
        from nanoidp.services import device_code as device_code_module

        store = get_device_code_store()
        device_code, user_code = store.create("demo-client", "openid", expires_in=-1)

        assert store.pending_status(user_code) is DeviceVerifyOutcome.EXPIRED
        assert store.verify(user_code, "approve", _alice())[0] is DeviceVerifyOutcome.EXPIRED
        assert store.poll(device_code, "demo-client", _alice)[0] is DevicePollOutcome.EXPIRED
        assert store.poll(device_code, "another-client", _alice)[0] is DevicePollOutcome.WRONG_CLIENT
        # Once somebody has found it expired it is marked so, and from then
        # on the user's side calls it used, as it calls everything that is
        # no longer pending: the status is looked at before the time.
        assert store.pending_status(user_code) is DeviceVerifyOutcome.ALREADY_USED

        _, fresh = store.create("demo-client", "openid")  # the cleanup on the way in
        assert store.poll(device_code, "demo-client", _alice)[0] is DevicePollOutcome.NOT_FOUND
        assert store.pending_status(user_code) is DeviceVerifyOutcome.INVALID_CODE
        assert [entry.user_code for entry in store._index.list()] == [fresh]
        del device_code_module

    def test_a_user_code_that_is_taken_is_not_given_out_again(self, monkeypatch):
        """It used to be: the second grant silently took the user code over,
        and the first device's user was left approving somebody else's
        device. Eight characters of thirty-one make that unlikely, not
        impossible, and with several processes on one store it has to be a
        refusal the store makes."""
        from nanoidp.services import device_code as device_code_module

        store = get_device_code_store()
        wanted = iter("AAAAAAAA" + "AAAAAAAA" + "BBBBBBBB")
        real_choice = device_code_module.secrets.choice
        monkeypatch.setattr(device_code_module.secrets, "choice", lambda alphabet: next(wanted, None) or real_choice(alphabet))

        first_device, first_user = store.create("demo-client", "openid")
        second_device, second_user = store.create("demo-client", "openid")

        assert (first_user, second_user) == ("AAAAAAAA", "BBBBBBBB")
        assert len(store._grants.list()) == 2, "the grant whose user code was taken was left behind"
        assert store.verify(first_user, "approve", _alice())[0] is DeviceVerifyOutcome.AUTHORIZED
        assert store.poll(first_device, "demo-client", _alice)[0] is DevicePollOutcome.AUTHORIZED
        assert store.poll(second_device, "demo-client", _alice)[0] is DevicePollOutcome.PENDING

    def test_a_user_code_whose_grant_is_gone_opens_nothing(self, monkeypatch):
        """Not even a grant made later under the same device code: the
        index names the instance it was made for."""
        from nanoidp.services import device_code as device_code_module

        store = get_device_code_store()
        device_code, old_user_code = store.create("demo-client", "openid")
        store._grants.delete(device_code)

        assert store.pending_status(old_user_code) is DeviceVerifyOutcome.INVALID_CODE
        monkeypatch.setattr(device_code_module.secrets, "token_urlsafe", lambda n: device_code)
        successor, new_user_code = store.create("demo-client", "openid")
        assert successor == device_code

        assert store.verify(old_user_code, "approve", _alice())[0] is DeviceVerifyOutcome.INVALID_CODE
        assert store.pending_status(new_user_code) is None

    def test_the_cap_holds_and_leaves_no_half_made_pair(self, monkeypatch):
        from nanoidp.services import device_code as device_code_module

        monkeypatch.setattr(device_code_module, "MAX_PENDING_DEVICE_CODES", CAP)
        store = get_device_code_store()
        made = []

        def work(index):
            for _ in range(3):
                try:
                    made.append(store.create("demo-client", "openid"))
                except DeviceCodeStoreFull:
                    pass

        _race(work)

        assert len(made) == CAP
        assert len(store._grants.list()) == CAP
        assert sorted(entry.device_code for entry in store._index.list()) == sorted(d for d, _ in made)
        for _, user_code in made:
            assert store.pending_status(user_code) is None


@pytest.mark.usefixtures("interleaved")
class TestPendingSecondFactors:
    @pytest.mark.parametrize("operation", ["consume", "discard"])
    def test_a_record_is_taken_once(self, operation):
        store = get_pending_second_factor_store()
        record = _second_factor(store)
        winners = []

        def work(index):
            take = getattr(store, operation)
            if take(record.id, "browser-a", purpose="login", context={"next": "/"}) is not None:
                winners.append(index)

        _race(work)

        assert len(winners) == 1

    def test_the_cap_holds(self, monkeypatch):
        monkeypatch.setattr(second_factors_module, "MAX_PENDING_SECOND_FACTORS", CAP)
        store = get_pending_second_factor_store()
        accepted = []

        def work(index):
            for _ in range(3):
                try:
                    _second_factor(store, binding=f"browser-{index}")
                    accepted.append(True)
                except PendingSecondFactorStoreFull:
                    pass

        _race(work)

        assert len(accepted) == CAP
        assert len(store._repository.list()) == CAP


@pytest.mark.usefixtures("interleaved")
class TestClientMetadataCache:
    def test_the_cache_never_grows_past_its_cap(self, monkeypatch):
        monkeypatch.setattr(cimd, "MAX_CACHED_DOCUMENTS", CAP)
        most = []

        def work(index):
            for attempt in range(3):
                cimd.remember(_cached(f"https://client.example/{index}-{attempt}.json"), None)
                most.append(len(cimd.cache().list()))

        _race(work)

        assert max(most) <= CAP
        assert len(cimd.cache().list()) == CAP

    def test_one_document_fetched_by_several_is_remembered_without_a_collision(self):
        url = "https://client.example/metadata.json"

        _race(lambda index: cimd.remember(_cached(url), None))

        assert [entry.client_id for entry in cimd.cache().list()] == [url]

    def test_the_later_of_two_promises_is_kept(self):
        """Two codes issued against one cached client: the entry must
        outlive both, whichever is recorded last."""
        url = "https://client.example/metadata.json"
        cimd.remember(_cached(url), None)
        soon = time.time() + 100

        _race(lambda index: cimd.retain_until(url, soon + index))

        assert cimd.cache().get(url).protected_until == soon + THREADS - 1

    def test_a_promise_survives_a_document_fetched_again(self):
        url = "https://client.example/metadata.json"
        cimd.remember(_cached(url), None)
        until = time.time() + 100

        def work(index):
            if index % 2:
                cimd.retain_until(url, until)
            else:
                cimd.remember(_cached(url), None)

        _race(work)

        assert cimd.cache().get(url).protected_until == until
        # And in the order that decides it, which the race only sometimes
        # takes: the promise first, the document fetched again after.
        cimd.remember(_cached(url), None)
        assert cimd.cache().get(url).protected_until == until

    def test_an_expired_document_is_dropped_but_not_the_fresh_one_that_replaced_it(self):
        url = "https://client.example/metadata.json"
        for _ in range(5):
            cimd.forget_all()
            cimd.remember(_cached(url), None)
            runtime_repository.replace(
                cimd.cache(),
                url,
                lambda current: current.model_copy(update={"expires_at": time.time() - 1}),
            )
            seen = []

            def work(index, seen=seen):
                if index == 0:
                    cimd.remember(_cached(url), None)
                else:
                    seen.append(cimd.cached_client(url))

            _race(work)

            assert cimd.cached_client(url) is not None, "the fresh document was dropped with the expired one"
