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

import threading
import time

import pytest

from nanoidp.config import OAuthClient
from nanoidp.services import authorization_transactions as transactions_module
from nanoidp.services import client_metadata as cimd
from nanoidp.services import pending_second_factors as second_factors_module
from nanoidp.services import runtime_repository
from nanoidp.services.authorization_transactions import (
    AuthorizationParameters,
    TransactionState,
    TransactionStoreFull,
    get_authorization_transaction_store,
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


@pytest.mark.usefixtures("interleaved")
class TestAuthorizationTransactions:
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
