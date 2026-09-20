"""The lifecycle of a dynamic registration record (#190).

A record is metadata beside a runtime client, never the answer to "does this
client exist": the resolver owns that. So the record has to become inert by
itself when the client goes away - promoted into the declared configuration,
deleted, reset or shadowed by a reload - without ``services.identities``
knowing that registration exists at all.

These tests run against the service, before any HTTP surface, so the route
layer inherits a contract instead of defining one.
"""

import shutil
from pathlib import Path

import pytest
import yaml

from nanoidp.app import create_app
from nanoidp.config import OAuthClient
from nanoidp.services.dynamic_registration import (
    CLIENT_ID_PREFIX,
    forget_registration_of,
    live_registration,
    new_client_id,
    new_registration_token,
    prune_stale_registrations,
    record_registration,
    registrations,
    token_matches,
)
from nanoidp.services.identities import get_identities
from nanoidp.services.yaml_writer import get_yaml_writer

_REPO = Path(__file__).resolve().parent.parent


@pytest.fixture
def app(tmp_path):
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
    return application


def _register(client_id="dcr-one", grant_types=("authorization_code",)):
    """A runtime client plus its record, the way POST /register makes them."""
    identities = get_identities()
    created = identities.create_runtime_client_entry(
        OAuthClient(
            client_id=client_id,
            token_endpoint_auth_method="none",
            redirect_uris=["http://localhost:9000/callback"],
        )
    )
    token = new_registration_token()
    record_registration(created, list(grant_types), token, limit=100)
    return client_id, token


class TestTheCredential:
    def test_the_raw_token_is_not_in_the_record(self, app):
        with app.app_context():
            client_id, token = _register()
            record = registrations().get(client_id)

            assert token not in record.model_dump_json()
            assert record.registration_token_hash != token

    def test_the_right_token_verifies_and_another_does_not(self, app):
        with app.app_context():
            client_id, token = _register()
            record = registrations().get(client_id)

            assert token_matches(token, record) is True
            assert token_matches(new_registration_token(), record) is False
            assert token_matches("", record) is False


class TestGeneratedIds:
    def test_an_id_is_free_and_carries_the_prefix(self, app):
        with app.app_context():
            client_id = new_client_id(get_identities())

            assert client_id.startswith(CLIENT_ID_PREFIX)
            assert get_identities().resolve_client(client_id) is None

    def test_a_taken_id_is_not_handed_out_again(self, app, monkeypatch):
        """The prefix is a hint for a human reading a log, so nothing stops a
        client from already holding the id the generator draws; it has to
        draw again. Random ids make a real collision vanishingly rare, so
        the draw is forced here rather than hoped for."""
        drawn = iter(["taken", "taken", "free"])
        monkeypatch.setattr(
            "nanoidp.services.dynamic_registration.secrets.token_urlsafe",
            lambda _length: next(drawn),
        )
        with app.app_context():
            get_identities().create_runtime_client(
                OAuthClient(
                    client_id=f"{CLIENT_ID_PREFIX}taken",
                    token_endpoint_auth_method="none",
                )
            )

            assert new_client_id(get_identities()) == f"{CLIENT_ID_PREFIX}free"

    def test_a_generator_that_only_draws_taken_ids_fails_loudly(self, app, monkeypatch):
        """Better a refused registration than one that quietly takes over
        another client's id."""
        monkeypatch.setattr(
            "nanoidp.services.dynamic_registration.secrets.token_urlsafe",
            lambda _length: "taken",
        )
        with app.app_context():
            get_identities().create_runtime_client(
                OAuthClient(
                    client_id=f"{CLIENT_ID_PREFIX}taken",
                    token_endpoint_auth_method="none",
                )
            )

            with pytest.raises(RuntimeError, match="unused client_id"):
                new_client_id(get_identities())


class TestTheRecordFollowsItsClient:
    def test_a_live_client_has_a_live_record(self, app):
        with app.app_context():
            client_id, _ = _register()

            assert live_registration(client_id, get_identities()) is not None

    def test_a_deleted_client_leaves_no_live_record(self, app):
        with app.app_context():
            client_id, _ = _register()
            get_identities().delete_runtime_client(client_id)

            assert live_registration(client_id, get_identities()) is None
            assert registrations().get(client_id) is None, "the record was not dropped"

    def test_a_promoted_client_leaves_no_live_record(self, app):
        """Promotion makes it declared configuration; RFC 7592 management of
        it ends there, rather than a registration credential staying valid
        against a client the operator now owns."""
        with app.app_context():
            client_id, _ = _register()
            get_identities().promote_runtime_client(client_id, {"source": "test"})

            assert get_identities().resolve_client(client_id).origin == "declared"
            assert live_registration(client_id, get_identities()) is None

    def test_a_reset_leaves_no_live_record(self, app):
        with app.app_context():
            client_id, _ = _register()
            get_identities().reset_runtime_identities()

            assert live_registration(client_id, get_identities()) is None

    def test_a_declared_client_of_the_same_name_ends_the_record(self, app):
        """A reload that declares the name removes the runtime client (#235),
        so its record must stop managing the declared one."""
        with app.app_context():
            client_id, _ = _register()
            get_yaml_writer().save_client(
                OAuthClient(
                    client_id=client_id,
                    client_secret="declared-secret",
                    redirect_uris=["http://localhost:9000/callback"],
                ),
                is_new=True,
            )

            assert get_identities().resolve_client(client_id).origin == "declared"
            assert live_registration(client_id, get_identities()) is None


class TestPruning:
    def test_records_nobody_asks_about_are_swept(self, app):
        """Without this, a register/promote/register cycle would grow the
        repository forever and keep spending capacity on the dead."""
        with app.app_context():
            identities = get_identities()
            kept, _ = _register("dcr-kept")
            for name in ("dcr-gone-1", "dcr-gone-2"):
                _register(name)
                identities.delete_runtime_client(name)

            assert prune_stale_registrations(identities) == 2
            assert [r.client_id for r in registrations().list()] == [kept]

    def test_pruning_is_idempotent(self, app):
        with app.app_context():
            identities = get_identities()
            _register()

            assert prune_stale_registrations(identities) == 0
            assert prune_stale_registrations(identities) == 0
            assert len(registrations().list()) == 1

    def test_a_stale_record_is_dropped_but_not_the_one_that_replaced_it(self, app, monkeypatch):
        """The cleanup on the way past a stale record goes by the record's
        own instance: a registration made under the same id between the
        look and the drop is a different record, and stays."""
        from nanoidp.services.runtime_repository import MemoryRuntimeRepository

        with app.app_context():
            identities = get_identities()
            client_id, _ = _register()
            identities.delete_runtime_client(client_id)
            looked = MemoryRuntimeRepository.entry
            once = []

            def then_registered_again(self, name):
                found = looked(self, name)
                if self is registrations() and not once:
                    once.append(True)
                    registrations().delete(client_id)
                    _register(client_id)
                return found

            monkeypatch.setattr(MemoryRuntimeRepository, "entry", then_registered_again)

            assert live_registration(client_id, identities) is None
            monkeypatch.undo()
            assert live_registration(client_id, identities) is not None

    def test_the_sweep_drops_the_record_it_looked_at_and_no_other(self, app, monkeypatch):
        from nanoidp.services.runtime_repository import MemoryRuntimeRepository

        with app.app_context():
            identities = get_identities()
            client_id, _ = _register()
            identities.delete_runtime_client(client_id)
            listed = MemoryRuntimeRepository.entries
            once = []

            def then_registered_again(self):
                found = listed(self)
                if self is registrations() and not once:
                    once.append(True)
                    registrations().delete(client_id)
                    _register(client_id)
                return found

            monkeypatch.setattr(MemoryRuntimeRepository, "entries", then_registered_again)

            assert prune_stale_registrations(identities) == 0
            monkeypatch.undo()
            assert live_registration(client_id, identities) is not None

    def test_forgetting_a_record_says_whether_there_was_one(self, app):
        with app.app_context():
            client_id, _ = _register()
            client = get_identities().store.clients.entry(client_id)

            assert forget_registration_of(client) is True
            assert forget_registration_of(client) is False
