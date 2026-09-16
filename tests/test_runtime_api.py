"""``/api/runtime`` (#192): disposable runtime users and clients on a running
IdP, their lifecycle (create, read, delete, reset, promote), the audit, and
the declared configuration left alone unless an object is promoted.
"""

import base64
import logging
import re
import shutil
import threading
from pathlib import Path

import pytest
import yaml

from nanoidp.app import create_app
from nanoidp.config import get_config
from nanoidp.services import get_audit_log
from nanoidp.services.identities import get_identities
from nanoidp.services.runtime_identities import get_runtime_identity_store

_REPO = Path(__file__).resolve().parent.parent
REDIRECT = "http://localhost:3000/callback"
ALICE = {"username": "ci-alice", "password": "alice-pw", "roles": ["TESTER"], "email": "alice@ci.test"}
APP = {"client_id": "ci-app", "client_secret": "app-secret-value", "redirect_uris": [REDIRECT]}


@pytest.fixture
def idp(tmp_path):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    for name in ("settings.yaml", "users.yaml"):
        shutil.copy(_REPO / "config" / name, config_dir / name)
    settings = config_dir / "settings.yaml"
    doc = yaml.safe_load(settings.read_text())
    doc["jwt"]["keys_dir"] = str(tmp_path / "keys")
    settings.write_text(yaml.safe_dump(doc))
    app = create_app(str(config_dir))
    app.config["TESTING"] = True
    return app.test_client(), config_dir


def _files(config_dir: Path) -> dict:
    return {name: (config_dir / name).read_bytes() for name in ("settings.yaml", "users.yaml")}


def _basic(client_id: str, secret: str) -> dict:
    return {"Authorization": "Basic " + base64.b64encode(f"{client_id}:{secret}".encode()).decode()}


def _events(event_type: str) -> list:
    return get_audit_log().get_entries(event_type=event_type)


def _create_both(client) -> None:
    assert client.post("/api/runtime/users", json=ALICE).status_code == 201
    assert client.post("/api/runtime/clients", json=APP).status_code == 201


class TestCreateReadDelete:
    def test_created_identities_work_in_protocol_flows_and_leave_the_files_alone(self, idp):
        client, config_dir = idp
        before = _files(config_dir)

        created = client.post("/api/runtime/users", json=ALICE)
        assert created.status_code == 201
        assert created.get_json()["origin"] == "runtime"
        assert "password" not in created.get_json()
        assert client.post("/api/runtime/clients", json=APP).status_code == 201

        tokens = client.post(
            "/token",
            data={"grant_type": "password", "username": "ci-alice", "password": "alice-pw"},
            headers=_basic("ci-app", "app-secret-value"),
        )
        assert tokens.status_code == 200, tokens.get_data(as_text=True)
        assert _files(config_dir) == before

    def test_authorization_code_and_saml_sso_for_a_created_user(self, idp):
        client, _ = idp
        _create_both(client)
        query = f"response_type=code&client_id=ci-app&redirect_uri={REDIRECT}&scope=openid"
        assert client.get("/authorize?" + query).status_code == 200
        login = client.post("/authorize", data={"username": "ci-alice", "password": "alice-pw"})
        code = re.search(r"code=([^&]+)", login.headers["Location"]).group(1)
        exchanged = client.post(
            "/token",
            data={"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT},
            headers=_basic("ci-app", "app-secret-value"),
        )
        assert exchanged.status_code == 200, exchanged.get_data(as_text=True)

        request = base64.b64encode(
            b'<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r" '
            b'Version="2.0" IssueInstant="2026-01-01T00:00:00Z" AssertionConsumerServiceURL="http://sp.test/acs"/>'
        ).decode()
        sso = client.post(
            "/saml/sso",
            data={"SAMLRequest": request, "saml_original_verb": "POST", "username": "ci-alice", "password": "alice-pw"},
        )
        assert b"SAMLResponse" in sso.data

    def test_read_endpoints_list_only_runtime_objects(self, idp):
        client, _ = idp
        _create_both(client)

        users = client.get("/api/runtime/users").get_json()
        assert [u["username"] for u in users["users"]] == ["ci-alice"] and users["count"] == 1
        assert client.get("/api/runtime/users/ci-alice").get_json()["email"] == "alice@ci.test"
        assert client.get("/api/runtime/users/admin").status_code == 404
        clients = client.get("/api/runtime/clients").get_json()
        assert [c["client_id"] for c in clients["clients"]] == ["ci-app"]
        assert "client_secret" not in clients["clients"][0]
        assert client.get("/api/runtime/clients/demo-client").status_code == 404

    def test_delete_removes_the_object_and_the_login(self, idp):
        client, _ = idp
        _create_both(client)

        assert client.delete("/api/runtime/users/ci-alice").get_json() == {"deleted": "ci-alice", "kind": "user"}
        assert client.delete("/api/runtime/users/ci-alice").status_code == 404
        assert client.delete("/api/runtime/clients/ci-app").status_code == 200
        refused = client.post(
            "/token",
            data={"grant_type": "client_credentials"},
            headers=_basic("ci-app", "app-secret-value"),
        )
        assert refused.status_code == 401
        assert [e["details"]["name"] for e in _events("runtime_identity_deleted")] == ["ci-app", "ci-alice"]

    def test_creation_is_audited(self, idp):
        client, _ = idp
        _create_both(client)
        details = [e["details"] for e in _events("runtime_identity_created")]
        assert {"kind": "user", "name": "ci-alice"} in details
        assert {"kind": "client", "name": "ci-app"} in details

    def test_runtime_objects_survive_a_reload(self, idp):
        client, _ = idp
        _create_both(client)
        assert client.post("/api/config/reload").status_code == 200
        assert client.get("/api/runtime/users/ci-alice").status_code == 200


class TestValidationAndCollisions:
    @pytest.mark.parametrize(
        "path, payload, fragment",
        [
            ("/api/runtime/users", {"password": "p"}, "username is required"),
            ("/api/runtime/users", {"username": "x", "roles": "ADMIN"}, "roles"),
            ("/api/runtime/users", ["not", "an", "object"], "expected a JSON object"),
            ("/api/runtime/clients", {"client_id": "x"}, "client_secret is required"),
            ("/api/runtime/clients", {"client_id": "x", "client_secret": "s", "bogus": 1}, "unknown key bogus"),
            ("/api/runtime/clients", {"client_id": "x", "client_secret": "s", "token_endpoint_auth_method": "magic"}, "token_endpoint_auth_method"),
        ],
    )
    def test_an_invalid_payload_answers_400_with_the_models_message(self, idp, path, payload, fragment):
        client, _ = idp
        response = client.post(path, json=payload)
        assert response.status_code == 400
        body = response.get_json()
        assert body["kind"] == "invalid" and fragment in body["error"]

    def test_a_rejected_secret_is_never_echoed(self, idp):
        client, _ = idp
        response = client.post(
            "/api/runtime/users", json={"username": "x", "password": "s3cr3t-value", "totp_secret": "not base32 at all!"}
        )
        assert response.status_code == 400
        assert "s3cr3t-value" not in response.get_data(as_text=True)
        assert "not base32 at all!" not in response.get_data(as_text=True)

    def test_a_declared_name_answers_409(self, idp):
        client, _ = idp
        user = client.post("/api/runtime/users", json={"username": "admin", "password": "x"})
        app = client.post("/api/runtime/clients", json={**APP, "client_id": "demo-client"})
        assert user.status_code == 409 and user.get_json()["kind"] == "declared"
        assert app.status_code == 409 and app.get_json()["kind"] == "declared"

    def test_an_existing_runtime_name_answers_409(self, idp):
        client, _ = idp
        _create_both(client)
        again = client.post("/api/runtime/users", json=ALICE)
        assert again.status_code == 409 and again.get_json()["kind"] == "exists"


class TestReset:
    def test_reset_removes_everything_runtime_and_reports_the_counts(self, idp):
        client, config_dir = idp
        before = _files(config_dir)
        _create_both(client)
        client.post("/api/runtime/users", json={"username": "ci-bob", "password": "b"})

        response = client.delete("/api/runtime")

        assert response.get_json() == {"users_deleted": 2, "clients_deleted": 1}
        assert client.get("/api/runtime/users").get_json()["count"] == 0
        assert client.post(
            "/token",
            data={"grant_type": "password", "username": "ci-alice", "password": "alice-pw"},
            headers=_basic("demo-client", "demo-secret"),
        ).status_code == 400
        assert _files(config_dir) == before
        assert _events("runtime_identities_reset")[0]["details"] == {"users_deleted": 2, "clients_deleted": 1}


class TestPromotion:
    def test_promoting_a_user_writes_one_entry_and_retires_the_runtime_object(self, idp, caplog):
        client, config_dir = idp
        _create_both(client)

        with caplog.at_level(logging.WARNING):
            response = client.post("/api/runtime/users/ci-alice/promote")

        assert response.status_code == 200, response.get_data(as_text=True)
        assert response.get_json() == {"promoted": "ci-alice", "kind": "user", "file": "users.yaml"}
        written = yaml.safe_load((config_dir / "users.yaml").read_text())["users"]["ci-alice"]
        assert written["password"] == "alice-pw" and written["roles"] == ["TESTER"]
        assert client.get("/api/runtime/users/ci-alice").status_code == 404
        assert get_identities().resolve_user("ci-alice").origin == "declared"
        assert len(_events("runtime_identity_promoted")) == 1
        assert _events("runtime_identity_removed_on_reload") == []
        assert not [r for r in caplog.records if "Runtime user" in r.getMessage()]

    def test_promoting_a_client_writes_it_to_settings_yaml(self, idp):
        client, config_dir = idp
        _create_both(client)

        response = client.post("/api/runtime/clients/ci-app/promote")

        assert response.status_code == 200
        clients = yaml.safe_load((config_dir / "settings.yaml").read_text())["oauth"]["clients"]
        assert "ci-app" in [c["client_id"] for c in clients]
        assert get_identities().resolve_client("ci-app").origin == "declared"
        assert get_identities().check_client("ci-app", "app-secret-value")

    def test_promoting_an_unknown_object_answers_404(self, idp):
        client, _ = idp
        assert client.post("/api/runtime/users/nobody/promote").status_code == 404

    def test_a_name_declared_in_the_file_meanwhile_answers_409_and_keeps_the_object(self, idp):
        client, config_dir = idp
        _create_both(client)
        users = config_dir / "users.yaml"
        doc = yaml.safe_load(users.read_text())
        doc["users"]["ci-alice"] = {"password": "someone-else"}
        users.write_text(yaml.safe_dump(doc))  # on disk, not reloaded

        response = client.post("/api/runtime/users/ci-alice/promote")

        assert response.status_code == 409 and response.get_json()["kind"] == "declared"
        assert client.get("/api/runtime/users/ci-alice").status_code == 200
        assert _events("runtime_identity_promoted") == []
        # Not marked any more: it can be deleted.
        assert client.delete("/api/runtime/users/ci-alice").status_code == 200

    def test_delete_and_a_second_promotion_answer_409_while_promoting(self, idp, monkeypatch):
        from nanoidp.services.yaml_writer import get_yaml_writer

        client, _ = idp
        _create_both(client)
        writer = get_yaml_writer()
        real_save_user = writer.save_user
        writing = threading.Event()
        release = threading.Event()

        def slow_save_user(user, **kwargs):
            writing.set()
            release.wait(5)
            return real_save_user(user, **kwargs)

        monkeypatch.setattr(writer, "save_user", slow_save_user)
        app = client.application
        results = {}

        def promote():
            with app.test_client() as other:
                results["promote"] = other.post("/api/runtime/users/ci-alice/promote").status_code

        worker = threading.Thread(target=promote)
        worker.start()
        assert writing.wait(5)
        deleting = client.delete("/api/runtime/users/ci-alice")
        promoting_again = client.post("/api/runtime/users/ci-alice/promote")
        release.set()
        worker.join()

        assert deleting.status_code == 409 and deleting.get_json()["kind"] == "promotion_in_progress"
        assert promoting_again.status_code == 409
        assert promoting_again.get_json()["kind"] == "promotion_in_progress"
        assert results["promote"] == 200
        assert len(_events("runtime_identity_promoted")) == 1

    def test_a_failing_strict_mirror_hook_does_not_undo_the_promotion(self, idp):
        client, config_dir = idp
        settings = config_dir / "settings.yaml"
        doc = yaml.safe_load(settings.read_text())
        doc["hooks"] = {"on_config_saved": "false", "strict": True}
        settings.write_text(yaml.safe_dump(doc))
        assert client.post("/api/config/reload").status_code == 200
        _create_both(client)

        response = client.post("/api/runtime/users/ci-alice/promote")

        assert response.status_code == 200
        assert "mirror_hook_error" in response.get_json()
        assert get_identities().resolve_user("ci-alice").origin == "declared"
        assert len(_events("runtime_identity_promoted")) == 1

    def test_a_failed_reload_after_the_write_keeps_the_object_until_a_reload_succeeds(self, idp, caplog):
        client, config_dir = idp
        _create_both(client)
        settings = config_dir / "settings.yaml"
        good = settings.read_text()
        settings.write_text("oauth: [broken\n")

        response = client.post("/api/runtime/users/ci-alice/promote")

        assert response.status_code == 500 and response.get_json()["kind"] == "reload_failed"
        assert "ci-alice" in yaml.safe_load((config_dir / "users.yaml").read_text())["users"]
        assert client.get("/api/runtime/users/ci-alice").status_code == 200
        assert client.delete("/api/runtime/users/ci-alice").status_code == 409  # still marked

        settings.write_text(good)
        with caplog.at_level(logging.WARNING):
            assert client.post("/api/config/reload").status_code == 200

        assert client.get("/api/runtime/users/ci-alice").status_code == 404
        assert len(_events("runtime_identity_promoted")) == 1
        assert _events("runtime_identity_removed_on_reload") == []
        assert not [r for r in caplog.records if "Runtime user" in r.getMessage()]


class TestPromotionAcrossFailuresAndConcurrency:
    """The review cases of #192: every mark resolves on a successful load,
    and a promotion never records an event it did not earn."""

    @staticmethod
    def _break_settings_with_a_missing_strict_plugin(config_dir: Path) -> str:
        settings = config_dir / "settings.yaml"
        good = settings.read_text()
        doc = yaml.safe_load(good)
        doc["hooks"] = {"strict": True}
        doc["plugins"] = {"no-such-plugin": {}}
        settings.write_text(yaml.safe_dump(doc))  # on disk only
        return good

    def test_a_strict_plugin_failing_on_the_reload_after_the_write_is_reload_failed(self, idp, caplog):
        client, config_dir = idp
        _create_both(client)
        good = self._break_settings_with_a_missing_strict_plugin(config_dir)

        response = client.post("/api/runtime/users/ci-alice/promote")

        assert response.status_code == 500 and response.get_json()["kind"] == "reload_failed"
        assert "mirror_hook_error" not in response.get_json()
        assert client.delete("/api/runtime/users/ci-alice").status_code == 409
        assert _events("runtime_identity_promoted") == []

        (config_dir / "settings.yaml").write_text(good)
        with caplog.at_level(logging.WARNING):
            assert client.post("/api/config/reload").status_code == 200
        assert len(_events("runtime_identity_promoted")) == 1
        assert not [r for r in caplog.records if "Runtime user" in r.getMessage()]

    def test_a_promotion_whose_entry_is_gone_after_the_repair_is_abandoned(self, idp, caplog):
        client, config_dir = idp
        _create_both(client)
        users_before = (config_dir / "users.yaml").read_text()
        settings = config_dir / "settings.yaml"
        good = settings.read_text()
        settings.write_text("oauth: [broken\n")
        assert client.post("/api/runtime/users/ci-alice/promote").status_code == 500

        settings.write_text(good)
        (config_dir / "users.yaml").write_text(users_before)  # the operator reverts the entry
        with caplog.at_level(logging.WARNING):
            assert client.post("/api/config/reload").status_code == 200

        assert client.get("/api/runtime/users/ci-alice").status_code == 200
        assert client.delete("/api/runtime/users/ci-alice").status_code == 200  # no stuck mark
        assert len(_events("runtime_identity_promotion_abandoned")) == 1
        assert _events("runtime_identity_promoted") == []
        assert any("Promotion of runtime user 'ci-alice' abandoned" in r.getMessage() for r in caplog.records)

    def test_reset_waits_for_a_promotion_in_progress(self, idp, monkeypatch):
        from nanoidp.services.yaml_writer import get_yaml_writer

        client, _ = idp
        _create_both(client)
        writer = get_yaml_writer()
        real_save_user = writer.save_user
        writing, release = threading.Event(), threading.Event()

        def paused_save_user(user, **kwargs):
            writing.set()
            release.wait(5)
            return real_save_user(user, **kwargs)

        monkeypatch.setattr(writer, "save_user", paused_save_user)
        app = client.application
        results = {}

        def promote():
            with app.test_client() as other:
                results["promote"] = other.post("/api/runtime/users/ci-alice/promote").status_code

        def reset():
            with app.test_client() as other:
                results["reset"] = other.delete("/api/runtime").get_json()

        promoter = threading.Thread(target=promote)
        promoter.start()
        assert writing.wait(5)
        resetter = threading.Thread(target=reset)
        resetter.start()
        resetter.join(0.3)
        assert resetter.is_alive()  # waiting for the promotion
        release.set()
        promoter.join()
        resetter.join()

        assert results["promote"] == 200
        assert results["reset"] == {"users_deleted": 0, "clients_deleted": 1}
        assert len(_events("runtime_identity_promoted")) == 1

    def test_reset_keeps_an_object_whose_promotion_awaits_a_successful_reload(self, idp):
        client, config_dir = idp
        _create_both(client)
        settings = config_dir / "settings.yaml"
        good = settings.read_text()
        settings.write_text("oauth: [broken\n")
        assert client.post("/api/runtime/users/ci-alice/promote").status_code == 500

        assert client.delete("/api/runtime").get_json() == {"users_deleted": 0, "clients_deleted": 1}
        assert client.get("/api/runtime/users/ci-alice").status_code == 200

        settings.write_text(good)
        assert client.post("/api/config/reload").status_code == 200
        assert len(_events("runtime_identity_promoted")) == 1

    def test_a_concurrent_declaration_of_the_name_is_a_collision_not_a_promotion(self, idp, monkeypatch, caplog):
        from nanoidp.config import User
        from nanoidp.services.yaml_writer import get_yaml_writer

        client, config_dir = idp
        _create_both(client)
        writer = get_yaml_writer()
        real_save_user = writer.save_user
        paused, go = threading.Event(), threading.Event()

        def save_user(user, **kwargs):
            if threading.current_thread().name == "promoter":
                paused.set()
                go.wait(5)
            return real_save_user(user, **kwargs)

        monkeypatch.setattr(writer, "save_user", save_user)
        app = client.application
        results = {}

        def promote():
            with app.test_client() as other:
                response = other.post("/api/runtime/users/ci-alice/promote")
                results["promote"] = (response.status_code, response.get_json()["kind"])

        def declare():
            writer.save_user(User(username="ci-alice", password="declared-by-ui"), is_new=True)

        promoter = threading.Thread(target=promote, name="promoter")
        promoter.start()
        assert paused.wait(5)
        declarer = threading.Thread(target=declare)
        with caplog.at_level(logging.WARNING):
            declarer.start()
            for _ in range(50):  # the declaration reaches the file, its reload waits
                if "ci-alice" in (config_dir / "users.yaml").read_text():
                    break
                threading.Event().wait(0.05)
            go.set()
            promoter.join()
            declarer.join()

        assert results["promote"] == (409, "declared")
        assert _events("runtime_identity_promoted") == []
        assert len(_events("runtime_identity_removed_on_reload")) == 1
        assert get_identities().resolve_user("ci-alice").user.password == "declared-by-ui"

    def test_an_unexpected_failure_after_the_write_keeps_the_promotion(self, idp, monkeypatch):
        """The file is replaced before the notify/reload steps: a failure
        there must not be reported as "nothing was written", or the mark
        would be dropped and the entry become a plain collision later."""
        client, config_dir = idp
        _create_both(client)
        manager = get_config()
        real_reload_local = manager.reload_local
        failed = []

        def reload_local_once_broken():
            if not failed:
                failed.append(True)
                raise RuntimeError("something unexpected after the write")
            return real_reload_local()

        monkeypatch.setattr(manager, "reload_local", reload_local_once_broken)
        response = client.post("/api/runtime/users/ci-alice/promote")
        monkeypatch.setattr(manager, "reload_local", real_reload_local)

        assert failed
        assert response.status_code == 500 and response.get_json()["kind"] == "reload_failed"
        assert "ci-alice" in yaml.safe_load((config_dir / "users.yaml").read_text())["users"]
        assert client.delete("/api/runtime/users/ci-alice").status_code == 409  # still marked

        assert client.post("/api/config/reload").status_code == 200
        assert client.get("/api/runtime/users/ci-alice").status_code == 404
        assert len(_events("runtime_identity_promoted")) == 1
        assert _events("runtime_identity_removed_on_reload") == []

    def test_a_malformed_file_on_disk_is_a_json_write_failure(self, idp):
        client, config_dir = idp
        _create_both(client)
        (config_dir / "users.yaml").write_text("users: [not: a mapping\n")

        response = client.post("/api/runtime/users/ci-alice/promote")

        assert response.status_code == 500
        assert response.is_json and response.get_json()["kind"] == "write_failed"
        assert client.delete("/api/runtime/users/ci-alice").status_code == 200  # not marked


class TestReconciliationAudit:
    def test_a_reload_that_declares_a_runtime_name_is_audited_and_warned(self, idp, caplog):
        client, config_dir = idp
        _create_both(client)
        users = config_dir / "users.yaml"
        doc = yaml.safe_load(users.read_text())
        doc["users"]["ci-alice"] = {"password": "declared"}
        users.write_text(yaml.safe_dump(doc))

        with caplog.at_level(logging.WARNING):
            assert client.post("/api/config/reload").status_code == 200

        events = _events("runtime_identity_removed_on_reload")
        assert [e["details"] for e in events] == [{"kind": "user", "name": "ci-alice"}]
        assert any("Runtime user 'ci-alice' removed" in r.getMessage() for r in caplog.records)
        assert _events("runtime_identity_promoted") == []


class TestManagementSecretGate:
    def test_writes_need_the_secret_and_reads_stay_open(self, idp, monkeypatch):
        client, _ = idp
        get_config().settings.management_secret = "gate-secret"

        assert client.post("/api/runtime/users", json=ALICE).status_code == 401
        assert client.delete("/api/runtime").status_code == 401
        assert client.get("/api/runtime/users").status_code == 200
        created = client.post("/api/runtime/users", json=ALICE, headers={"X-Management-Secret": "gate-secret"})
        assert created.status_code == 201
        assert client.post("/api/runtime/users/ci-alice/promote").status_code == 401
        assert get_runtime_identity_store().users.get("ci-alice") is not None


def test_the_network_binding_warning_names_the_runtime_api(idp, caplog, monkeypatch):
    import nanoidp.app as app_module

    monkeypatch.setattr(app_module.Flask, "run", lambda *args, **kwargs: None)
    with caplog.at_level(logging.WARNING, logger="nanoidp.app"):
        app_module.run_app(host="0.0.0.0", config_dir=str(idp[1]))
    assert any("/api/runtime" in record.getMessage() for record in caplog.records)
