"""Stateful identity scenarios over ``/api/runtime/scenarios`` (#402): a
runtime user that changes as the application uses the protocol, the state a
test reads back, and what ties a scenario to the one user it created.

Every test runs on both backends of the runtime store: the scenario and its
user are in two repositories, and the contract is the same on each.
"""

import base64
import logging
import re
import shutil
import sys
from pathlib import Path

import jwt as pyjwt
import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nanoidp.app import create_app  # noqa: E402
from nanoidp.services import get_audit_log, scenarios  # noqa: E402
from nanoidp.services.identities import IdentityResolver  # noqa: E402
from nanoidp.services.runtime_repository import RuntimeStoreUnavailable  # noqa: E402
from nanoidp.services.runtime_store import get_runtime_store  # noqa: E402
from tests.conftest import claim_for_promotion  # noqa: E402

_REPO = Path(__file__).resolve().parent.parent
REDIRECT = "http://localhost:3000/callback"
CLIENT = {"Authorization": "Basic " + base64.b64encode(b"demo-client:demo-secret").decode()}
URL = "/api/runtime/scenarios"


def _declaration(name="role-change", username="alice", steps=None, **user):
    return {
        "name": name,
        "given": {"user": {"username": username, "password": "alice-pw", "roles": ["USER"], **user}},
        "steps": steps
        if steps is not None
        else [{"after": {"event": "token_issued"}, "update_user": {"roles": ["ADMIN"]}}],
    }


def _write_settings(config_dir: Path, tmp_path: Path, backend: str, **session) -> None:
    for name in ("settings.yaml", "users.yaml"):
        shutil.copy(_REPO / "config" / name, config_dir / name)
    settings = config_dir / "settings.yaml"
    document = yaml.safe_load(settings.read_text())
    document["jwt"]["keys_dir"] = str(tmp_path / "keys")
    if backend == "sqlite":
        document["runtime"] = {"store": "sqlite", "path": str(tmp_path / "state" / "runtime.db")}
    if session:
        document.setdefault("session", {}).update(session)
    settings.write_text(yaml.safe_dump(document))


@pytest.fixture(params=["memory", "sqlite"])
def idp(request, tmp_path):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    _write_settings(config_dir, tmp_path, request.param)
    app = create_app(str(config_dir))
    app.config["TESTING"] = True
    return app.test_client(), config_dir


def _password(client, username="alice", password="alice-pw"):
    response = client.post(
        "/token", data={"grant_type": "password", "username": username, "password": password}, headers=CLIENT
    )
    assert response.status_code == 200, response.get_data(as_text=True)
    return response.get_json()


def _refresh(client, tokens):
    response = client.post(
        "/token", data={"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"]}, headers=CLIENT
    )
    assert response.status_code == 200, response.get_data(as_text=True)
    return response.get_json()


def _authorities(tokens):
    return pyjwt.decode(tokens["access_token"], options={"verify_signature": False})["authorities"]


def _step(client, name="role-change", index=0):
    return client.get(f"{URL}/{name}").get_json()["steps"][index]


def _roles(client, username="alice"):
    return client.get(f"/api/runtime/users/{username}").get_json()["roles"]


def _arm(client, **declaration):
    armed = client.post(URL, json=_declaration(**declaration))
    assert armed.status_code == 201, armed.get_data(as_text=True)
    return armed.get_json()


def _events(event_type):
    return get_audit_log().get_entries(event_type=event_type)


class _ProcessDies(BaseException):
    """What a worker that goes away raises: nothing below catches it."""


class TestTheRoleChange:
    def test_the_token_that_fires_the_step_is_from_before_and_the_next_is_from_after(self, idp):
        """The proof: the application asks for two tokens, and nothing
        touches the IdP in between."""
        client, _ = idp
        armed = _arm(client)
        assert armed == {
            "name": "role-change",
            "state": "armed",
            "user": "alice",
            "steps": [
                {
                    "after": {"event": "token_issued", "count": 1},
                    "update_user": {"roles": ["ADMIN"]},
                    "seen": 0,
                    "state": "waiting",
                }
            ],
        }

        first = _password(client)
        second = _password(client)

        assert _authorities(first) == ["ROLE_USER"]
        assert _authorities(second) == ["ROLE_ADMIN"]
        assert _step(client) == {
            "after": {"event": "token_issued", "count": 1},
            "update_user": {"roles": ["ADMIN"]},
            "seen": 1,
            "state": "applied",
        }

    def test_a_refresh_is_a_token_issued_with_its_grant_type(self, idp):
        client, _ = idp
        _arm(
            client,
            steps=[
                {
                    "after": {"event": "token_issued", "grant_type": "refresh_token"},
                    "update_user": {"roles": ["ADMIN"], "groups": ["ops"]},
                }
            ],
        )

        tokens = _password(client)
        assert _step(client)["seen"] == 0 and _step(client)["state"] == "waiting"
        refreshed = _refresh(client, tokens)
        again = _refresh(client, refreshed)

        assert _authorities(refreshed) == ["ROLE_USER"]
        assert _authorities(again) == ["ROLE_ADMIN", "GROUP_OPS"]

    def test_a_step_waits_for_its_count_and_fires_once(self, idp):
        client, _ = idp
        _arm(client, steps=[{"after": {"event": "token_issued", "count": 2}, "update_user": {"roles": ["ADMIN"]}}])

        first = _password(client)
        assert _step(client)["seen"] == 1 and _step(client)["state"] == "waiting"
        second = _password(client)
        third = _password(client)
        _password(client)

        assert [_authorities(t) for t in (first, second, third)] == [["ROLE_USER"], ["ROLE_USER"], ["ROLE_ADMIN"]]
        # Fired once: a step that is no longer waiting counts nothing.
        assert _step(client)["seen"] == 2 and _step(client)["state"] == "applied"
        assert len(_events(scenarios.STEP)) == 1

    def test_the_steps_of_a_scenario_each_count_from_the_arming(self, idp):
        client, _ = idp
        _arm(
            client,
            steps=[
                {"after": {"event": "token_issued", "count": 1}, "update_user": {"roles": ["ADMIN"]}},
                {"after": {"event": "token_issued", "count": 2}, "update_user": {"roles": ["AUDITOR"]}},
            ],
        )

        tokens = [_password(client) for _ in range(3)]

        assert [_authorities(t) for t in tokens] == [["ROLE_USER"], ["ROLE_ADMIN"], ["ROLE_AUDITOR"]]
        # The first step fired at the first token and counted nothing after,
        # while the second was still waiting.
        assert _step(client, index=0)["seen"] == 1 and _step(client, index=1)["seen"] == 2
        assert len(_events(scenarios.STEP)) == 2

    def test_a_scenario_with_no_step_waiting_for_the_event_takes_no_decision(self, idp, monkeypatch):
        """A decision takes the store's write lock: a scenario whose steps
        have fired, or wait for another event, costs a token a read."""
        client, _ = idp
        _arm(client)
        _password(client)
        counted = []
        real = scenarios._count
        monkeypatch.setattr(scenarios, "_count", lambda event: counted.append(event) or real(event))

        _password(client)

        assert counted == []

    def test_an_authorization_completed_fires_when_the_code_is_stored(self, idp):
        client, _ = idp
        _arm(client, steps=[{"after": {"event": "authorization_completed"}, "update_user": {"roles": ["ADMIN"]}}])
        client.post(
            "/api/runtime/clients",
            json={"client_id": "ci-app", "client_secret": "app-secret-value", "redirect_uris": [REDIRECT]},
        )

        query = f"response_type=code&client_id=ci-app&redirect_uri={REDIRECT}&scope=openid"
        assert client.get("/authorize?" + query).status_code == 200
        assert _step(client)["state"] == "waiting"
        login = client.post("/authorize", data={"username": "alice", "password": "alice-pw"})
        code = re.search(r"code=([^&]+)", login.headers["Location"]).group(1)

        assert _step(client)["state"] == "applied"
        exchanged = client.post(
            "/token",
            data={"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT},
            headers={"Authorization": "Basic " + base64.b64encode(b"ci-app:app-secret-value").decode()},
        )
        # The token is built after the code: it is the next request.
        assert _authorities(exchanged.get_json()) == ["ROLE_ADMIN"]

    def test_a_failed_login_at_authorize_is_no_authorization_completed(self, idp):
        client, _ = idp
        _arm(client, steps=[{"after": {"event": "authorization_completed"}, "update_user": {"roles": ["ADMIN"]}}])
        query = f"response_type=code&client_id=demo-client&redirect_uri={REDIRECT}&scope=openid"
        client.get("/authorize?" + query)

        client.post("/authorize", data={"username": "alice", "password": "wrong"})

        assert _step(client) == {
            "after": {"event": "authorization_completed", "count": 1},
            "update_user": {"roles": ["ADMIN"]},
            "seen": 0,
            "state": "waiting",
        }

    def test_only_the_token_endpoint_issues_a_token_for_a_scenario(self, idp):
        """/api/users/<name>/token mints for a test, not for the application;
        a failed grant issued nothing; another user's token is not alice's."""
        client, _ = idp
        _arm(client)
        client.post("/api/runtime/users", json={"username": "bob", "password": "bob-pw"})

        assert client.post("/api/users/alice/token").status_code == 200
        refused = client.post(
            "/token", data={"grant_type": "password", "username": "alice", "password": "wrong"}, headers=CLIENT
        )
        assert refused.status_code != 200
        _password(client, "bob", "bob-pw")
        assert client.post("/token", data={"grant_type": "client_credentials"}, headers=CLIENT).status_code == 200

        assert _step(client)["seen"] == 0 and _roles(client) == ["USER"]

    def test_a_token_that_could_not_be_built_is_no_token_issued(self, idp, monkeypatch):
        from nanoidp.services.token import TokenService

        client, _ = idp
        _arm(client)

        def fails(self, **kwargs):
            raise OSError("no token")

        monkeypatch.setattr(TokenService, "create_token", fails)
        with pytest.raises(OSError):
            client.post(
                "/token", data={"grant_type": "password", "username": "alice", "password": "alice-pw"}, headers=CLIENT
            )
        monkeypatch.undo()

        assert _step(client)["seen"] == 0 and _authorities(_password(client)) == ["ROLE_USER"]

    def test_an_event_counts_only_on_the_steps_that_wait_for_it(self, idp):
        client, _ = idp
        _arm(client, steps=[{"after": {"event": "authorization_completed"}, "update_user": {"roles": ["ADMIN"]}}])

        _password(client)

        assert _step(client)["seen"] == 0 and _roles(client) == ["USER"]

    def test_two_scenarios_on_one_instance_keep_to_their_users(self, idp):
        client, _ = idp
        _arm(client)
        _arm(client, name="bob-changes", username="bob")

        _password(client, "bob")

        assert _roles(client, "bob") == ["ADMIN"] and _roles(client) == ["USER"]
        assert _step(client)["state"] == "waiting"
        listed = client.get(URL).get_json()
        assert listed["count"] == 2 and [s["name"] for s in listed["scenarios"]] == ["role-change", "bob-changes"]

    def test_the_lifecycle_and_each_step_are_audited(self, idp):
        client, _ = idp
        _arm(client)
        _password(client)
        client.delete(f"{URL}/role-change")

        (armed,) = _events("runtime_scenario_armed")
        (step,) = _events(scenarios.STEP)
        (removed,) = _events("runtime_scenario_removed")
        assert armed["username"] == "alice" and armed["details"] == {"kind": "scenario", "name": "role-change"}
        assert step["status"] == "success" and step["username"] == "alice"
        assert step["details"] == {"scenario": "role-change", "step": 0, "outcome": "applied"}
        assert removed["username"] == "alice"
        assert removed["details"] == {"kind": "scenario", "name": "role-change", "user_removed": True}


class TestTheDeclaration:
    @pytest.mark.parametrize(
        "change, says",
        [
            (lambda d: d.update(extra=1), "extra"),
            (lambda d: d.update(name="has space"), "name"),
            (lambda d: d.pop("given"), "given"),
            (lambda d: d["given"].update(client={}), "given.client"),
            (lambda d: d["given"]["user"].pop("username"), "given.user: username is required"),
            (lambda d: d["given"]["user"].update(roles="USER"), "given.user"),
            (lambda d: d.update(steps=[]), "steps"),
            (lambda d: d["steps"][0]["after"].update(event="userinfo_read"), "event must be one of"),
            (lambda d: d["steps"][0]["after"].update(count=0), "steps.0.after.count"),
            (lambda d: d["steps"][0]["after"].update(count=True), "steps.0.after.count"),
            (lambda d: d["steps"][0]["after"].update(grant_type="refresh"), "grant_type must be one of"),
            (lambda d: d["steps"][0]["after"].update(grant_type="client_credentials"), "grant_type must be one of"),
            (lambda d: d.update(name=".."), "name"),
            (lambda d: d["steps"][0]["after"].update(user="alice"), "steps.0.after.user"),
            (
                lambda d: d["steps"][0]["after"].update(event="authorization_completed", grant_type="password"),
                "grant_type is only for token_issued",
            ),
            (lambda d: d["steps"][0].update(update_user={}), "steps.0.update_user sets one or more of"),
            (lambda d: d["steps"][0].update(update_user={"username": "eve"}), "not username"),
            (lambda d: d["steps"][0].update(update_user={"password": "x"}), "not password"),
            (lambda d: d["steps"][0].update(update_user={"roles": "ADMIN"}), "steps.0.update_user"),
            (lambda d: d["steps"][0].update(respond={}), "steps.0.respond"),
        ],
    )
    def test_what_does_not_validate_is_refused_and_nothing_is_made(self, idp, change, says):
        client, _ = idp
        declaration = _declaration()
        change(declaration)

        refused = client.post(URL, json=declaration)

        assert refused.status_code == 400, refused.get_data(as_text=True)
        assert refused.get_json()["kind"] == "invalid" and says in refused.get_json()["error"]
        assert client.get(URL).get_json()["count"] == 0
        assert client.get("/api/runtime/users").get_json()["count"] == 0

    def test_a_body_that_is_no_object_is_refused(self, idp):
        client, _ = idp
        assert client.post(URL, json=["role-change"]).status_code == 400

    def test_the_change_is_stored_as_the_user_model_reads_it(self, idp):
        client, _ = idp
        _arm(
            client,
            steps=[
                {
                    "after": {"event": "token_issued"},
                    "update_user": {"identity_class": "INTERNAL", "attributes": {"team": "blue"}, "source_acl": ["s1"]},
                }
            ],
        )

        _password(client)

        user = get_runtime_store().users.get("alice")
        assert (user.identity_class, user.attributes, user.source_acl) == ("INTERNAL", {"team": "blue"}, ["s1"])
        # What the step does not name stays as given.
        assert user.roles == ["USER"]


    def test_the_grant_types_a_step_may_name_are_the_grants_that_issue_for_a_user(self):
        from nanoidp.routes.oauth_grants import _GRANT_HANDLERS
        from nanoidp.services.protocol_events import USER_GRANT_TYPES

        assert set(USER_GRANT_TYPES) == set(_GRANT_HANDLERS) - {"client_credentials"}

    def test_a_named_field_is_replaced_whole(self, idp):
        client, _ = idp
        _arm(
            client,
            attributes={"a": 1, "b": 2},
            steps=[{"after": {"event": "token_issued"}, "update_user": {"attributes": {"a": 9}}}],
        )

        _password(client)

        assert get_runtime_store().users.get("alice").attributes == {"a": 9}


class TestCollisions:
    def test_a_scenario_of_that_name_is_refused_and_its_user_is_not_created(self, idp):
        client, _ = idp
        _arm(client)

        refused = client.post(URL, json=_declaration(username="bob"))

        assert refused.status_code == 409 and refused.get_json()["kind"] == "exists"
        assert "scenario" in refused.get_json()["error"]
        assert client.get("/api/runtime/users/bob").status_code == 404
        assert client.get(f"{URL}/role-change").get_json()["user"] == "alice"

    def test_a_declared_user_of_that_name_is_refused_and_no_scenario_is_left(self, idp):
        client, _ = idp

        refused = client.post(URL, json=_declaration(username="admin"))

        assert refused.status_code == 409 and refused.get_json()["kind"] == "declared"
        assert client.get(URL).get_json()["count"] == 0

    def test_a_runtime_user_of_that_name_is_refused_and_stays_as_it_was(self, idp):
        client, _ = idp
        client.post("/api/runtime/users", json={"username": "alice", "password": "x", "roles": ["MINE"]})

        refused = client.post(URL, json=_declaration())

        assert refused.status_code == 409 and refused.get_json()["kind"] == "exists"
        assert "runtime user" in refused.get_json()["error"]
        assert client.get(URL).get_json()["count"] == 0
        assert _roles(client) == ["MINE"]

    def test_at_the_cap_a_scenario_is_refused_and_its_user_is_not_created(self, idp, monkeypatch):
        client, _ = idp
        monkeypatch.setattr(scenarios, "MAX_SCENARIOS", 1)
        _arm(client)

        refused = client.post(URL, json=_declaration(name="one-more", username="bob"))

        assert refused.status_code == 409 and refused.get_json()["kind"] == "full"
        assert client.get("/api/runtime/users/bob").status_code == 404


class TestTheScenarioOwnsOneInstance:
    def test_removing_the_scenario_removes_its_user(self, idp):
        client, _ = idp
        _arm(client)

        removed = client.delete(f"{URL}/role-change")

        assert removed.get_json() == {"deleted": "role-change", "kind": "scenario", "user": "alice", "user_removed": True}
        assert client.get(f"{URL}/role-change").status_code == 404
        assert client.get("/api/runtime/users/alice").status_code == 404
        assert client.delete(f"{URL}/role-change").status_code == 404

    def test_a_user_created_again_under_the_name_is_not_the_scenarios(self, idp):
        client, _ = idp
        _arm(client)
        client.delete("/api/runtime/users/alice")
        client.post("/api/runtime/users", json={"username": "alice", "password": "alice-pw", "roles": ["MINE"]})

        _password(client)

        assert _step(client)["state"] == "refused" and _step(client)["reason"] == "user_gone"
        assert _roles(client) == ["MINE"]
        removed = client.delete(f"{URL}/role-change")
        assert removed.get_json()["user_removed"] is False
        assert _roles(client) == ["MINE"]

    def test_a_user_that_is_gone_refuses_the_step(self, idp, caplog):
        client, _ = idp
        _arm(client, steps=[{"after": {"event": "token_issued", "count": 2}, "update_user": {"roles": ["ADMIN"]}}])
        _password(client)
        get_runtime_store().users.delete("alice")
        client.post("/api/runtime/users", json={"username": "alice", "password": "alice-pw"})

        with caplog.at_level(logging.ERROR):
            delivered = _password(client)

        assert "access_token" in delivered
        assert _step(client)["state"] == "refused" and _step(client)["reason"] == "user_gone"
        assert "was not applied" in caplog.text
        (step,) = _events(scenarios.STEP)
        assert step["status"] == "failed" and step["details"]["reason"] == "user_gone"

    def test_a_user_a_promotion_holds_is_not_changed_and_not_removed(self, idp):
        """A promotion writes the value it claimed: a change made meanwhile
        would be lost without a word (#405, probe P4). And the scenario
        stays, to be removed once the promotion has ended."""
        client, _ = idp
        _arm(client)
        held = claim_for_promotion("user", "alice", "writing")

        _password(client)
        refused = client.delete(f"{URL}/role-change")

        assert _step(client)["state"] == "refused" and _step(client)["reason"] == "user_held"
        assert _roles(client) == ["USER"]
        assert refused.status_code == 409 and refused.get_json()["kind"] == "promotion_in_progress"
        assert client.get(f"{URL}/role-change").get_json()["state"] == "armed"

        get_runtime_store().users.transact(lambda view: view.release_hold("alice", held.hold_id))
        assert client.delete(f"{URL}/role-change").get_json()["user_removed"] is True

    def test_the_change_is_the_resolvers_and_follows_its_rule_for_a_held_user(self, idp, monkeypatch):
        """One home for 'a held user is not changed': the resolver, which
        also recovers the claim of a writer that died. The scenario does
        not write the users' repository on its own."""
        client, _ = idp
        _arm(client)
        calls = []
        real = IdentityResolver.replace_runtime_user

        def seen(self, username, instance_id, change):
            calls.append((username, instance_id))
            return real(self, username, instance_id, change)

        monkeypatch.setattr(IdentityResolver, "replace_runtime_user", seen)
        _password(client)

        assert calls == [("alice", get_runtime_store().users.entry("alice").instance_id)]
        assert _roles(client) == ["ADMIN"]

    def test_a_promoted_user_stays_declared_when_the_scenario_is_removed(self, idp):
        client, config_dir = idp
        _arm(client, steps=[{"after": {"event": "token_issued", "count": 2}, "update_user": {"roles": ["ADMIN"]}}])
        _password(client)
        assert client.post("/api/runtime/users/alice/promote").status_code == 200

        _password(client)
        removed = client.delete(f"{URL}/role-change")

        # The step found no runtime object: the declared user is not its.
        assert removed.get_json()["user_removed"] is False
        declared = yaml.safe_load((config_dir / "users.yaml").read_text())["users"]["alice"]
        assert declared["roles"] == ["USER"]
        assert _authorities(_password(client)) == ["ROLE_USER"]


class TestAStepIsTwoDecisions:
    def test_a_process_that_dies_before_the_change_leaves_the_step_pending(self, idp, monkeypatch):
        client, _ = idp
        _arm(client)

        def dies(fired):
            raise _ProcessDies()

        monkeypatch.setattr(scenarios, "_about_to_change", dies)
        with pytest.raises(_ProcessDies):
            _password(client)
        monkeypatch.undo()

        assert _step(client)["state"] == "pending" and "reason" not in _step(client)
        assert _roles(client) == ["USER"]
        # Nothing applies it later.
        assert _authorities(_password(client)) == ["ROLE_USER"]
        assert _step(client)["state"] == "pending" and _step(client)["seen"] == 1

    def test_a_process_that_dies_after_the_change_leaves_the_step_pending_and_applies_nothing_twice(
        self, idp, monkeypatch
    ):
        client, _ = idp
        _arm(client)

        def dies(fired):
            raise _ProcessDies()

        monkeypatch.setattr(scenarios, "_about_to_record", dies)
        with pytest.raises(_ProcessDies):
            _password(client)
        monkeypatch.undo()

        assert _step(client)["state"] == "pending"
        assert _roles(client) == ["ADMIN"]
        # A change made after it is not written over by a second application.
        store = get_runtime_store()
        store.users.transact(
            lambda view: view.replace("alice", view.entry("alice").value.model_copy(update={"roles": ["LATER"]}))
        )
        _password(client)
        assert _roles(client) == ["LATER"]
        assert _step(client)["state"] == "pending" and _step(client)["seen"] == 1
        assert _events(scenarios.STEP) == []

    def test_the_outcome_is_recorded_only_on_the_firing_that_marked_the_step(self, idp, monkeypatch):
        """A scenario removed and armed again under the name while a step
        was between its decisions is another scenario."""
        client, _ = idp
        _arm(client)

        def rearm(fired):
            monkeypatch.undo()
            client.delete(f"{URL}/role-change")
            _arm(client)

        monkeypatch.setattr(scenarios, "_about_to_change", rearm)
        _password(client)

        assert _step(client)["state"] == "waiting" and _step(client)["seen"] == 0
        assert _roles(client) == ["USER"]

    def test_an_outcome_is_not_written_on_a_step_another_firing_marked(self, idp, monkeypatch):
        client, _ = idp
        _arm(client)
        seen = []
        monkeypatch.setattr(scenarios, "_about_to_record", seen.append)
        _password(client)
        (fired,) = seen

        scenarios._record(fired.model_copy(update={"attempt": "another"}), "failed", "error")

        assert _step(client)["state"] == "applied" and "reason" not in _step(client)

    @pytest.mark.parametrize(
        "failure, reason", [(RuntimeStoreUnavailable("held"), "store_unavailable"), (OSError("disk"), "error")]
    )
    def test_a_change_that_cannot_be_made_delivers_the_token_and_says_failed(
        self, idp, monkeypatch, caplog, failure, reason
    ):
        client, _ = idp
        _arm(client)

        def fails(fired):
            raise failure

        monkeypatch.setattr(scenarios, "_change", fails)
        with caplog.at_level(logging.ERROR):
            delivered = _password(client)
        monkeypatch.undo()

        assert _authorities(delivered) == ["ROLE_USER"]
        assert _step(client)["state"] == "failed" and _step(client)["reason"] == reason
        assert "was not applied" in caplog.text
        (step,) = _events(scenarios.STEP)
        assert step["status"] == "failed" and step["details"]["outcome"] == "failed"
        # Failed is an outcome: the step does not fire again.
        assert _authorities(_password(client)) == ["ROLE_USER"]

    def test_an_outcome_that_cannot_be_recorded_delivers_the_token_and_stays_pending(
        self, idp, monkeypatch, caplog
    ):
        client, _ = idp
        _arm(client)

        def fails(fired, state, reason):
            raise RuntimeStoreUnavailable("held")

        monkeypatch.setattr(scenarios, "_record", fails)
        with caplog.at_level(logging.ERROR):
            delivered = _password(client)
        monkeypatch.undo()

        assert "access_token" in delivered
        assert _step(client)["state"] == "pending" and _roles(client) == ["ADMIN"]
        assert "could not be recorded; the step stays pending" in caplog.text

    def test_an_event_that_cannot_be_counted_delivers_the_token_and_leaves_the_step_waiting(
        self, idp, monkeypatch, caplog
    ):
        client, _ = idp
        _arm(client)

        def fails(event):
            raise RuntimeStoreUnavailable("held")

        monkeypatch.setattr(scenarios, "_count", fails)
        with caplog.at_level(logging.ERROR):
            delivered = _password(client)
        monkeypatch.undo()

        assert "access_token" in delivered
        assert _step(client)["state"] == "waiting" and _step(client)["seen"] == 0
        assert "was not counted by its scenarios" in caplog.text

    def test_an_observer_that_raises_does_not_fail_the_request(self, idp, monkeypatch, caplog):
        client, _ = idp
        _arm(client)

        def raises(event):
            raise RuntimeError("observer")

        monkeypatch.setattr(scenarios, "on_protocol_event", raises)
        with caplog.at_level(logging.ERROR):
            delivered = _password(client)

        assert "access_token" in delivered
        assert "An observer of token_issued failed" in caplog.text


class TestArmingIsTwoRepositories:
    def test_a_process_that_dies_while_arming_leaves_a_record_that_owns_no_user(self, idp, monkeypatch):
        client, _ = idp
        real = IdentityResolver.create_runtime_user_entry

        def dies(self, user):
            real(self, user)
            raise _ProcessDies()

        monkeypatch.setattr(IdentityResolver, "create_runtime_user_entry", dies)
        two = [{"after": {"event": "token_issued", "count": 2}, "update_user": {"roles": ["ADMIN"]}}]
        with pytest.raises(_ProcessDies):
            client.post(URL, json=_declaration(steps=two))
        monkeypatch.undo()

        assert client.get(f"{URL}/role-change").get_json()["state"] == "arming"
        # It never fires, and the user that exists is not known to be its.
        _password(client)
        assert _step(client)["seen"] == 0 and _roles(client) == ["USER"]
        removed = client.delete(f"{URL}/role-change")
        assert removed.get_json()["user_removed"] is False
        assert client.get("/api/runtime/users/alice").status_code == 200

    def test_an_arming_that_cannot_record_its_user_leaves_neither(self, idp, monkeypatch):
        """The store held by another process at the third step: the answer
        says to come back, and coming back has to work."""
        client, _ = idp
        real = scenarios._take_the_user

        def held(repository, record, created):
            raise RuntimeStoreUnavailable("held")

        monkeypatch.setattr(scenarios, "_take_the_user", held)
        refused = client.post(URL, json=_declaration())
        monkeypatch.setattr(scenarios, "_take_the_user", real)

        assert refused.status_code == 503
        assert client.get(URL).get_json()["count"] == 0
        assert client.get("/api/runtime/users/alice").status_code == 404
        assert client.post(URL, json=_declaration()).status_code == 201

    def test_a_removal_that_met_the_scenario_arming_removes_the_user_it_got_meanwhile(self, idp, monkeypatch):
        """The removal read the record before it had its user, and the
        arming completed before the record went."""
        client, _ = idp
        real = IdentityResolver.create_runtime_user_entry
        answers = []

        def removed_in_between(self, user):
            created = real(self, user)
            # The removal reads the arming record now, and reaches its
            # second step once the arming has recorded the user.
            def arm_completes(name):
                monkeypatch.setattr(scenarios, "_about_to_remove_the_record", lambda name: None)
                scenarios._take_the_user(*taking)

            taking = (scenarios._repository(), scenarios._repository().entry("role-change"), created)
            monkeypatch.setattr(scenarios, "_about_to_remove_the_record", arm_completes)
            answers.append(client.delete(f"{URL}/role-change").get_json())
            return created

        monkeypatch.setattr(IdentityResolver, "create_runtime_user_entry", removed_in_between)
        client.post(URL, json=_declaration())
        monkeypatch.undo()

        assert answers == [{"deleted": "role-change", "kind": "scenario", "user": "alice", "user_removed": True}]
        assert client.get(URL).get_json()["count"] == 0
        assert client.get("/api/runtime/users/alice").status_code == 404

    def test_a_reset_while_arming_leaves_neither_the_scenario_nor_its_user(self, idp, monkeypatch):
        client, _ = idp
        real = IdentityResolver.create_runtime_user_entry

        def reset_in_between(self, user):
            scenarios.reset()
            return real(self, user)

        monkeypatch.setattr(IdentityResolver, "create_runtime_user_entry", reset_in_between)
        refused = client.post(URL, json=_declaration())
        monkeypatch.undo()

        assert refused.status_code == 409 and refused.get_json()["kind"] == "conflict"
        assert client.get(URL).get_json()["count"] == 0
        assert client.get("/api/runtime/users/alice").status_code == 404

    def test_a_scenario_armed_under_the_name_meanwhile_is_not_armed_with_this_user(self, idp, monkeypatch):
        client, _ = idp
        real = IdentityResolver.create_runtime_user_entry
        calls = []

        def replaced_in_between(self, user):
            calls.append(user.username)
            if len(calls) == 1:
                scenarios.reset()
                _arm(client, username="bob")
            return real(self, user)

        monkeypatch.setattr(IdentityResolver, "create_runtime_user_entry", replaced_in_between)
        refused = client.post(URL, json=_declaration())
        monkeypatch.undo()

        assert refused.status_code == 409 and refused.get_json()["kind"] == "conflict"
        assert client.get(f"{URL}/role-change").get_json()["user"] == "bob"
        assert client.get("/api/runtime/users/alice").status_code == 404
        _password(client, "bob")
        assert _roles(client, "bob") == ["ADMIN"]

    def test_the_record_that_fails_to_get_its_user_does_not_take_another_scenarios_place(self, idp, monkeypatch):
        """The record removed after a failed creation is this call's, by
        instance: one armed under the name meanwhile stays."""
        client, _ = idp
        real = IdentityResolver.create_runtime_user_entry
        calls = []

        def replaced_in_between(self, user):
            calls.append(user.username)
            if len(calls) == 1:
                scenarios.reset()
                _arm(client, username="bob")
                raise ValueError("no user for the first")
            return real(self, user)

        monkeypatch.setattr(IdentityResolver, "create_runtime_user_entry", replaced_in_between)
        with pytest.raises(ValueError):
            client.post(URL, json=_declaration())
        monkeypatch.undo()

        assert client.get(f"{URL}/role-change").get_json()["user"] == "bob"


class TestReset:
    def test_a_reset_removes_the_scenarios_with_the_rest(self, idp):
        client, _ = idp
        _arm(client)
        _arm(client, name="bob-changes", username="bob")

        counts = client.delete("/api/runtime").get_json()

        assert counts["scenarios_removed"] == 2 and counts["users_deleted"] == 2
        assert client.get(URL).get_json() == {"scenarios": [], "count": 0}
        # A scenario of the same name starts from nothing.
        assert _arm(client)["steps"][0]["seen"] == 0


class TestTheGate:
    def test_arming_and_removing_need_the_management_secret_and_reading_does_not(self, tmp_path):
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        _write_settings(config_dir, tmp_path, "memory", management_secret="s3cret-402")
        client = create_app(str(config_dir)).test_client()
        secret = {"X-Management-Secret": "s3cret-402"}

        assert client.post(URL, json=_declaration()).status_code in (401, 403)
        assert client.get(URL).get_json()["count"] == 0
        assert client.post(URL, json=_declaration(), headers=secret).status_code == 201
        assert client.delete(f"{URL}/role-change").status_code in (401, 403)
        assert client.get(f"{URL}/role-change").status_code == 200
        assert client.delete(f"{URL}/role-change", headers=secret).status_code == 200

    def test_the_answer_shows_no_credential_of_the_user(self, idp):
        client, _ = idp
        armed = client.post(URL, json=_declaration())

        assert "alice-pw" not in armed.get_data(as_text=True)
        assert "alice-pw" not in client.get(URL).get_data(as_text=True)
