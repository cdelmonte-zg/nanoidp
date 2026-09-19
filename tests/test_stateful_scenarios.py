"""Spike: stateful identity test scenarios over the runtime store (issue #402).

The question this spike answers is narrow: does NanoIDP already have the parts
for an identity that *evolves during a test*, driven by the application's own
protocol calls, so that a role change between two token requests needs no
hand-orchestrated timing? The proof is
test_the_role_change_scenario_is_the_awkward_test_made_easy: two ordinary
password-grant calls, and the first token carries ROLE_USER while the second
carries ROLE_ADMIN, with nothing in the test touching the IdP between them.

Everything here is test-only, on purpose (issue #402 decision 1): no
declaration surface, no general DSL, one mutation shape (`roles`). The engine
is a plugin object on the existing on_audit_event extension point (#185) - it
is not new event plumbing, which is the point of the spike. It is deliberately
NOT a request/respond matcher (that is WireMock's job).

Scope corrections found while building, recorded honestly:
- The User model has no `enabled` flag (models.py: "there is no separate
  'enabled' flag"), so the mutation set of this slice is `roles` only;
  a disable scenario would need a new user field, out of this spike.
- The timing invariant (issue #402 decision 3) is pinned, not assumed:
  token issuance mints from the user resolved *before* it, then audits
  success (routes/oauth.py), so the first token is always pre-mutation.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Any, Mapping, Optional

import jwt as pyjwt
import pytest
import yaml

from nanoidp.app import create_app
from nanoidp.config import get_config
from nanoidp.hooks import HOOK_API_VERSION
from nanoidp.models import User
from nanoidp.services.identities import get_identities

_REPO = Path(__file__).resolve().parent.parent


# --- the spike engine -------------------------------------------------------

# Named semantic events, mapped from the raw audit (event_type, status) so a
# scenario binds to "token_issued", not to the incidental audit string
# "token_request" (issue #402 decision 2).
_EVENT_VOCABULARY = {
    ("token_request", "success"): "token_issued",
    ("authorization_request", "success"): "authorization_completed",
}


def _semantic_event(event: Mapping[str, Any]) -> Optional[str]:
    return _EVENT_VOCABULARY.get((event.get("event_type"), event.get("status")))


@dataclass
class Step:
    event: str
    user: str
    count: int
    update_user: dict


@dataclass
class Scenario:
    name: str
    steps: list[Step]


class ScenarioEngine:
    """Observes audit events (as an on_audit_event plugin object) and applies
    a runtime-identity mutation when a step's trigger is reached. One-shot per
    step. Mutates only a runtime user - never a declared one, since a scenario
    owns disposable test state, not the operator's file."""

    hook_api_version = HOOK_API_VERSION

    def __init__(self, scenario: Scenario) -> None:
        self._scenario = scenario
        self._counts: dict[tuple[str, str], int] = {}
        self._fired: set[int] = set()
        self._lock = Lock()
        self.applied: list[dict] = []  # observable record, for the tests

    def on_audit_event(self, event: Mapping[str, Any]) -> None:
        semantic = _semantic_event(event)
        username = event.get("username")
        if semantic is None or not username:
            return
        with self._lock:
            for index, step in enumerate(self._scenario.steps):
                if index in self._fired or step.event != semantic or step.user != username:
                    continue
                key = (semantic, username)
                self._counts[key] = self._counts.get(key, 0) + 1
                if self._counts[key] >= step.count:
                    self._apply(step)
                    self._fired.add(index)

    def _apply(self, step: Step) -> None:
        identities = get_identities()
        resolved = identities.resolve_user(step.user)
        if resolved is None or resolved.origin != "runtime":
            return  # never rewrite a declared identity
        updated = resolved.user.model_copy(update=step.update_user)
        identities.delete_runtime_user(step.user)
        identities.create_runtime_user(updated)
        self.applied.append({"user": step.user, "update": dict(step.update_user)})


# --- harness ----------------------------------------------------------------

CLIENT = ("demo-client", "demo-secret")


@pytest.fixture
def app(tmp_path, reset_singletons):
    cfg = tmp_path / "config"
    cfg.mkdir()
    for name in ("settings.yaml", "users.yaml"):
        shutil.copy(_REPO / "config" / name, cfg / name)
    settings = cfg / "settings.yaml"
    document = yaml.safe_load(settings.read_text())
    document.setdefault("jwt", {})["keys_dir"] = str(tmp_path / "keys")
    settings.write_text(yaml.safe_dump(document))
    app = create_app(str(cfg))
    app.config["TESTING"] = True
    return app


def _arm(scenario: Scenario) -> ScenarioEngine:
    """Register the engine on the running config's hook registry (test-only)."""
    engine = ScenarioEngine(scenario)
    get_config().hooks.register_plugin_object("scenario-spike", engine, source="test")
    return engine


def _runtime_user(username: str, roles: list[str], password: str = "pw-12345") -> None:
    get_identities().create_runtime_user(
        User(username=username, password=password, roles=roles)
    )


def _password_token(client, username: str, password: str = "pw-12345") -> dict:
    response = client.post(
        "/token",
        data={"grant_type": "password", "username": username, "password": password},
        auth=CLIENT,
    )
    assert response.status_code == 200, response.get_data(as_text=True)
    return response.get_json()


def _authorities(access_token: str) -> list[str]:
    payload = pyjwt.decode(access_token, options={"verify_signature": False})
    return payload.get("authorities", [])


# --- the proof --------------------------------------------------------------

ROLE_CHANGE = Scenario(
    name="role-change-after-login",
    steps=[Step(event="token_issued", user="alice", count=1, update_user={"roles": ["ADMIN"]})],
)


def test_the_role_change_scenario_is_the_awkward_test_made_easy(app):
    """The whole point. An app that re-reads authorization on its next token
    call sees the role change, and the test orchestrates no timing: the app's
    own two calls drive it. First token pre-mutation, second post."""
    with app.app_context():
        _runtime_user("alice", roles=["USER"])
        engine = _arm(ROLE_CHANGE)
    client = app.test_client()

    first = _password_token(client, "alice")
    assert "ROLE_USER" in _authorities(first["access_token"])
    assert "ROLE_ADMIN" not in _authorities(first["access_token"])

    second = _password_token(client, "alice")
    assert "ROLE_ADMIN" in _authorities(second["access_token"])

    assert engine.applied == [{"user": "alice", "update": {"roles": ["ADMIN"]}}]


def test_the_step_is_one_shot(app):
    """Once fired, the step does not re-fire: a third token stays ADMIN and the
    mutation was applied exactly once."""
    with app.app_context():
        _runtime_user("alice", roles=["USER"])
        engine = _arm(ROLE_CHANGE)
    client = app.test_client()

    _password_token(client, "alice")
    _password_token(client, "alice")
    third = _password_token(client, "alice")

    assert "ROLE_ADMIN" in _authorities(third["access_token"])
    assert len(engine.applied) == 1


def test_a_higher_count_does_not_fire_early(app):
    """count: 2 means the mutation lands after the second event, not the
    first: the token issued between them is still pre-mutation."""
    with app.app_context():
        _runtime_user("alice", roles=["USER"])
        _arm(Scenario(
            name="role-change-after-two",
            steps=[Step(event="token_issued", user="alice", count=2, update_user={"roles": ["ADMIN"]})],
        ))
    client = app.test_client()

    assert "ROLE_ADMIN" not in _authorities(_password_token(client, "alice")["access_token"])
    assert "ROLE_ADMIN" not in _authorities(_password_token(client, "alice")["access_token"])
    assert "ROLE_ADMIN" in _authorities(_password_token(client, "alice")["access_token"])


def test_a_declared_user_is_never_mutated(app):
    """The engine owns disposable test state, not the operator's file: a step
    aimed at a declared user applies nothing, and the declared roles stand."""
    with app.app_context():
        _arm(Scenario(
            name="touch-declared",
            steps=[Step(event="token_issued", user="admin", count=1, update_user={"roles": ["ADMIN"]})],
        ))
        before = get_config().get_user("admin").roles
    client = app.test_client()

    _password_token(client, "admin", password="admin")
    _password_token(client, "admin", password="admin")

    with app.app_context():
        assert get_config().get_user("admin").roles == before
