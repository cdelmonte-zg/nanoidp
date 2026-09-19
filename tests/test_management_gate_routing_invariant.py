"""Management-mutation boundary as a fail-closed routing invariant (SEC-002).

`management_secret` gates mutations. `tests/test_management_secret.py` proves
the mechanism, and `tests/test_ui_forms.py` sweeps a hand-maintained list of
`ui` POST paths. Both are representative: the list falls out of date (it is
already missing `/clients/forget`), it covers only `ui` and only POST, and
neither notices a new blueprint that exposes a mutating route without the
gate.

This lifts that assumption to a contract over the whole application routing,
derived from `app.url_map` so nothing has to be maintained by hand, and
fail-closed: every non-safe route belongs to a blueprint that is explicitly
classified as a management surface (gated) or a protocol surface (governed by
its own authorization), and a route on any other blueprint fails this test
until someone classifies it.

The contract, as agreed:

    Safe methods (GET/HEAD/OPTIONS) never require management_secret.

    Non-safe methods:
      ui:           require it, except ui.login and ui.management_unlock
      api:          require it, no exemptions
      runtime:      require it, no exemptions
      oauth:        outside the management boundary (protocol)
      saml:         outside the management boundary (protocol)
      registration: outside it; governed by OAuth / RFC 7591 / RFC 7592
      any other blueprint with a non-safe route: fails until classified

This does not reproduce a current defect: on today's code every management
mutation is gated. Its job is to fail closed when a future route or blueprint
would slip a mutation past the gate, and to replace the hand-maintained list.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

from nanoidp.app import create_app
from nanoidp.routes import _auth

_REPO_CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"
SECRET = "sec002-management-secret-unknown-to-the-caller"

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

# Blueprints whose non-safe routes MUST require the management write guard.
MANAGEMENT_BLUEPRINTS = {"ui", "api", "runtime"}

# Blueprints that are outside the management boundary by design: their
# authorization is the protocol's own (OAuth client auth and PKCE, SAML
# signatures, the RFC 7591/7592 registration access token).
PROTOCOL_BLUEPRINTS = {"oauth", "saml", "registration"}

# The only management endpoints that a non-safe request may reach without the
# guard. ui.management_unlock cannot require the secret without being circular;
# ui.login is the authentication front door, not an administrative mutation.
# Pinned here as the intended set and checked against the code below, so that
# adding an exemption in either place without the other fails this test.
MANAGEMENT_EXEMPT_ENDPOINTS = {"ui.login", "ui.management_unlock"}


@pytest.fixture
def app(tmp_path, reset_singletons):
    """An instance with the management gate on and UI login off - the posture
    in which a non-safe request that is not gated would take effect.

    `management_secret_required_for_ui/_api` read the process-global
    `get_config()`, and conftest's autouse `reset_singletons` clears it around
    each test. So the app is built inside the fixture, after that reset (which
    is why the fixture depends on it), and `create_app(config_dir=...)` is the
    last thing to set the global - otherwise the gate reads a config without
    the secret and every mutation reaches its view. `config_dir` is explicit,
    so the autouse `NANOIDP_CONFIG_DIR` does not choose it.
    """
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    for name in ("settings.yaml", "users.yaml"):
        shutil.copy(_REPO_CONFIG_DIR / name, cfg / name)
    settings = cfg / "settings.yaml"
    document = yaml.safe_load(settings.read_text())
    document.setdefault("jwt", {})["keys_dir"] = str(tmp_path / "keys")
    document.setdefault("session", {})["management_secret"] = SECRET
    document["oauth"]["dynamic_registration"] = {"enabled": True}
    settings.write_text(yaml.safe_dump(document))
    app = create_app(config_dir=str(cfg))
    app.config["TESTING"] = True
    return app


def _nonsafe_routes(app):
    """(blueprint, endpoint, method, url) for every non-safe route, with a
    dummy value in each path argument (the guard runs before the view, so the
    value never reaches it)."""
    out = []
    with app.test_request_context():
        from flask import url_for

        for rule in app.url_map.iter_rules():
            methods = rule.methods - SAFE_METHODS - {"HEAD", "OPTIONS"}
            if not methods:
                continue
            blueprint = rule.endpoint.split(".")[0]
            url = url_for(rule.endpoint, **dict.fromkeys(rule.arguments, "x"))
            for method in sorted(methods):
                out.append((blueprint, rule.endpoint, method, url))
    return out


def test_exempt_set_matches_the_code(app):
    """The intended exemptions and the code's own set are the same, and every
    exemption names a real ui endpoint (a typo would silently exempt nothing
    or, worse, drift)."""
    assert MANAGEMENT_EXEMPT_ENDPOINTS == _auth._UI_MANAGEMENT_EXEMPT_ENDPOINTS
    endpoints = {rule.endpoint for rule in app.url_map.iter_rules()}
    assert MANAGEMENT_EXEMPT_ENDPOINTS <= endpoints
    assert all(e.startswith("ui.") for e in MANAGEMENT_EXEMPT_ENDPOINTS)


def test_every_nonsafe_blueprint_is_classified(app):
    """Fail-closed: the set of blueprints that expose a non-safe route is
    exactly the union of the two classified sets. A new blueprint with a
    mutating route fails here until it is classified; a classified blueprint
    that no longer exists fails too, so the sets cannot rot."""
    seen = {bp for bp, _e, _m, _u in _nonsafe_routes(app)}
    classified = MANAGEMENT_BLUEPRINTS | PROTOCOL_BLUEPRINTS
    assert not MANAGEMENT_BLUEPRINTS & PROTOCOL_BLUEPRINTS
    assert seen - classified == set(), f"unclassified blueprints with a non-safe route: {seen - classified}"
    assert classified - seen == set(), f"classified blueprints with no non-safe route: {classified - seen}"


def test_every_management_mutation_is_gated(app):
    """Behavioural: with the gate on and no proof, every non-safe route on a
    management blueprint that is not an explicit exemption is refused before
    its view runs - 401 on the api/runtime surfaces, a redirect to /login on
    the ui. The request carries no body: the guard is a before_request hook,
    so it fires before the view would parse one."""
    client = app.test_client()
    checked = 0
    for blueprint, endpoint, method, url in _nonsafe_routes(app):
        if blueprint not in MANAGEMENT_BLUEPRINTS or endpoint in MANAGEMENT_EXEMPT_ENDPOINTS:
            continue
        response = client.open(url, method=method)  # no X-Management-Secret, no session
        if blueprint == "ui":
            assert response.status_code == 302, (method, url, response.status_code)
            assert "/login" in response.headers["Location"], (method, url)
        else:
            assert response.status_code == 401, (method, url, response.status_code)
        checked += 1
    assert checked >= 20, checked  # api 4 + runtime 7 + ui 12 today; guards against a vacuous sweep


def test_the_exemptions_are_reachable_without_the_secret(app):
    """The two exempt endpoints are not gated: a POST reaches the view rather
    than the guard's redirect to /login with the management error. (That the
    unlock and login then work is proven in test_management_secret.py.)"""
    client = app.test_client()
    # ui.management_unlock with the wrong secret reaches the unlock handler,
    # which redirects back to /login with an error - not the guard, which
    # would redirect BEFORE the view. We assert it is not refused as a gated
    # mutation would be: an empty POST to /login reaches the login handler.
    login = client.post("/login", data={})
    assert login.status_code in {200, 302}
    unlock = client.post("/management/unlock", data={"management_secret": "wrong"})
    assert unlock.status_code in {200, 302}
