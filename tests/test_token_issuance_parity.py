"""
Access-point parity for token issuance (#283) - the #269/#272 tripwire.

The bug class this closes: a capability exposed by N entry points, a policy
updated at N-1 of them (#73 was enforced at /token but initially forgotten
at /api/users/<u>/token, fixed in #272). Every policy so far has been
verified by hand-enumerated per-endpoint tests whose completeness was a
review property; this file makes it a suite property, following the
table-driven precedent of test_settings_plumbing_parity and
test_discovery_parity.

Two mechanisms:

1. **Call-site registry**: the set of CALL SITES of
   ``TokenService.create_token`` - ``file::enclosing_function``, found by
   AST walk, so comments cannot fool it - must equal ``ISSUANCE_SURFACES``.
   Registering files alone was not enough (#292 review round 1): a second
   function minting tokens inside an already-registered module would have
   stayed invisible, which is precisely the access-point class this file
   exists to catch. A new minting call site fails this test until it is
   registered AND takes a stance on every policy below.

2. **Policy stance matrix**: every (surface, policy) pair must be declared
   ``enforced`` or ``exempt`` in ``POLICY_STANCE``. Enforced pairs run a
   behavioral assertion against that surface; exempt pairs assert the
   exemption STILL HOLDS (with the documented reason), so silently starting
   to enforce - or silently stopping - both show up as a deliberate contract
   change, never as drift.
"""

import ast
import base64
import json
from itertools import product
from pathlib import Path

import jwt as pyjwt
import pytest

_SRC = Path(__file__).resolve().parent.parent / "src" / "nanoidp"

# The call sites allowed to mint tokens (file::enclosing_function, dotted for
# nested functions, <module> for module level). services/token.py itself (the
# definition and its internal helpers) is not a caller. If you are here
# because the call-site registry test failed: register the new site AND add a
# row per policy to POLICY_STANCE below.
ISSUANCE_SURFACES = {
    "routes/oauth.py::token": "the /token grant funnel",
    "routes/api.py::generate_token": "POST /api/users/<username>/token",
    "mcp_server/handlers_tokens.py::_tool_generate_token": "MCP generate_token",
}

POLICIES = ("mint_binding", "scope_ceiling", "resource_ceiling")

# enforced -> the behavioral assertion below must hold.
# exempt:<reason> -> the surface deliberately does not apply the policy, and
# the exemption itself is pinned.
# NOTE (#292 review): the stance strings and the behavioral test methods
# below are linked by convention, not mechanically - each "enforced" pair has
# a corresponding assertion in the surface's test class, maintained by hand.
# That is deliberate: nine combinations do not justify a mini-framework. If
# this matrix ever grows past what a reviewer can eyeball, revisit; do not
# bolt a runner onto it.
POLICY_STANCE = {
    ("routes/oauth.py::token", "mint_binding"): "enforced",
    ("routes/oauth.py::token", "scope_ceiling"): "enforced",
    ("routes/oauth.py::token", "resource_ceiling"): "enforced",
    ("routes/api.py::generate_token", "mint_binding"): "enforced",
    ("routes/api.py::generate_token", "scope_ceiling"): "exempt: the endpoint has no scope parameter at all",
    ("routes/api.py::generate_token", "resource_ceiling"): "exempt: the endpoint has no resource parameter at all",
    ("mcp_server/handlers_tokens.py::_tool_generate_token", "mint_binding"): "enforced",
    ("mcp_server/handlers_tokens.py::_tool_generate_token", "scope_ceiling"): "exempt: simulation affordance (#279 boundary)",
    ("mcp_server/handlers_tokens.py::_tool_generate_token", "resource_ceiling"): "exempt: simulation affordance (#187/#279 boundary)",
}


def _basic(client_id: str, secret: str) -> dict:
    credentials = base64.b64encode(f"{client_id}:{secret}".encode()).decode()
    return {"Authorization": f"Basic {credentials}"}


SCOPED_AUTH = _basic("scoped-client", "scoped-secret")


def _create_token_call_sites() -> set:
    """Every ``file::enclosing_function`` under src/nanoidp with a call whose
    callee is named create_token (attribute or bare), excluding
    services/token.py. The enclosing name is the dotted chain of
    FunctionDef/AsyncFunctionDef ancestors (``<module>`` at module level), so
    a SECOND minting function in an already-registered file is a new entry -
    files alone would hide it (#292 review round 1)."""
    sites = set()
    for path in sorted(_SRC.rglob("*.py")):
        rel = path.relative_to(_SRC).as_posix()
        if rel == "services/token.py":
            continue
        tree = ast.parse(path.read_text(), filename=str(path))
        _walk_for_create_token(tree, rel, [], sites)
    return sites


def _walk_for_create_token(node, rel: str, stack: list, sites: set) -> None:
    entered = isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    if entered:
        stack.append(node.name)
    if isinstance(node, ast.Call):
        callee = node.func
        name = (
            callee.attr
            if isinstance(callee, ast.Attribute)
            else callee.id if isinstance(callee, ast.Name) else None
        )
        if name == "create_token":
            enclosing = ".".join(stack) if stack else "<module>"
            sites.add(f"{rel}::{enclosing}")
    for child in ast.iter_child_nodes(node):
        _walk_for_create_token(child, rel, stack, sites)
    if entered:
        stack.pop()


class TestCallerRegistry:
    def test_create_token_call_sites_match_the_registry(self):
        found = _create_token_call_sites()
        assert found == set(ISSUANCE_SURFACES), (
            "Token-minting call sites changed. Register the site in "
            "ISSUANCE_SURFACES and declare its stance on every policy in "
            f"POLICY_STANCE. Found: {sorted(found)}"
        )

    def test_collector_sees_a_new_function_in_a_registered_file(self, tmp_path,
                                                                monkeypatch):
        """The tripwire the file-level registry lacked: a SECOND minting
        function inside an already-registered module must surface as a new
        registry entry."""
        import tests.test_token_issuance_parity as mod

        fake = tmp_path / "src"
        (fake / "routes").mkdir(parents=True)
        (fake / "routes" / "api.py").write_text(
            "def generate_token():\n"
            "    return svc.create_token(user)\n"
            "\n"
            "def sneaky_new_endpoint():\n"
            "    return svc.create_token(user)\n"
        )
        monkeypatch.setattr(mod, "_SRC", fake)
        found = _create_token_call_sites()
        assert found == {
            "routes/api.py::generate_token",
            "routes/api.py::sneaky_new_endpoint",
        }

    def test_every_surface_declares_every_policy(self):
        expected = set(product(ISSUANCE_SURFACES, POLICIES))
        assert set(POLICY_STANCE) == expected
        for pair, stance in POLICY_STANCE.items():
            assert stance == "enforced" or stance.startswith("exempt: "), pair


class TestOAuthTokenSurface:
    """routes/oauth.py: all three policies enforced."""

    def test_mint_binding_enforced(self, client):
        """A grant-minted refresh token carries the client_id binding."""
        resp = client.post(
            "/token",
            data={"grant_type": "password", "username": "admin", "password": "admin"},
            headers=SCOPED_AUTH,
        )
        assert resp.status_code == 200
        refresh = json.loads(resp.data)["refresh_token"]
        claims = pyjwt.decode(refresh, options={"verify_signature": False})
        assert claims["client_id"] == "scoped-client"

    def test_scope_ceiling_enforced(self, client):
        """scoped-client's allowed_scopes is [openid, profile]: email is
        inside the vocabulary but outside the ceiling."""
        resp = client.post(
            "/token",
            data={
                "grant_type": "password",
                "username": "admin",
                "password": "admin",
                "scope": "email",
            },
            headers=SCOPED_AUTH,
        )
        assert resp.status_code == 400
        assert json.loads(resp.data)["error"] == "invalid_scope"

    def test_resource_ceiling_enforced(self, client, app):
        from nanoidp.config import get_config

        with app.app_context():
            get_config().get_client("scoped-client").allowed_resources = [
                "https://allowed.example/api"
            ]
        try:
            resp = client.post(
                "/token",
                data={
                    "grant_type": "password",
                    "username": "admin",
                    "password": "admin",
                    "resource": "https://forbidden.example/api",
                },
                headers=SCOPED_AUTH,
            )
            assert resp.status_code == 400
            assert json.loads(resp.data)["error"] == "invalid_target"
        finally:
            with app.app_context():
                get_config().get_client("scoped-client").allowed_resources = []


class TestApiUserTokenSurface:
    """routes/api.py: binding enforced; scope/resource do not exist there."""

    def test_mint_binding_enforced(self, client):
        bound = client.post(
            "/api/users/admin/token",
            json={"client_id": "demo-client"},
        )
        assert bound.status_code == 200
        bound_data = bound.get_json()
        claims = pyjwt.decode(
            bound_data["refresh_token"], options={"verify_signature": False}
        )
        assert claims["client_id"] == "demo-client"

        unbound = client.post("/api/users/admin/token", json={})
        assert unbound.status_code == 200
        assert "refresh_token" not in unbound.get_json()

    def test_scope_exemption_still_holds(self, client):
        """The endpoint has no scope parameter: a scope key in the body is
        ignored and the minted token carries no scope claim. If this fails
        because scope IS now honoured, update POLICY_STANCE - that is a
        contract change, not a fix."""
        resp = client.post("/api/users/admin/token", json={"scope": "email admin"})
        assert resp.status_code == 200
        claims = pyjwt.decode(
            resp.get_json()["access_token"], options={"verify_signature": False}
        )
        assert "scope" not in claims

    def test_resource_exemption_still_holds(self, client):
        """Same for resource: ignored, aud stays the configured audience."""
        resp = client.post(
            "/api/users/admin/token", json={"resource": "https://x.example/api"}
        )
        assert resp.status_code == 200
        claims = pyjwt.decode(
            resp.get_json()["access_token"], options={"verify_signature": False}
        )
        assert claims["aud"] != "https://x.example/api"


class TestMcpGenerateTokenSurface:
    """mcp_server.py: binding enforced; scope/resource deliberately free
    (#279 simulation boundary - the detailed pins live in
    test_mcp.py::TestSimulationBoundary; these keep the matrix complete)."""

    async def _generate(self, arguments):
        from nanoidp.config import get_config
        from nanoidp.mcp_server import _execute_tool

        result = await _execute_tool("generate_token", arguments, get_config())
        assert result["success"] is True, result
        return result

    @pytest.mark.asyncio
    async def test_mint_binding_enforced(self, app):
        bound = await self._generate({"username": "admin", "client_id": "demo-client"})
        claims = pyjwt.decode(
            bound["refresh_token"], options={"verify_signature": False}
        )
        assert claims["client_id"] == "demo-client"

        unbound = await self._generate({"username": "admin"})
        assert "refresh_token" not in unbound

    @pytest.mark.asyncio
    async def test_scope_exemption_still_holds(self, app):
        result = await self._generate(
            {"username": "admin", "client_id": "scoped-client", "scope": "email"}
        )
        claims = pyjwt.decode(
            result["access_token"], options={"verify_signature": False}
        )
        assert claims["scope"] == "email"

    @pytest.mark.asyncio
    async def test_resource_exemption_still_holds(self, app):
        result = await self._generate(
            {
                "username": "admin",
                "client_id": "scoped-client",
                "resource": ["https://anything.example/api"],
            }
        )
        claims = pyjwt.decode(
            result["access_token"], options={"verify_signature": False}
        )
        assert claims["aud"] == "https://anything.example/api"
