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

1. **Caller registry**: the set of modules that call
   ``TokenService.create_token`` (found by AST walk, not grep, so comments
   cannot fool it) must equal ``ISSUANCE_SURFACES``. Adding a fourth minting
   surface fails this test until the surface is registered AND takes a
   stance on every policy below.

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

# The modules allowed to mint tokens, i.e. to call TokenService.create_token.
# services/token.py itself (the definition and its internal helpers) is not a
# caller. If you are here because the caller-registry test failed: register
# the new surface AND add a row per policy to POLICY_STANCE below.
ISSUANCE_SURFACES = {
    "routes/oauth.py": "the /token grant funnel",
    "routes/api.py": "POST /api/users/<username>/token",
    "mcp_server.py": "MCP generate_token",
}

POLICIES = ("mint_binding", "scope_ceiling", "resource_ceiling")

# enforced -> the behavioral assertion below must hold.
# exempt:<reason> -> the surface deliberately does not apply the policy, and
# the exemption itself is pinned.
POLICY_STANCE = {
    ("routes/oauth.py", "mint_binding"): "enforced",
    ("routes/oauth.py", "scope_ceiling"): "enforced",
    ("routes/oauth.py", "resource_ceiling"): "enforced",
    ("routes/api.py", "mint_binding"): "enforced",
    ("routes/api.py", "scope_ceiling"): "exempt: the endpoint has no scope parameter at all",
    ("routes/api.py", "resource_ceiling"): "exempt: the endpoint has no resource parameter at all",
    ("mcp_server.py", "mint_binding"): "enforced",
    ("mcp_server.py", "scope_ceiling"): "exempt: simulation affordance (#279 boundary)",
    ("mcp_server.py", "resource_ceiling"): "exempt: simulation affordance (#187/#279 boundary)",
}


def _basic(client_id: str, secret: str) -> dict:
    credentials = base64.b64encode(f"{client_id}:{secret}".encode()).decode()
    return {"Authorization": f"Basic {credentials}"}


SCOPED_AUTH = _basic("scoped-client", "scoped-secret")


def _create_token_caller_files() -> set:
    """Every file under src/nanoidp with a call whose callee is named
    create_token (attribute or bare), excluding services/token.py."""
    callers = set()
    for path in sorted(_SRC.rglob("*.py")):
        rel = path.relative_to(_SRC).as_posix()
        if rel == "services/token.py":
            continue
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                callee = node.func
                name = (
                    callee.attr
                    if isinstance(callee, ast.Attribute)
                    else callee.id if isinstance(callee, ast.Name) else None
                )
                if name == "create_token":
                    callers.add(rel)
    return callers


class TestCallerRegistry:
    def test_create_token_callers_match_the_registry(self):
        found = _create_token_caller_files()
        assert found == set(ISSUANCE_SURFACES), (
            "Token-issuing surfaces changed. Register the surface in "
            "ISSUANCE_SURFACES and declare its stance on every policy in "
            f"POLICY_STANCE. Found: {sorted(found)}"
        )

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
