"""
Tests for first-class group support: the ``groups`` user field, its ``groups``
claim, the ``GROUP_`` authorities it produces, and the admin surfaces (UI, REST
API, MCP) that read and write it.

SAML export of roles/groups is covered in ``test_saml.py`` because it depends on
the ``roles_attr_name``/``groups_attr_name`` settings.
"""

import json

import jwt as pyjwt
import pytest

from nanoidp.config import ConfigManager, User, get_config
from nanoidp.serialization import user_to_yaml
from nanoidp.services.token import get_token_service, resolve_user_claim

SETTINGS_YAML = """
server:
  host: "0.0.0.0"
  port: 8000

oauth:
  issuer: "http://localhost:8000"
  clients:
    - client_id: "test"
      client_secret: "test"

authority_prefixes:
  roles: "ROLE_"
  groups: "GROUP_"
"""


def _write_config(config_dir, users_yaml: str) -> ConfigManager:
    config_dir.mkdir(exist_ok=True)
    (config_dir / "settings.yaml").write_text(SETTINGS_YAML)
    (config_dir / "users.yaml").write_text(users_yaml)
    return ConfigManager(str(config_dir))


class TestGroupsModel:
    """The ``groups`` field itself."""

    def test_groups_default_to_empty_list(self):
        user = User(username="u", password="p")
        assert user.groups == []

    def test_groups_round_trip(self):
        user = User(username="u", password="p", groups=["ENGINEERING", "FINANCE"])
        assert user.groups == ["ENGINEERING", "FINANCE"]

    def test_to_dict_includes_groups(self):
        user = User(username="u", password="p", groups=["ENGINEERING"])
        assert user.to_dict()["groups"] == ["ENGINEERING"]


class TestGroupsConfigLoading:
    """Loading ``groups`` out of users.yaml."""

    def test_groups_are_loaded(self, tmp_path):
        config = _write_config(tmp_path / "config", """
users:
  alice:
    password: "pw"
    groups:
      - "ENGINEERING"
      - "ONCALL"
default_user: alice
""")
        assert config.get_user("alice").groups == ["ENGINEERING", "ONCALL"]

    def test_groups_default_to_empty_when_absent(self, tmp_path):
        config = _write_config(tmp_path / "config", """
users:
  alice:
    password: "pw"
default_user: alice
""")
        assert config.get_user("alice").groups == []

    def test_groups_do_not_leak_into_attributes(self, tmp_path):
        """``groups`` is a known field, so it must not fall into the custom
        attribute catch-all (which would also add it to authorities twice)."""
        config = _write_config(tmp_path / "config", """
users:
  alice:
    password: "pw"
    groups:
      - "ENGINEERING"
default_user: alice
""")
        assert "groups" not in config.get_user("alice").attributes

    def test_default_prefixes_include_groups(self, app):
        with app.app_context():
            prefixes = get_config().settings.authority_prefixes
        assert prefixes.get("groups") == "GROUP_"


class TestGroupsSerialization:
    """``user_to_yaml`` stays sparse, like it is for roles."""

    def test_groups_written_when_set(self):
        entry = user_to_yaml(User(username="u", password="p", groups=["ENGINEERING"]))
        assert entry["groups"] == ["ENGINEERING"]

    def test_groups_omitted_when_empty(self):
        entry = user_to_yaml(User(username="u", password="p"))
        assert "groups" not in entry


class TestGroupsAuthorities:
    """``GROUP_`` authorities, mirroring ``ROLE_``."""

    @pytest.fixture
    def token_service(self, app):
        with app.app_context():
            return get_token_service()

    def test_groups_get_group_prefix(self, token_service, app):
        user = User(username="u", password="p", groups=["engineering", "ONCALL"])
        with app.app_context():
            authorities = token_service.build_authorities(user)

        assert "GROUP_ENGINEERING" in authorities
        assert "GROUP_ONCALL" in authorities

    def test_roles_and_groups_coexist(self, token_service, app):
        user = User(username="u", password="p", roles=["ADMIN"], groups=["ENGINEERING"])
        with app.app_context():
            authorities = token_service.build_authorities(user)

        assert "ROLE_ADMIN" in authorities
        assert "GROUP_ENGINEERING" in authorities

    def test_no_groups_no_group_authorities(self, token_service, app):
        user = User(username="u", password="p", roles=["ADMIN"])
        with app.app_context():
            authorities = token_service.build_authorities(user)

        assert not [a for a in authorities if a.startswith("GROUP_")]


class TestGroupsClaim:
    """The ``groups`` claim on tokens, /userinfo and discovery."""

    @pytest.fixture
    def token_service(self, app):
        with app.app_context():
            return get_token_service()

    def test_access_token_contains_groups(self, token_service, app):
        user = User(username="u", password="p", groups=["ENGINEERING"])
        with app.app_context():
            result = token_service.create_token(user)

        decoded = pyjwt.decode(result["access_token"], options={"verify_signature": False})
        assert decoded["groups"] == ["ENGINEERING"]

    def test_access_token_omits_empty_groups(self, token_service, app):
        user = User(username="u", password="p")
        with app.app_context():
            result = token_service.create_token(user)

        decoded = pyjwt.decode(result["access_token"], options={"verify_signature": False})
        assert "groups" not in decoded

    def test_resolve_user_claim_returns_groups(self):
        user = User(username="u", password="p", groups=["ENGINEERING"])
        assert resolve_user_claim(user, "groups") == (True, ["ENGINEERING"])

    def test_resolve_user_claim_skips_empty_groups(self):
        """Voluntary claims are omitted rather than emitted as null (§5.5.1)."""
        assert resolve_user_claim(User(username="u", password="p"), "groups") == (False, None)

    def test_id_token_carries_requested_groups_claim(self, token_service, app):
        user = User(username="u", password="p", groups=["ENGINEERING"])
        with app.app_context():
            result = token_service.create_token(
                user, scope="openid", id_token_claims=["groups"]
            )

        decoded = pyjwt.decode(result["id_token"], options={"verify_signature": False})
        assert decoded["groups"] == ["ENGINEERING"]

    def test_discovery_advertises_groups(self, client):
        doc = json.loads(client.get("/.well-known/openid-configuration").data)
        assert "groups" in doc["claims_supported"]

    def test_userinfo_returns_groups(self, client, bearer_header):
        response = client.get("/userinfo", headers=bearer_header)
        assert response.status_code == 200
        data = json.loads(response.data)
        # The bundled admin user is in groups, so the claim must be present.
        assert "groups" in data
        assert isinstance(data["groups"], list)


class TestGroupsRestApi:
    def test_user_list_includes_groups(self, client):
        data = json.loads(client.get("/api/users").data)
        assert all("groups" in u for u in data["users"])

    def test_user_detail_includes_groups(self, client):
        data = json.loads(client.get("/api/users/admin").data)
        assert data["groups"] == ["ADMINISTRATORS", "EVERYONE"]


class TestGroupsUi:
    """Group editing through the admin UI."""

    def _form(self, **overrides) -> dict:
        form = {
            "username": "groupuser",
            "password": "pw",
            "email": "groupuser@example.org",
            "roles": "USER",
            "groups": "ENGINEERING, ONCALL",
            "tenant": "default",
        }
        form.update(overrides)
        return form

    def test_create_user_parses_groups(self, client, preserve_config_files):
        with client.session_transaction() as sess:
            sess["user"] = "admin"

        response = client.post("/users/create", data=self._form(), follow_redirects=True)
        assert response.status_code == 200
        assert get_config().get_user("groupuser").groups == ["ENGINEERING", "ONCALL"]

    def test_edit_user_updates_groups(self, client, preserve_config_files):
        with client.session_transaction() as sess:
            sess["user"] = "admin"

        client.post("/users/create", data=self._form(), follow_redirects=True)
        response = client.post(
            "/users/groupuser/edit",
            data=self._form(groups="FINANCE"),
            follow_redirects=True,
        )
        assert response.status_code == 200
        assert get_config().get_user("groupuser").groups == ["FINANCE"]

    def test_edit_user_can_clear_groups(self, client, preserve_config_files):
        with client.session_transaction() as sess:
            sess["user"] = "admin"

        client.post("/users/create", data=self._form(), follow_redirects=True)
        client.post(
            "/users/groupuser/edit", data=self._form(groups=""), follow_redirects=True
        )
        assert get_config().get_user("groupuser").groups == []

    def test_user_form_renders_groups_field(self, client):
        with client.session_transaction() as sess:
            sess["user"] = "admin"
        response = client.get("/users/create")
        assert response.status_code == 200
        assert b'name="groups"' in response.data

    def test_user_detail_renders_groups(self, client):
        with client.session_transaction() as sess:
            sess["user"] = "admin"
        response = client.get("/users/admin")
        assert response.status_code == 200
        assert b"ADMINISTRATORS" in response.data

    def test_claims_preview_includes_groups(self, client):
        with client.session_transaction() as sess:
            sess["user"] = "admin"
        data = json.loads(client.get("/claims/preview/admin").data)
        assert data["claims"]["groups"] == ["ADMINISTRATORS", "EVERYONE"]
        assert "GROUP_ADMINISTRATORS" in data["authorities"]

    def test_claims_page_offers_groups_prefix(self, client):
        with client.session_transaction() as sess:
            sess["user"] = "admin"
        response = client.get("/claims")
        assert response.status_code == 200
        assert b'name="prefix_groups"' in response.data


class TestGroupsMcp:
    """MCP create_user/update_user handle groups."""

    @pytest.fixture
    def config(self, tmp_path):
        return _write_config(tmp_path / "config", """
users:
  admin:
    password: "admin"
default_user: admin
""")

    @pytest.mark.asyncio
    async def test_create_user_with_groups(self, config):
        from nanoidp.mcp_server import _execute_tool

        result = await _execute_tool(
            "create_user",
            {"username": "alice", "password": "pw", "groups": ["ENGINEERING"]},
            config,
        )
        assert result["success"] is True
        assert result["user"]["groups"] == ["ENGINEERING"]

    @pytest.mark.asyncio
    async def test_create_user_defaults_to_no_groups(self, config):
        from nanoidp.mcp_server import _execute_tool

        result = await _execute_tool(
            "create_user", {"username": "alice", "password": "pw"}, config
        )
        assert result["user"]["groups"] == []

    @pytest.mark.asyncio
    async def test_update_user_replaces_groups(self, config):
        from nanoidp.mcp_server import _execute_tool

        await _execute_tool(
            "create_user",
            {"username": "alice", "password": "pw", "groups": ["ENGINEERING"]},
            config,
        )
        result = await _execute_tool(
            "update_user", {"username": "alice", "groups": ["FINANCE"]}, config
        )
        assert result["user"]["groups"] == ["FINANCE"]
        assert config.get_user("alice").groups == ["FINANCE"]
