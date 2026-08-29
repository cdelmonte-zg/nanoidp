"""
Branch coverage for the _tool_* MCP handlers (#222).

mcp_server.py sat at 75% statement coverage: the wire-level tests proved
the dispatch and guard machinery, but most handlers' domain-failure
branches (user/client already exists, not found) and several whole happy
paths (get_user, delete_user, list_clients, decode/verify token,
reload_config, update_settings' field branches, save_config) had no test
at all. Everything here drives the real protocol path through the
in-memory MCP client (conftest.call_mcp_tool), asserting the
{"success": False, ...} / is_error contract the module docstring pins.
"""

import json

import pytest
import yaml

from nanoidp.config import ConfigManager, ReloadAfterSaveError
from nanoidp.config_writer import ConflictError, LockUnavailableError, current_revision
from nanoidp.hooks import HookError


@pytest.fixture
def mcp_config(tmp_path, monkeypatch):
    """A ConfigManager on its own config dir, installed as the MCP singleton.

    Mirrors the pattern of tests/test_mcp.py: the MCP server keeps its own
    config global, so tests install theirs and clear the gate env vars.
    keys_dir points into tmp_path because generate_token/rotate_keys build
    a real crypto service.
    """
    import nanoidp.mcp_server as mcp

    config_dir = tmp_path / "config"
    config_dir.mkdir()
    settings = {
        "server": {"host": "127.0.0.1", "port": 8000},
        "oauth": {
            "issuer": "http://localhost:8000",
            "audience": "test-aud",
            "clients": [
                {
                    "client_id": "branch-client",
                    "client_secret": "branch-secret",
                    "description": "seed client",
                    "redirect_uris": ["https://app.example/cb"],
                    "allowed_scopes": ["openid", "profile"],
                }
            ],
        },
        "jwt": {"keys_dir": str(tmp_path / "keys")},
    }
    (config_dir / "settings.yaml").write_text(yaml.safe_dump(settings))
    (config_dir / "users.yaml").write_text(
        'users:\n  admin:\n    password: "admin"\ndefault_user: admin\n'
    )

    config = ConfigManager(str(config_dir))
    monkeypatch.setattr(mcp, "_config", config)
    monkeypatch.setattr(mcp, "_readonly_mode", False)
    monkeypatch.delenv("NANOIDP_MCP_ADMIN_SECRET", raising=False)
    monkeypatch.delenv("NANOIDP_MANAGEMENT_SECRET", raising=False)
    # generate_token goes through get_token_service(), which builds from the
    # GLOBAL config discovery, not from mcp_server's own ConfigManager (the
    # same global-vs-own coupling family as #176's B5 finding, latent in
    # production because both usually resolve the same directory). Point the
    # discovery at this test's directory so the two agree here too - and so
    # the token service can never touch the repo's ./keys.
    monkeypatch.setenv("NANOIDP_CONFIG_DIR", str(config_dir))
    return config


def _payload(result):
    return json.loads(result.content[0].text)


class TestUserToolBranches:
    @pytest.mark.asyncio
    async def test_get_user_found_and_missing(self, mcp_config, mcp_call_tool):
        found = _payload(await mcp_call_tool("get_user", {"username": "admin"}))
        assert found["found"] is True
        assert found["user"]["username"] == "admin"

        missing_result = await mcp_call_tool("get_user", {"username": "ghost"})
        missing = _payload(missing_result)
        assert missing["found"] is False
        assert missing["username"] == "ghost"

    @pytest.mark.asyncio
    async def test_create_user_duplicate_fails_without_overwrite(self, mcp_config, mcp_call_tool):
        result = await mcp_call_tool(
            "create_user", {"username": "admin", "password": "hacked"}
        )
        assert result.is_error is True
        payload = _payload(result)
        assert payload["success"] is False
        assert "already exists" in payload["error"]
        assert mcp_config.get_user("admin").password == "admin"

    @pytest.mark.asyncio
    async def test_update_user_missing_and_field_branches(self, mcp_config, mcp_call_tool):
        missing = await mcp_call_tool("update_user", {"username": "ghost", "email": "x@x"})
        assert missing.is_error is True
        assert "not found" in _payload(missing)["error"]

        updated = _payload(
            await mcp_call_tool(
                "update_user",
                {
                    "username": "admin",
                    "password": "newpw",
                    "email": "admin@new.example",
                    "roles": ["ops", "dev"],
                    "groups": ["team-a"],
                    "tenant": "acme",
                    "identity_class": "INTERNAL",
                    "entitlements": ["E1"],
                    "source_acl": ["svc-a"],
                },
            )
        )
        assert updated["success"] is True
        user = mcp_config.get_user("admin")
        assert user.password == "newpw"
        assert user.email == "admin@new.example"
        assert user.roles == ["ops", "dev"]
        assert user.groups == ["team-a"]
        assert user.tenant == "acme"
        assert user.entitlements == ["E1"]
        assert user.source_acl == ["svc-a"]

    @pytest.mark.asyncio
    async def test_delete_user_success_and_missing(self, mcp_config, mcp_call_tool):
        _payload(await mcp_call_tool("create_user", {"username": "todelete", "password": "x"}))
        deleted = _payload(await mcp_call_tool("delete_user", {"username": "todelete"}))
        assert deleted["success"] is True
        assert mcp_config.get_user("todelete") is None

        missing = await mcp_call_tool("delete_user", {"username": "todelete"})
        assert missing.is_error is True
        assert "not found" in _payload(missing)["error"]


class TestTokenToolBranches:
    @pytest.mark.asyncio
    async def test_generate_decode_and_verify_roundtrip(self, mcp_config, mcp_call_tool):
        generated = _payload(
            await mcp_call_tool("generate_token", {"username": "admin"})
        )
        token = generated["access_token"]

        decoded = _payload(await mcp_call_tool("decode_token", {"token": token}))
        assert decoded["claims"]["sub"] == "admin"

        verified = _payload(await mcp_call_tool("verify_token", {"token": token}))
        assert verified["valid"] is True
        assert verified["claims"]["sub"] == "admin"

    @pytest.mark.asyncio
    async def test_generate_token_unknown_user_fails(self, mcp_config, mcp_call_tool):
        result = await mcp_call_tool("generate_token", {"username": "ghost"})
        assert result.is_error is True
        assert "not found" in _payload(result)["error"]

    @pytest.mark.asyncio
    async def test_decode_token_garbage_is_a_clean_failure(self, mcp_config, mcp_call_tool):
        result = await mcp_call_tool("decode_token", {"token": "not-a-jwt"})
        assert result.is_error is True
        assert "Failed to decode token" in _payload(result)["error"]

    @pytest.mark.asyncio
    async def test_verify_token_garbage_is_invalid_not_a_crash(self, mcp_config, mcp_call_tool):
        result = await mcp_call_tool("verify_token", {"token": "not-a-jwt"})
        payload = _payload(result)
        assert payload.get("valid") is not True


class TestClientToolBranches:
    @pytest.mark.asyncio
    async def test_list_and_get_client(self, mcp_config, mcp_call_tool):
        listed = _payload(await mcp_call_tool("list_clients", {}))
        assert any(c["client_id"] == "branch-client" for c in listed["clients"])

        found = _payload(await mcp_call_tool("get_client", {"client_id": "branch-client"}))
        assert found["found"] is True
        assert found["client"]["allowed_scopes"] == ["openid", "profile"]

        missing = _payload(await mcp_call_tool("get_client", {"client_id": "ghost"}))
        assert missing["found"] is False

    @pytest.mark.asyncio
    async def test_create_client_duplicate_fails(self, mcp_config, mcp_call_tool):
        result = await mcp_call_tool(
            "create_client", {"client_id": "branch-client", "client_secret": "other"}
        )
        assert result.is_error is True
        assert "already exists" in _payload(result)["error"]
        assert mcp_config.get_client("branch-client").client_secret == "branch-secret"

    @pytest.mark.asyncio
    async def test_update_client_missing_and_field_branches(self, mcp_config, mcp_call_tool):
        missing = await mcp_call_tool("update_client", {"client_id": "ghost", "description": "x"})
        assert missing.is_error is True
        assert "not found" in _payload(missing)["error"]

        updated = _payload(
            await mcp_call_tool(
                "update_client",
                {
                    "client_id": "branch-client",
                    "client_secret": "rotated",
                    "description": "edited",
                    "additional_audiences": ["aud-x"],
                    "redirect_uris": ["https://other.example/cb"],
                    "allowed_scopes": ["openid"],
                    "allowed_resources": ["https://mcp.example/server"],
                    "background_color": "#112233",
                    "header_color": "#445566",
                    "footer_color": "#778899",
                    "show_client_id": True,
                    "show_description": True,
                },
            )
        )
        assert updated["success"] is True
        client = mcp_config.get_client("branch-client")
        assert client.client_secret == "rotated"
        assert client.description == "edited"
        assert client.additional_audiences == ["aud-x"]
        assert client.redirect_uris == ["https://other.example/cb"]
        assert client.allowed_scopes == ["openid"]
        assert client.allowed_resources == ["https://mcp.example/server"]
        assert client.background_color == "#112233"
        assert client.header_color == "#445566"
        assert client.footer_color == "#778899"
        assert client.show_client_id is True
        assert client.show_description is True

    @pytest.mark.asyncio
    async def test_delete_client_success_and_missing(self, mcp_config, mcp_call_tool):
        deleted = _payload(await mcp_call_tool("delete_client", {"client_id": "branch-client"}))
        assert deleted["success"] is True
        assert mcp_config.get_client("branch-client") is None

        missing = await mcp_call_tool("delete_client", {"client_id": "branch-client"})
        assert missing.is_error is True
        assert "not found" in _payload(missing)["error"]


class TestConfigToolBranches:
    @pytest.mark.asyncio
    async def test_reload_config_succeeds(self, mcp_config, mcp_call_tool):
        payload = _payload(await mcp_call_tool("reload_config", {}))
        assert payload["success"] is True

    @pytest.mark.asyncio
    async def test_update_settings_field_branches(self, mcp_config, mcp_call_tool):
        payload = _payload(
            await mcp_call_tool(
                "update_settings",
                {
                    "issuer": "http://idp.example:9000",
                    "issuer_from_request": True,
                    "issuer_allowlist": ["http://idp.example:9000"],
                    "device_verification_base_url": "http://idp.example:9000",
                    "issuer_from_proxy_headers": True,
                    "audience": "new-aud",
                    "token_expiry_minutes": 12,
                    "saml_entity_id": "http://idp.example:9000/saml/metadata",
                    "saml_sso_url": "http://idp.example:9000/saml/sso",
                    "saml_sign_responses": False,
                    "saml_export_roles": True,
                    "saml_export_groups": True,
                    "saml_roles_attr_name": "memberOf",
                    "saml_groups_attr_name": "memberOf",
                    "saml_c14n_algorithm": "c14n",
                    "saml_want_authn_requests_signed": False,
                    "saml_sp_certificates": [],
                    "strict_saml_binding": True,
                    "verbose_logging": False,
                    "refresh_token_rotation": True,
                    "require_pkce": True,
                },
            )
        )
        assert payload["success"] is True
        settings = mcp_config.settings
        assert settings.issuer == "http://idp.example:9000"
        assert settings.audience == "new-aud"
        assert settings.token_expiry_minutes == 12
        assert settings.require_pkce is True
        assert settings.refresh_token_rotation is True
        assert settings.verbose_logging is False
        assert settings.saml_roles_attr_name == "memberOf"
        assert settings.strict_saml_binding is True

    @pytest.mark.asyncio
    async def test_save_config_writes_yaml(self, mcp_config, mcp_call_tool):
        _payload(await mcp_call_tool("update_settings", {"audience": "saved-aud"}))
        payload = _payload(await mcp_call_tool("save_config", {}))
        assert payload["success"] is True
        saved = yaml.safe_load((mcp_config.config_dir / "settings.yaml").read_text())
        assert saved["oauth"]["audience"] == "saved-aud"

    @pytest.mark.asyncio
    async def test_save_config_failure_is_a_clean_error(
        self, mcp_config, mcp_call_tool, monkeypatch
    ):
        def _failing_save(**kwargs):
            raise OSError("disk full")

        monkeypatch.setattr(mcp_config, "save", _failing_save)
        result = await mcp_call_tool("save_config", {})
        assert result.is_error is True
        payload = _payload(result)
        assert payload["success"] is False
        assert "Failed to save config" in payload["error"]

    @pytest.mark.asyncio
    async def test_save_config_conflict_is_distinguishable(
        self, mcp_config, mcp_call_tool, monkeypatch
    ):
        """#229 review, blocking 3: a caller must be able to tell "nothing
        was written" (ConflictError) apart from the other two save()
        failure modes by more than the free-text error message."""

        def _failing_save(**kwargs):
            raise ConflictError("settings.yaml changed since it was last read")

        monkeypatch.setattr(mcp_config, "save", _failing_save)
        result = await mcp_call_tool("save_config", {})
        assert result.is_error is True
        payload = _payload(result)
        assert payload["success"] is False
        assert payload["kind"] == "conflict"

    @pytest.mark.asyncio
    async def test_save_config_hook_failure_is_distinguishable(
        self, mcp_config, mcp_call_tool, monkeypatch
    ):
        """#229 review, blocking 3: both files ARE written when only the
        mirror hook fails - the error text says so, and 'kind' carries
        the hook's own kind rather than a generic one."""

        def _failing_save(**kwargs):
            raise HookError("on_config_saved shell hook exited 1", kind="on_config_saved")

        monkeypatch.setattr(mcp_config, "save", _failing_save)
        result = await mcp_call_tool("save_config", {})
        assert result.is_error is True
        payload = _payload(result)
        assert payload["success"] is False
        assert payload["kind"] == "on_config_saved"
        assert "mirror failed" in payload["error"]

    @pytest.mark.asyncio
    async def test_save_config_reload_after_save_is_distinguishable(
        self, mcp_config, mcp_call_tool, monkeypatch
    ):
        """#229 review, blocking 3: the write succeeded but the runtime
        could not adopt it - a distinct 'kind' so a caller does not
        mistake this for "nothing was written" and retry expecting a
        different outcome."""

        def _failing_save(**kwargs):
            raise ReloadAfterSaveError("runtime could not reload settings.yaml")

        monkeypatch.setattr(mcp_config, "save", _failing_save)
        result = await mcp_call_tool("save_config", {})
        assert result.is_error is True
        payload = _payload(result)
        assert payload["success"] is False
        assert payload["kind"] == "reload_after_save"

    @pytest.mark.asyncio
    async def test_save_config_lock_unavailable_is_distinguishable(
        self, mcp_config, mcp_call_tool, monkeypatch
    ):
        """#229 review, blocking 4: LockUnavailableError is raised before
        compare_and_replace_many touches any file - it belongs with
        ConflictError as "nothing was written", not with
        ReloadAfterSaveError's "already written" - and the handler must
        actually catch it rather than falling through to the generic
        branch, which would drop 'kind' entirely."""

        def _failing_save(**kwargs):
            raise LockUnavailableError(
                "Timed out after 10.0s waiting for the write lock", kind="lock_timeout"
            )

        monkeypatch.setattr(mcp_config, "save", _failing_save)
        result = await mcp_call_tool("save_config", {})
        assert result.is_error is True
        payload = _payload(result)
        assert payload["success"] is False
        assert payload["kind"] == "lock_timeout"

    @pytest.mark.asyncio
    async def test_get_jwks_serves_the_active_key(self, mcp_config, mcp_call_tool):
        jwks = _payload(await mcp_call_tool("get_jwks", {}))
        assert jwks["keys"]
        info = _payload(await mcp_call_tool("get_keys_info", {}))
        assert any(k["kid"] == info["active_kid"] for k in jwks["keys"])

    @pytest.mark.asyncio
    async def test_keys_info_and_rotation(self, mcp_config, mcp_call_tool):
        info = _payload(await mcp_call_tool("get_keys_info", {}))
        kid_before = info["active_kid"]

        rotated = _payload(await mcp_call_tool("rotate_keys", {}))
        assert rotated["success"] is True
        assert rotated["new_kid"] != kid_before


class TestRevisionPreconditions:
    """#229 phase 5: the read tools hand out the revisions the runtime was
    loaded from, and save_config accepts them as optional preconditions -
    the MCP leg of the same read -> mutate -> conflict-checked-save loop
    the web UI's forms got in phase 4."""

    @pytest.mark.asyncio
    async def test_read_tools_expose_the_loaded_revisions(
        self, mcp_config, mcp_call_tool
    ):
        users_rev = mcp_config.users_revision
        settings_rev = mcp_config.settings_revision

        assert _payload(await mcp_call_tool("list_users", {}))["users_revision"] == users_rev
        found = _payload(await mcp_call_tool("get_user", {"username": "admin"}))
        assert found["users_revision"] == users_rev
        # The not-found branch carries it too: get_user -> create_user ->
        # save_config is "create only if the file still looks like it did
        # when I saw them absent".
        absent = _payload(await mcp_call_tool("get_user", {"username": "nobody"}))
        assert absent["found"] is False
        assert absent["users_revision"] == users_rev

        assert (
            _payload(await mcp_call_tool("list_clients", {}))["settings_revision"]
            == settings_rev
        )
        client = _payload(await mcp_call_tool("get_client", {"client_id": "branch-client"}))
        assert client["settings_revision"] == settings_rev
        no_client = _payload(await mcp_call_tool("get_client", {"client_id": "ghost"}))
        assert no_client["found"] is False
        assert no_client["settings_revision"] == settings_rev

        assert (
            _payload(await mcp_call_tool("get_settings", {}))["settings_revision"]
            == settings_rev
        )

    @pytest.mark.asyncio
    async def test_reload_config_hands_back_fresh_revisions(
        self, mcp_config, mcp_call_tool
    ):
        settings_file = mcp_config.config_dir / "settings.yaml"
        settings_file.write_text(settings_file.read_text() + "\n# another writer\n")

        payload = _payload(await mcp_call_tool("reload_config", {}))

        assert payload["success"] is True
        assert payload["settings_revision"] == current_revision(settings_file)
        assert payload["users_revision"] == current_revision(
            mcp_config.config_dir / "users.yaml"
        )

    @pytest.mark.asyncio
    async def test_save_config_with_fresh_revisions_succeeds_and_chains(
        self, mcp_config, mcp_call_tool
    ):
        _payload(await mcp_call_tool("update_settings", {"audience": "rev-aud"}))
        payload = _payload(
            await mcp_call_tool(
                "save_config",
                {
                    "expected_users_revision": mcp_config.users_revision,
                    "expected_settings_revision": mcp_config.settings_revision,
                },
            )
        )

        assert payload["success"] is True
        saved = yaml.safe_load((mcp_config.config_dir / "settings.yaml").read_text())
        assert saved["oauth"]["audience"] == "rev-aud"
        # The response's revisions describe what was just written, so a
        # follow-up save can chain from them without another read call.
        assert payload["settings_revision"] == current_revision(
            mcp_config.config_dir / "settings.yaml"
        )
        assert payload["users_revision"] == current_revision(
            mcp_config.config_dir / "users.yaml"
        )

    @pytest.mark.asyncio
    async def test_save_config_with_a_stale_revision_is_refused_writing_nothing(
        self, mcp_config, mcp_call_tool
    ):
        """The real two-writer path, no monkeypatching: another writer
        moves users.yaml after this runtime loaded; a save carrying the
        loaded revision must be refused with kind 'conflict' and leave
        BOTH files exactly as that writer left them."""
        loaded_users_rev = mcp_config.users_revision
        users_file = mcp_config.config_dir / "users.yaml"
        settings_file = mcp_config.config_dir / "settings.yaml"
        users_file.write_text(users_file.read_text() + "\n# another writer\n")
        users_before = users_file.read_bytes()
        settings_before = settings_file.read_bytes()

        _payload(await mcp_call_tool("update_settings", {"audience": "must-not-land"}))
        result = await mcp_call_tool(
            "save_config", {"expected_users_revision": loaded_users_rev}
        )

        assert result.is_error is True
        payload = _payload(result)
        assert payload["success"] is False
        assert payload["kind"] == "conflict"
        assert users_file.read_bytes() == users_before
        assert settings_file.read_bytes() == settings_before

    @pytest.mark.asyncio
    async def test_a_users_only_guard_still_protects_settings(
        self, mcp_config, mcp_call_tool
    ):
        """#252 review blocker: save_config always writes BOTH files, so a
        caller following the natural flow (get_user -> mutate user ->
        save with only expected_users_revision) must not have its stale
        settings snapshot silently overwrite a settings.yaml another
        writer - one that touches only that file, like the UI's settings
        form - changed in the meantime. Supplying either revision makes
        the whole save conflict-checked; the omitted one defaults to the
        runtime's loaded revision."""
        loaded_users_rev = mcp_config.users_revision
        users_file = mcp_config.config_dir / "users.yaml"
        settings_file = mcp_config.config_dir / "settings.yaml"

        # Another writer moves ONLY settings.yaml; users.yaml still
        # matches the revision this runtime loaded.
        settings_file.write_text(settings_file.read_text() + "\n# settings-only writer\n")
        users_before = users_file.read_bytes()
        settings_before = settings_file.read_bytes()

        _payload(
            await mcp_call_tool(
                "create_user", {"username": "cross-user", "password": "pw12345"}
            )
        )
        result = await mcp_call_tool(
            "save_config", {"expected_users_revision": loaded_users_rev}
        )

        assert result.is_error is True
        payload = _payload(result)
        assert payload["success"] is False
        assert payload["kind"] == "conflict"
        assert users_file.read_bytes() == users_before
        assert settings_file.read_bytes() == settings_before

    @pytest.mark.asyncio
    async def test_a_settings_only_guard_still_protects_users(
        self, mcp_config, mcp_call_tool
    ):
        """The symmetric leg: a save guarded only on settings.yaml must
        not overwrite a users.yaml another writer changed."""
        loaded_settings_rev = mcp_config.settings_revision
        users_file = mcp_config.config_dir / "users.yaml"
        settings_file = mcp_config.config_dir / "settings.yaml"

        users_file.write_text(users_file.read_text() + "\n# users-only writer\n")
        users_before = users_file.read_bytes()
        settings_before = settings_file.read_bytes()

        _payload(await mcp_call_tool("update_settings", {"audience": "must-not-land"}))
        result = await mcp_call_tool(
            "save_config", {"expected_settings_revision": loaded_settings_rev}
        )

        assert result.is_error is True
        payload = _payload(result)
        assert payload["success"] is False
        assert payload["kind"] == "conflict"
        assert users_file.read_bytes() == users_before
        assert settings_file.read_bytes() == settings_before


class TestPublicClientTools:
    """#188: the MCP client tools handle token_endpoint_auth_method,
    including the secret/method interplay that must never half-update."""

    @pytest.mark.asyncio
    async def test_create_public_client_needs_no_secret(self, mcp_config, mcp_call_tool):
        payload = _payload(
            await mcp_call_tool(
                "create_client",
                {"client_id": "pub-mcp", "token_endpoint_auth_method": "none"},
            )
        )
        assert payload["success"] is True
        assert payload["client"]["token_endpoint_auth_method"] == "none"
        assert "client_secret" not in payload["client"]
        assert mcp_config.get_client("pub-mcp").is_public is True

    @pytest.mark.asyncio
    async def test_create_confidential_client_without_secret_is_refused(
        self, mcp_config, mcp_call_tool
    ):
        result = await mcp_call_tool("create_client", {"client_id": "no-secret"})
        payload = _payload(result)
        assert payload["success"] is False
        assert "client_secret is required" in payload["error"]
        assert mcp_config.get_client("no-secret") is None

    @pytest.mark.asyncio
    async def test_invalid_auth_method_rejects_before_any_mutation(
        self, mcp_config, mcp_call_tool
    ):
        result = await mcp_call_tool(
            "update_client",
            {
                "client_id": "branch-client",
                "description": "must-not-land",
                "token_endpoint_auth_method": "client_secret_jwt",
            },
        )
        assert result.is_error is True
        client = mcp_config.get_client("branch-client")
        assert client.description != "must-not-land"

    @pytest.mark.asyncio
    async def test_create_none_with_a_secret_stores_no_secret(
        self, mcp_config, mcp_call_tool
    ):
        """#254 review: a public client keeps no secret, so a supplied one on
        create is dropped (parity with the UI create form)."""
        _payload(
            await mcp_call_tool(
                "create_client",
                {
                    "client_id": "pub-drop",
                    "token_endpoint_auth_method": "none",
                    "client_secret": "should-be-dropped",
                },
            )
        )
        assert mcp_config.get_client("pub-drop").client_secret is None

    @pytest.mark.asyncio
    async def test_update_to_none_drops_the_existing_secret(
        self, mcp_config, mcp_call_tool
    ):
        _payload(
            await mcp_call_tool(
                "update_client",
                {"client_id": "branch-client", "token_endpoint_auth_method": "none"},
            )
        )
        assert mcp_config.get_client("branch-client").client_secret is None

    @pytest.mark.asyncio
    async def test_update_already_public_with_a_secret_stays_secretless(
        self, mcp_config, mcp_call_tool
    ):
        """A secret supplied to an already-public client must not be stored."""
        _payload(
            await mcp_call_tool(
                "create_client",
                {"client_id": "pub-stay", "token_endpoint_auth_method": "none"},
            )
        )
        _payload(
            await mcp_call_tool(
                "update_client", {"client_id": "pub-stay", "client_secret": "sneaky"}
            )
        )
        assert mcp_config.get_client("pub-stay").client_secret is None

    @pytest.mark.asyncio
    async def test_switch_to_none_then_back_requires_a_secret(
        self, mcp_config, mcp_call_tool
    ):
        payload = _payload(
            await mcp_call_tool(
                "update_client",
                {"client_id": "branch-client", "token_endpoint_auth_method": "none"},
            )
        )
        assert payload["success"] is True

        # Back to confidential WITHOUT a secret: refused before any
        # assignment, the client stays public and fully intact.
        refused = _payload(
            await mcp_call_tool(
                "update_client",
                {
                    "client_id": "branch-client",
                    "token_endpoint_auth_method": "client_secret_basic",
                    "client_secret": "",
                },
            )
        )
        assert refused["success"] is False
        assert mcp_config.get_client("branch-client").is_public is True

        # With a secret in the same call it works (secret assigned first).
        back = _payload(
            await mcp_call_tool(
                "update_client",
                {
                    "client_id": "branch-client",
                    "token_endpoint_auth_method": "client_secret_basic",
                    "client_secret": "fresh-secret",
                },
            )
        )
        assert back["success"] is True
        assert mcp_config.get_client("branch-client").is_public is False


class TestDispatchGuards:
    @pytest.mark.asyncio
    async def test_readonly_mode_rejects_mutating_tool(
        self, mcp_config, mcp_call_tool, monkeypatch
    ):
        import nanoidp.mcp_server as mcp

        monkeypatch.setattr(mcp, "_readonly_mode", True)
        result = await mcp_call_tool("create_user", {"username": "x", "password": "y"})
        assert result.is_error is True
        payload = _payload(result)
        assert payload["code"] == "MCP_READONLY_MODE"
        assert mcp_config.get_user("x") is None

    @pytest.mark.asyncio
    async def test_execute_tool_unknown_name_raises(self, mcp_config):
        """The dispatcher's unreachable-on-protocol-path contract: a direct
        mis-call raises instead of returning a divergent error shape."""
        from nanoidp.mcp_server import _execute_tool

        with pytest.raises(ValueError, match="Unknown tool"):
            await _execute_tool("no-such-tool", {}, mcp_config)
