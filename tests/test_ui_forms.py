"""
Unit tests for the routes/ui.py form flows (#213).

These flows were covered almost only by examples/test_agent.py, which CI
runs without a management secret; that is exactly the blind spot where a
mutation that 302s to /login can pass a status-code-only assertion (the
PR #176 round-3 finding). Every mutating test here therefore asserts on
the resulting state (the user/client/setting actually changed, or
actually did not), never only on the redirect.

The bare `app`/`client` fixtures from conftest.py operate on a throwaway
copy of the repo's config/ directory (see isolated_repo_config), so
mutations are safe and the preset users (admin/admin) and clients
(demo-client) are available.
"""

import json
import shutil
from pathlib import Path

import pytest
import yaml

from nanoidp.app import create_app
from nanoidp.config import get_config

_REPO_CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"


def _make_app(tmp_path, session_overrides=None):
    """An app on its own copied config dir, optionally with gate settings.

    jwt.keys_dir always points into tmp_path: create_app eagerly initializes
    the crypto service at settings.keys_dir, which is cwd-relative (./keys)
    in the preset - without the override every app built here would generate
    or rotate key material in the repo's own gitignored keys/ directory.
    """
    cfg = tmp_path / "cfg"
    cfg.mkdir(exist_ok=True)
    for name in ("settings.yaml", "users.yaml"):
        shutil.copy(_REPO_CONFIG_DIR / name, cfg / name)
    data = yaml.safe_load((cfg / "settings.yaml").read_text())
    data.setdefault("jwt", {})["keys_dir"] = str(tmp_path / "keys")
    if session_overrides:
        data.setdefault("session", {}).update(session_overrides)
    (cfg / "settings.yaml").write_text(yaml.safe_dump(data))
    app = create_app(config_dir=str(cfg))
    app.config["TESTING"] = True
    return app


def _login(client, username="admin", password="admin"):
    return client.post(
        "/login", data={"username": username, "password": password}, follow_redirects=False
    )


def _get_client_by_id(app, client_id):
    with app.app_context():
        for c in get_config().settings.clients:
            if c.client_id == client_id:
                return c
    return None


class TestLoginLogout:
    def test_login_success_sets_session(self, client):
        resp = _login(client)
        assert resp.status_code == 302
        assert "/login" not in resp.headers["Location"]
        with client.session_transaction() as sess:
            assert sess["user"] == "admin"
            assert sess["auth_method"] == "password"

    def test_login_wrong_password_no_session(self, client):
        resp = _login(client, password="nope")
        assert resp.status_code == 302
        assert "error=" in resp.headers["Location"]
        with client.session_transaction() as sess:
            assert "user" not in sess

    def test_login_missing_fields_redirects_with_error(self, client):
        resp = client.post("/login", data={"username": "admin"})
        assert resp.status_code == 302
        assert "error=" in resp.headers["Location"]
        with client.session_transaction() as sess:
            assert "user" not in sess

    def test_logout_clears_session(self, client):
        # /logout is handled by oauth_bp's OIDC end-session endpoint, which
        # shadows the ui.logout route entirely (both register the same rule;
        # oauth_bp wins). ui.logout is unreachable dead code - a known
        # non-blocking finding from the #176 review. What matters to the UI
        # is the observable contract: hitting /logout drops the session.
        # The status is deliberately loose (200 today, 302 if the shadowing
        # is ever fixed and ui.logout's redirect takes over).
        _login(client)
        resp = client.get("/logout")
        assert resp.status_code in (200, 302)
        with client.session_transaction() as sess:
            assert "user" not in sess


class TestUserForms:
    def test_create_user_persists_parsed_fields(self, app, client, isolated_repo_config):
        resp = client.post(
            "/users/create",
            data={
                "username": "uiform1",
                "password": "pw1",
                "email": "u1@example.org",
                "roles": "dev, qa",
                "groups": "team-a",
                "entitlements": "E_ONE\nE_TWO",
                "source_acl": "svc-a",
                "tenant": "acme",
                "attr_key[]": ["department"],
                "attr_value[]": ["engineering"],
            },
        )
        assert resp.status_code == 302
        assert "/users/uiform1" in resp.headers["Location"]
        with app.app_context():
            user = get_config().get_user("uiform1")
        assert user is not None
        assert user.roles == ["dev", "qa"]
        assert user.groups == ["team-a"]
        assert user.entitlements == ["E_ONE", "E_TWO"]
        assert user.tenant == "acme"
        assert user.attributes == {"department": "engineering"}
        # Persisted to the isolated users.yaml, not only to memory
        assert "uiform1" in (isolated_repo_config / "users.yaml").read_text()

    def test_create_user_missing_username_creates_nothing(self, app, client):
        with app.app_context():
            before = len(get_config().users)
        resp = client.post("/users/create", data={"username": "", "password": "pw"})
        assert resp.status_code == 302
        assert "/users/create" in resp.headers["Location"]
        with app.app_context():
            assert len(get_config().users) == before

    def test_create_user_missing_password_creates_nothing(self, app, client):
        resp = client.post("/users/create", data={"username": "nopw", "password": "  "})
        assert resp.status_code == 302
        with app.app_context():
            assert get_config().get_user("nopw") is None

    def test_create_duplicate_user_does_not_overwrite(self, app, client):
        with app.app_context():
            before = get_config().get_user("admin").password
        resp = client.post("/users/create", data={"username": "admin", "password": "hacked"})
        assert resp.status_code == 302
        with app.app_context():
            assert get_config().get_user("admin").password == before

    def test_user_detail_found_and_missing(self, client):
        assert client.get("/users/admin").status_code == 200
        resp = client.get("/users/ghost-user")
        assert resp.status_code == 302
        assert resp.headers["Location"].endswith("/users")

    def test_edit_user_updates_and_keeps_password_when_blank(self, app, client):
        client.post("/users/create", data={"username": "uiedit", "password": "keepme"})
        resp = client.post(
            "/users/uiedit/edit",
            data={"username": "uiedit", "password": "", "email": "new@example.org", "roles": "ops"},
        )
        assert resp.status_code == 302
        with app.app_context():
            user = get_config().get_user("uiedit")
        assert user.email == "new@example.org"
        assert user.roles == ["ops"]
        assert user.password == "keepme"

    def test_edit_missing_user_redirects_to_users(self, client):
        resp = client.post("/users/ghost-user/edit", data={"email": "x@example.org"})
        assert resp.status_code == 302
        assert resp.headers["Location"].endswith("/users")

    def test_delete_user_removes_it(self, app, client):
        client.post("/users/create", data={"username": "uidel", "password": "pw"})
        resp = client.post("/users/uidel/delete")
        assert resp.status_code == 302
        with app.app_context():
            assert get_config().get_user("uidel") is None

    def test_delete_missing_user_flashes_and_survives(self, app, client):
        with app.app_context():
            before = len(get_config().users)
        resp = client.post("/users/ghost-user/delete")
        assert resp.status_code == 302
        with app.app_context():
            assert len(get_config().users) == before


class TestClientForms:
    CREATE = {
        "client_id": "ui-client",
        "client_secret": "ui-secret",
        "description": "made by the form",
        "redirect_uris": "https://app.example/cb\nhttp://127.0.0.1:7777/cb",
        "additional_audiences": "aud-a\naud-b",
    }

    def test_create_client_persists_lists(self, app, client):
        resp = client.post("/clients/create", data=self.CREATE)
        assert resp.status_code == 302
        created = _get_client_by_id(app, "ui-client")
        assert created is not None
        assert created.client_secret == "ui-secret"
        assert created.redirect_uris == ["https://app.example/cb", "http://127.0.0.1:7777/cb"]
        assert created.additional_audiences == ["aud-a", "aud-b"]

    def test_create_client_missing_id_or_secret_creates_nothing(self, app, client):
        with app.app_context():
            before = len(get_config().settings.clients)
        client.post("/clients/create", data={"client_id": "", "client_secret": "s"})
        client.post("/clients/create", data={"client_id": "half-client", "client_secret": ""})
        assert _get_client_by_id(app, "half-client") is None
        with app.app_context():
            # Also catches an empty-string client_id slipping through
            assert len(get_config().settings.clients) == before

    def test_edit_client_blank_secret_keeps_existing(self, app, client):
        client.post("/clients/create", data=self.CREATE)
        resp = client.post(
            "/clients/ui-client/edit",
            data={
                "client_secret": "",
                "description": "edited",
                "redirect_uris": "https://app.example/cb",
                "additional_audiences": "",
            },
        )
        assert resp.status_code == 302
        edited = _get_client_by_id(app, "ui-client")
        assert edited.description == "edited"
        assert edited.client_secret == "ui-secret"
        assert edited.redirect_uris == ["https://app.example/cb"]
        assert edited.additional_audiences == []

    def test_edit_missing_client_redirects(self, client):
        resp = client.post("/clients/ghost/edit", data={"description": "x"})
        assert resp.status_code == 302
        assert resp.headers["Location"].endswith("/clients")

    def test_delete_client_removes_it(self, app, client):
        client.post("/clients/create", data=self.CREATE)
        resp = client.post("/clients/ui-client/delete")
        assert resp.status_code == 302
        assert _get_client_by_id(app, "ui-client") is None

    def test_delete_missing_client_survives(self, app, client):
        with app.app_context():
            before = len(get_config().settings.clients)
        resp = client.post("/clients/ghost/delete")
        assert resp.status_code == 302
        with app.app_context():
            assert len(get_config().settings.clients) == before

    def test_regenerate_secret_carries_every_field(self, app, client):
        """The #32 regression shape: regenerate must not drop ANY other field.

        Includes the branding fields on purpose: a version of this test that
        only set the fields the route happened to carry was tautological and
        stayed green while regenerate silently wiped colors and show_* flags.
        """
        branded = dict(
            self.CREATE,
            background_color="#112233",
            header_color="#445566",
            footer_color="#778899",
            show_client_id="on",
        )
        client.post("/clients/create", data=branded)
        resp = client.post("/clients/ui-client/regenerate-secret")
        assert resp.status_code == 302
        regen = _get_client_by_id(app, "ui-client")
        assert regen.client_secret != "ui-secret"
        assert regen.description == "made by the form"
        assert regen.redirect_uris == ["https://app.example/cb", "http://127.0.0.1:7777/cb"]
        assert regen.additional_audiences == ["aud-a", "aud-b"]
        assert regen.background_color == "#112233"
        assert regen.header_color == "#445566"
        assert regen.footer_color == "#778899"
        assert regen.show_client_id is True

    def test_regenerate_secret_missing_client_redirects(self, client):
        resp = client.post("/clients/ghost/regenerate-secret")
        assert resp.status_code == 302
        assert resp.headers["Location"].endswith("/clients")


class TestSettingsForm:
    def test_post_changes_only_submitted_fields(self, app, client):
        with app.app_context():
            issuer_before = get_config().settings.issuer
        resp = client.post("/settings", data={"audience": "form-aud"})
        assert resp.status_code == 302
        with app.app_context():
            settings = get_config().settings
        assert settings.audience == "form-aud"
        # absent = unchanged (#131): issuer was not on the form
        assert settings.issuer == issuer_before

    def test_checkbox_on_form_marker_contract(self, app, client):
        client.post("/settings", data={"require_pkce": "true"})
        with app.app_context():
            assert get_config().settings.require_pkce is True
        # Marker alone: the box was rendered and left unchecked
        client.post("/settings", data={"require_pkce__on_form": "1"})
        with app.app_context():
            assert get_config().settings.require_pkce is False

    def test_invalid_expiry_changes_nothing(self, app, client):
        with app.app_context():
            before = get_config().settings.token_expiry_minutes
        resp = client.post(
            "/settings", data={"token_expiry_minutes": "abc", "audience": "should-not-land"}
        )
        assert resp.status_code == 302
        with app.app_context():
            settings = get_config().settings
        assert settings.token_expiry_minutes == before
        assert settings.audience != "should-not-land"


class TestKeysPages:
    @pytest.fixture
    def keys_client(self, tmp_path):
        app = _make_app(tmp_path)
        return app, app.test_client()

    def test_keys_page_renders_kid(self, keys_client):
        from nanoidp.services import get_crypto_service

        app, client = keys_client
        with app.app_context():
            kid = get_crypto_service(get_config().settings.keys_dir).kid
        resp = client.get("/keys")
        assert resp.status_code == 200
        assert kid.encode() in resp.data

    def test_regenerate_changes_and_persists_kid(self, keys_client, tmp_path):
        from nanoidp.services import get_crypto_service

        app, client = keys_client
        with app.app_context():
            kid_before = get_crypto_service(get_config().settings.keys_dir).kid
        resp = client.post("/keys/regenerate")
        assert resp.status_code == 302
        with app.app_context():
            kid_after = get_crypto_service(get_config().settings.keys_dir).kid
        assert kid_after != kid_before
        # Not only the in-memory singleton the route just mutated: the new
        # kid must be on disk, or a restart reverts to the old key and
        # post-rotation tokens stop verifying against JWKS.
        assert (tmp_path / "keys" / "kid.txt").read_text().strip() == kid_after

    def test_download_public_key_and_certificate(self, keys_client):
        app, client = keys_client
        resp = client.get("/keys/download/public_key")
        assert resp.status_code == 200
        assert b"BEGIN PUBLIC KEY" in resp.data
        resp = client.get("/keys/download/certificate")
        assert resp.status_code == 200
        assert b"BEGIN CERTIFICATE" in resp.data

    def test_download_invalid_type_redirects(self, keys_client):
        app, client = keys_client
        resp = client.get("/keys/download/private_key")
        assert resp.status_code == 302
        assert resp.headers["Location"].endswith("/keys")


class TestClaimsPages:
    def test_claims_page_renders(self, client):
        assert client.get("/claims").status_code == 200

    def test_post_prefixes_persists_core_and_custom(self, app, client):
        resp = client.post(
            "/claims",
            data={
                "prefix_roles": "R_",
                "prefix_groups": "G_",
                "custom_prefix_key[]": ["department"],
                "custom_prefix_value[]": ["DEPT_"],
            },
        )
        assert resp.status_code == 302
        with app.app_context():
            prefixes = get_config().settings.authority_prefixes
        assert prefixes["roles"] == "R_"
        assert prefixes["groups"] == "G_"
        assert prefixes["department"] == "DEPT_"

    def test_claims_preview_json_and_404(self, client):
        resp = client.get("/claims/preview/admin")
        assert resp.status_code == 200
        payload = resp.get_json()
        assert payload["username"] == "admin"
        assert "authorities" in payload
        assert client.get("/claims/preview/ghost-user").status_code == 404


class TestAuditPages:
    def _generate_entries(self, app, client):
        """Two login events plus one non-login event, so a broken
        event_type/search filter shows up as the wrong entries coming back,
        not as a smaller count of the same kind."""
        from nanoidp.services import get_audit_log

        _login(client, password="wrong")  # a failed login is an audit entry
        _login(client)
        with app.app_context():
            get_audit_log().log(
                event_type="token_request",
                endpoint="/token",
                method="POST",
                username="filter-seed",
                status="success",
                details={},
            )

    def test_audit_page_search_filters_rows(self, app, client):
        self._generate_entries(app, client)
        assert client.get("/audit").status_code == 200
        resp = client.get("/audit?limit=5&event_type=login&search=admin")
        assert resp.status_code == 200
        assert b"filter-seed" not in resp.data
        resp = client.get("/audit?search=filter-seed")
        assert b"filter-seed" in resp.data

    def test_export_json_applies_event_type_filter(self, app, client):
        self._generate_entries(app, client)
        resp = client.get("/audit/export/json?event_type=login")
        assert resp.status_code == 200
        assert resp.mimetype == "application/json"
        entries = json.loads(resp.data)
        assert entries
        assert all(e["event_type"] == "login" for e in entries)
        # The unfiltered export does contain the other kind, so the filter
        # above provably excluded something.
        everything = json.loads(client.get("/audit/export/json").data)
        assert any(e["event_type"] == "token_request" for e in everything)

    def test_export_csv_has_header(self, app, client):
        self._generate_entries(app, client)
        resp = client.get("/audit/export/csv")
        assert resp.status_code == 200
        assert resp.mimetype == "text/csv"
        assert b"event_type" in resp.data

    def test_export_invalid_format_redirects(self, client):
        resp = client.get("/audit/export/xml")
        assert resp.status_code == 302
        assert resp.headers["Location"].endswith("/audit")

    def test_clear_empties_the_log(self, app, client):
        from nanoidp.services import get_audit_log

        self._generate_entries(app, client)
        resp = client.post("/audit/clear")
        assert resp.status_code == 302
        with app.app_context():
            assert get_audit_log().get_stats()["total_requests"] == 0
            assert get_audit_log().get_entries(limit=1) == []

    def test_index_and_test_pages_render(self, client):
        assert client.get("/").status_code == 200
        assert client.get("/test").status_code == 200


class TestRequireUiLoginGate:
    """require_ui_login alone: the session front door, not the write guard."""

    @pytest.fixture
    def gated(self, tmp_path):
        app = _make_app(tmp_path, session_overrides={"require_ui_login": True})
        return app, app.test_client()

    def test_view_and_mutation_redirect_to_login_without_session(self, gated):
        app, client = gated
        assert client.get("/users").headers["Location"].endswith("/login")
        resp = client.post("/users/create", data={"username": "gated1", "password": "pw"})
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]
        with app.app_context():
            assert get_config().get_user("gated1") is None

    def test_after_login_mutation_succeeds(self, gated):
        app, client = gated
        _login(client)
        resp = client.post("/users/create", data={"username": "gated2", "password": "pw"})
        assert resp.status_code == 302
        assert "/login" not in resp.headers["Location"]
        with app.app_context():
            assert get_config().get_user("gated2") is not None


class TestManagementSecretUiGateAcrossEndpoints:
    """management_secret alone must gate EVERY mutating UI surface.

    tests/test_management_secret.py proves the mechanism on /users/create;
    the parametrized test below sweeps every POST endpoint ui_bp registers
    today, and the targeted tests assert on state, not status codes.
    Caveat the sweep cannot cover: the gate short-circuits on safe methods
    (_auth.py), so a future mutating route added as GET - the shape
    /keys/download/<key_type> and /audit/export/<format> already have -
    would bypass it entirely.
    """

    SECRET = "ui-gate-secret"

    # Every mutating (POST) endpoint ui_bp registers, minus the two
    # deliberate exemptions (ui.login, ui.management_unlock). demo-client
    # and admin exist in the copied preset config.
    MUTATING_ENDPOINTS = [
        ("/users/create", {"username": "x", "password": "p"}),
        ("/users/admin/edit", {"email": "x@example.org"}),
        ("/users/admin/delete", {}),
        ("/clients/create", {"client_id": "x", "client_secret": "s"}),
        ("/clients/demo-client/edit", {"description": "x"}),
        ("/clients/demo-client/delete", {}),
        ("/clients/demo-client/regenerate-secret", {}),
        ("/settings", {"audience": "x"}),
        ("/claims", {"prefix_roles": "X_"}),
        ("/audit/clear", {}),
        ("/keys/regenerate", {}),
    ]

    @pytest.fixture
    def gated(self, tmp_path):
        app = _make_app(tmp_path, session_overrides={"management_secret": self.SECRET})
        return app, app.test_client()

    def _unlock(self, client, secret=None):
        return client.post(
            "/management/unlock", data={"management_secret": secret or self.SECRET}
        )

    @pytest.mark.parametrize("path,data", MUTATING_ENDPOINTS)
    def test_every_mutating_endpoint_redirects_to_login(self, gated, path, data):
        app, client = gated
        resp = client.post(path, data=data)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_client_create_blocked_then_unlocked(self, gated):
        app, client = gated
        data = {"client_id": "gate-client", "client_secret": "s"}
        resp = client.post("/clients/create", data=data)
        assert "/login" in resp.headers["Location"]
        assert _get_client_by_id(app, "gate-client") is None

        self._unlock(client)
        resp = client.post("/clients/create", data=data)
        assert "/login" not in resp.headers["Location"]
        assert _get_client_by_id(app, "gate-client") is not None

    def test_settings_post_blocked_without_unlock(self, gated):
        app, client = gated
        resp = client.post("/settings", data={"audience": "gated-aud"})
        assert "/login" in resp.headers["Location"]
        with app.app_context():
            assert get_config().settings.audience != "gated-aud"

    def test_audit_clear_blocked_without_unlock(self, gated):
        from nanoidp.services import get_audit_log

        app, client = gated
        with app.app_context():
            before = len(get_audit_log().get_entries(limit=100))
        _login(client, password="wrong")  # audit entry; /login POST is exempt
        with app.app_context():
            after = len(get_audit_log().get_entries(limit=100))
        # The count must have GROWN across the login: a leftover entry from
        # another test must not be able to satisfy the precondition.
        assert after > before
        resp = client.post("/audit/clear")
        assert "/login" in resp.headers["Location"]
        with app.app_context():
            assert len(get_audit_log().get_entries(limit=100)) == after

    def test_wrong_unlock_secret_keeps_the_gate(self, gated):
        app, client = gated
        resp = self._unlock(client, secret="not-it")
        assert "error=" in resp.headers["Location"]
        resp = client.post("/users/create", data={"username": "still-gated", "password": "pw"})
        assert "/login" in resp.headers["Location"]
        with app.app_context():
            assert get_config().get_user("still-gated") is None


class TestBothGates:
    """require_ui_login and management_secret together: login is not unlock."""

    SECRET = "both-gates-secret"

    @pytest.fixture
    def gated(self, tmp_path):
        app = _make_app(
            tmp_path,
            session_overrides={"require_ui_login": True, "management_secret": self.SECRET},
        )
        return app, app.test_client()

    def test_login_alone_does_not_satisfy_the_write_guard(self, gated):
        app, client = gated
        _login(client)
        resp = client.post("/users/create", data={"username": "only-login", "password": "pw"})
        assert "/login" in resp.headers["Location"]
        with app.app_context():
            assert get_config().get_user("only-login") is None

    def test_login_plus_unlock_mutates(self, gated):
        app, client = gated
        _login(client)
        client.post("/management/unlock", data={"management_secret": self.SECRET})
        resp = client.post("/users/create", data={"username": "fully-open", "password": "pw"})
        assert "/login" not in resp.headers["Location"]
        with app.app_context():
            assert get_config().get_user("fully-open") is not None
