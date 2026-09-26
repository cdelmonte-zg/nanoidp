"""
Unit tests for the routes/ui.py form flows (#213).

These flows were covered almost only by e2e/test_agent.py, which CI
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

    def test_oidc_end_session_clears_session(self, client):
        # /logout belongs solely to oauth_bp's OIDC end-session endpoint
        # since #221 moved the UI logout to its own rule; the earlier loose
        # (200, 302) assertion here can be exact again.
        _login(client)
        resp = client.get("/logout")
        assert resp.status_code == 200
        with client.session_transaction() as sess:
            assert "user" not in sess

    def test_ui_logout_redirects_to_dashboard_and_audits(self, app, client):
        from nanoidp.services import get_audit_log

        _login(client)
        resp = client.get("/ui/logout")
        assert resp.status_code == 302
        assert resp.headers["Location"].endswith("/")
        with client.session_transaction() as sess:
            assert "user" not in sess
        # The audit event ui.logout was supposed to write for years but never
        # could while the route was shadowed (#221).
        with app.app_context():
            entries = get_audit_log().get_entries(limit=10, event_type="logout")
        assert any(e.get("username") == "admin" for e in entries)


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

    def test_a_doubly_invalid_create_still_names_the_missing_password(self, app, client):
        """The route asks its own question before the reader builds a record
        (#298 review), so a submission that is invalid in two ways keeps the
        operator sentence instead of falling through to the model's refusal
        text, which is a pydantic dump with a documentation URL in it."""
        resp = client.post(
            "/users/create",
            data={"username": "dual", "password": "  ", "email": "no-at-sign"},
            follow_redirects=True,
        )

        page = resp.data.decode()
        assert "Password is required for new users" in page
        assert "errors.pydantic.dev" not in page
        with app.app_context():
            assert get_config().get_user("dual") is None

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

    def test_a_whitespace_only_password_means_blank_on_both_legs(self, app, client):
        """One notion of "the field was left blank", decided in #386. Until
        then create stripped before deciding and edit did not, so "  " was
        no password on one leg and a real password on the other: an operator
        leaving stray spaces in the field silently replaced the account's
        password with whitespace, with nothing flashed and nothing logged."""
        client.post("/users/create", data={"username": "wsp", "password": "realpw"})

        client.post("/users/wsp/edit", data={"password": "   "})

        with app.app_context():
            assert get_config().get_user("wsp").password == "realpw"

    def test_an_edited_password_that_is_not_blank_is_stored_verbatim(self, app, client):
        """Strip decides whether the field was filled in; it never rewrites
        what was typed, because leading and trailing spaces may be
        deliberate (#386). The create leg already has this in
        test_persona_login.py, which is also where the persona-mode blank
        case lives; only the edit leg was uncovered."""
        client.post("/users/create", data={"username": "spaced", "password": "realpw"})

        client.post("/users/spaced/edit", data={"password": "  new  "})

        with app.app_context():
            assert get_config().get_user("spaced").password == "  new  "

    def test_edit_with_a_refused_field_is_not_reported_as_a_failure(self, app, client):
        """Both legs build through the same reader now, so a field the model
        refuses on edit is operator input, answered like the create route
        answers it instead of falling to the catch-all (#298 review)."""
        client.post("/users/create", data={"username": "badmail", "password": "pw"})

        resp = client.post(
            "/users/badmail/edit", data={"email": "no-at-sign"}, follow_redirects=True
        )

        page = resp.data.decode()
        assert "Invalid email format" in page
        assert "Failed to update user" not in page
        with app.app_context():
            assert get_config().get_user("badmail").email == ""

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

    def test_create_client_without_a_method_gets_the_resolver_s_default(self, app, client):
        """The form has no method field on create, and the route does not
        spell a default of its own: what a client with no method named gets
        is the resolver's answer, and the resolver reads it off the model
        (#300 review)."""
        from nanoidp.services.client_policy import DEFAULT_METHOD

        client.post("/clients/create", data=self.CREATE)

        assert _get_client_by_id(app, "ui-client").token_endpoint_auth_method == DEFAULT_METHOD

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

    def test_edit_client_without_a_layout_keeps_the_stored_one(self, app, client):
        """The one fallback where create and edit genuinely differ: create
        has nothing to fall back to and spells the model's "vertical", edit
        falls back to the client it is editing (#298)."""
        client.post("/clients/create", data={**self.CREATE, "layout": "horizontal"})

        client.post(
            "/clients/ui-client/edit",
            data={"client_secret": "", "description": "no layout submitted"},
        )

        assert _get_client_by_id(app, "ui-client").layout == "horizontal"

    def test_edit_client_with_a_refused_field_is_not_reported_as_a_failure(self, app, client):
        """The clients form's counterpart: a colour the model refuses is
        operator input, not a server failure (#298 review)."""
        client.post("/clients/create", data=self.CREATE)

        resp = client.post(
            "/clients/ui-client/edit",
            data={"client_secret": "", "background_color": "not-a-color"},
            follow_redirects=True,
        )

        page = resp.data.decode()
        assert "Failed to update client" not in page
        assert _get_client_by_id(app, "ui-client").background_color is None

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

    def test_create_public_client_and_clients_page_renders(self, app, client):
        """#188 / #254 review, finding 1: a public client has no secret, so
        the clients list page must render it without slicing None."""
        resp = client.post(
            "/clients/create",
            data={"client_id": "pub-ui", "token_endpoint_auth_method": "none"},
        )
        assert resp.status_code == 302
        created = _get_client_by_id(app, "pub-ui")
        assert created is not None and created.is_public and created.client_secret is None
        # The page that the create flow redirects to must not 500.
        page = client.get("/clients")
        assert page.status_code == 200
        assert b"pub-ui" in page.data

    def test_create_public_client_drops_a_submitted_secret(self, app, client):
        """#254 review round 2: the create form pre-generates a secret; a
        browser that picks 'none' still submits it. The route must persist
        client_secret=None regardless, matching the edit-to-none behaviour."""
        resp = client.post(
            "/clients/create",
            data={
                "client_id": "pub-gen",
                "token_endpoint_auth_method": "none",
                "client_secret": "a-pre-generated-value-from-the-form",
            },
        )
        assert resp.status_code == 302
        created = _get_client_by_id(app, "pub-gen")
        assert created is not None and created.is_public
        assert created.client_secret is None

    def test_edit_to_public_with_blank_secret_drops_the_secret(self, app, client):
        """#254 review, finding 3: switching a confidential client to 'none'
        with a blank secret field must drop the old secret, not keep a dead
        one in the persisted client."""
        client.post("/clients/create", data=self.CREATE)
        resp = client.post(
            "/clients/ui-client/edit",
            data={"token_endpoint_auth_method": "none", "client_secret": ""},
        )
        assert resp.status_code == 302
        edited = _get_client_by_id(app, "ui-client")
        assert edited.is_public is True
        assert edited.client_secret is None

    def test_regenerate_secret_refused_for_public_client(self, app, client):
        """#254 review, finding 4: a public client has no secret; the route
        must refuse rather than model_copy a secret onto it."""
        client.post(
            "/clients/create",
            data={"client_id": "pub-regen", "token_endpoint_auth_method": "none"},
        )
        resp = client.post("/clients/pub-regen/regenerate-secret")
        assert resp.status_code == 302
        still = _get_client_by_id(app, "pub-regen")
        assert still.is_public is True and still.client_secret is None


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
            kid = get_crypto_service().kid
        resp = client.get("/keys")
        assert resp.status_code == 200
        assert kid.encode() in resp.data

    def test_regenerate_changes_and_persists_kid(self, keys_client, tmp_path):
        from nanoidp.services import get_crypto_service

        app, client = keys_client
        with app.app_context():
            kid_before = get_crypto_service().kid
        resp = client.post("/keys/regenerate")
        assert resp.status_code == 302
        with app.app_context():
            kid_after = get_crypto_service().kid
        assert kid_after != kid_before
        # Not only the in-memory singleton the route just mutated: the new
        # kid must be on disk, or a restart reverts to the old key and
        # post-rotation tokens stop verifying against JWKS.
        assert (tmp_path / "keys" / "kid.txt").read_text().strip() == kid_after

    def test_a_refused_regeneration_shows_the_fixed_message_and_not_the_directory(self, keys_client, monkeypatch):
        """The same refusal as /api/keys/rotate: the page shows the fixed
        message; the directory the exception names stays in the log."""
        from nanoidp.services import get_crypto_service
        from nanoidp.services.crypto import KEYS_DIRECTORY_NOT_WRITABLE
        from nanoidp.services.key_directory import KeysDirectoryNotWritable

        app, client = keys_client
        directory = "/srv/nanoidp/secret-keys-9f3a"
        with app.app_context():
            service = get_crypto_service()
        monkeypatch.setattr(
            service,
            "rotate_keys",
            lambda: (_ for _ in ()).throw(KeysDirectoryNotWritable(Path(directory), PermissionError(13, "denied"))),
        )

        page = client.post("/keys/regenerate", follow_redirects=True).get_data(as_text=True)

        assert KEYS_DIRECTORY_NOT_WRITABLE in page
        assert directory not in page

    def test_an_unexpected_failure_of_regeneration_is_not_quoted_on_the_page(self, keys_client, monkeypatch):
        from nanoidp.services import get_crypto_service

        app, client = keys_client
        with app.app_context():
            service = get_crypto_service()
        monkeypatch.setattr(
            service, "rotate_keys", lambda: (_ for _ in ()).throw(RuntimeError("disk /srv/nanoidp/keys-3f2 is on fire"))
        )

        page = client.post("/keys/regenerate", follow_redirects=True).get_data(as_text=True)

        assert "Failed to regenerate keys: see the server log" in page
        assert "on fire" not in page and "/srv/nanoidp" not in page

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
    """management_secret gates mutating UI surfaces: the specific semantics.

    That EVERY mutating route on the management surfaces is gated - the
    completeness of the boundary, fail-closed on new blueprints and methods,
    across ui/api/runtime - is now one contract in
    tests/test_management_gate_routing_invariant.py, derived from the URL map
    rather than a hand-maintained list (this class used to carry that list,
    and it had gone stale, missing /clients/forget). What stays here is the
    behaviour that invariant does not assert: an authorized mutation changes
    the right state, and an unauthorized one changes none. See also
    tests/test_management_secret.py for the mechanism.
    """

    SECRET = "ui-gate-secret"

    @pytest.fixture
    def gated(self, tmp_path):
        app = _make_app(tmp_path, session_overrides={"management_secret": self.SECRET})
        return app, app.test_client()

    def _unlock(self, client, secret=None):
        return client.post(
            "/management/unlock", data={"management_secret": secret or self.SECRET}
        )

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


class TestSwitchingAClientToPublicThroughTheEditForm:
    """#300: the edit form now drops a secret typed while switching to
    public, which the create form has done since #254 - a behaviour change,
    declared in the CHANGELOG rather than assumed away."""

    def _create(self, client, client_id="edit-public", secret="s3cret"):
        return client.post(
            "/clients/create",
            data={
                "client_id": client_id,
                "token_endpoint_auth_method": "client_secret_basic",
                "client_secret": secret,
            },
            follow_redirects=True,
        )

    def test_a_secret_typed_while_switching_to_public_is_dropped(self, client, app):
        self._create(client)

        client.post(
            "/clients/edit-public/edit",
            data={
                "client_id": "edit-public",
                "token_endpoint_auth_method": "none",
                "client_secret": "typed-by-the-operator",
            },
            follow_redirects=True,
        )

        with app.app_context():
            from nanoidp.config import get_config

            updated = get_config().get_client("edit-public")
        assert updated.token_endpoint_auth_method == "none"
        assert updated.client_secret is None

    def test_a_blank_secret_on_a_public_client_is_refused_with_the_operator_sentence(
        self, client, app
    ):
        """A public client's form never marks the secret required, so this
        is ordinary input and gets a sentence, not the catch-all's trace."""
        self._create(client, client_id="edit-back", secret="s3cret")
        client.post(
            "/clients/edit-back/edit",
            data={
                "client_id": "edit-back",
                "token_endpoint_auth_method": "none",
                "client_secret": "",
            },
            follow_redirects=True,
        )

        page = client.post(
            "/clients/edit-back/edit",
            data={
                "client_id": "edit-back",
                "token_endpoint_auth_method": "client_secret_basic",
                "client_secret": "",
            },
            follow_redirects=True,
        )

        assert b"Client Secret is required unless the auth method is" in page.data
        assert b"Failed to update client" not in page.data
        with app.app_context():
            from nanoidp.config import get_config

            unchanged = get_config().get_client("edit-back")
        assert unchanged.token_endpoint_auth_method == "none"
