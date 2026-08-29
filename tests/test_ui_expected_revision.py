"""
Tests for issue #229 phase 4: routes/ui.py's forms now carry the revision
they were rendered with as a hidden expected_revision field, and each
write route passes it through to the corresponding YamlWriter call,
catching ConflictError with a flash - the same pattern every existing
ValueError/HookError branch already used.

A form is not itself parsed here (no HTML scraping): current_revision()
is the same function the routes call, so computing it directly against
the isolated config directory gives the exact value a real page would
have embedded, without coupling these tests to template markup.
"""

import re
import shutil
from pathlib import Path

import yaml

from nanoidp.app import create_app
from nanoidp.config import get_config
from nanoidp.config_writer import current_revision
from nanoidp.services import get_yaml_writer

_REPO_CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"


def _hidden_revision(html: str) -> str:
    match = re.search(r'name="expected_revision" value="([^"]*)"', html)
    assert match, "no expected_revision hidden field found in the page"
    return match.group(1)


def _make_app_with_on_config_saved_hook(tmp_path, hook_command: str):
    """An app whose settings.yaml declares an on_config_saved shell hook,
    for tests that need something else to move the file's revision right
    after a write completes - the same shape a second admin, the MCP
    companion or a mirror hook could produce."""
    cfg = tmp_path / "cfg"
    cfg.mkdir(exist_ok=True)
    for name in ("settings.yaml", "users.yaml"):
        shutil.copy(_REPO_CONFIG_DIR / name, cfg / name)
    data = yaml.safe_load((cfg / "settings.yaml").read_text())
    data.setdefault("jwt", {})["keys_dir"] = str(tmp_path / "keys")
    data["hooks"] = {"on_config_saved": hook_command}
    (cfg / "settings.yaml").write_text(yaml.safe_dump(data))
    app = create_app(config_dir=str(cfg))
    app.config["TESTING"] = True
    return app


class TestGetPagesEmbedARealRevision:
    """The hidden field must carry an actual revision, not an empty
    Jinja-undefined string - a template context missing `revision`
    would render `value=""`, which reads as "not present" per
    _expected_revision_from_form() and silently disables the guard."""

    def test_user_create_form(self, client, isolated_repo_config):
        html = client.get("/users/create").get_data(as_text=True)
        assert _hidden_revision(html) == current_revision(isolated_repo_config / "users.yaml")

    def test_user_edit_form(self, client, isolated_repo_config):
        html = client.get("/users/admin/edit").get_data(as_text=True)
        assert _hidden_revision(html) == current_revision(isolated_repo_config / "users.yaml")

    def test_client_create_form(self, client, isolated_repo_config):
        html = client.get("/clients/create").get_data(as_text=True)
        assert _hidden_revision(html) == current_revision(isolated_repo_config / "settings.yaml")

    def test_client_edit_form(self, client, isolated_repo_config):
        html = client.get("/clients/demo-client/edit").get_data(as_text=True)
        assert _hidden_revision(html) == current_revision(isolated_repo_config / "settings.yaml")

    def test_clients_list_page(self, client, isolated_repo_config):
        html = client.get("/clients").get_data(as_text=True)
        assert _hidden_revision(html) == current_revision(isolated_repo_config / "settings.yaml")

    def test_settings_form(self, client, isolated_repo_config):
        html = client.get("/settings").get_data(as_text=True)
        assert _hidden_revision(html) == current_revision(isolated_repo_config / "settings.yaml")

    def test_claims_form(self, client, isolated_repo_config):
        html = client.get("/claims").get_data(as_text=True)
        assert _hidden_revision(html) == current_revision(isolated_repo_config / "settings.yaml")


class TestStaleFormSubmissionIsAConflictNotA500:
    def test_user_create_with_stale_revision_flashes_and_creates_nothing(
        self, app, client, isolated_repo_config
    ):
        stale = current_revision(isolated_repo_config / "users.yaml")
        client.post("/users/create", data={"username": "other", "password": "pw"})

        resp = client.post(
            "/users/create",
            data={"username": "toolate", "password": "pw", "expected_revision": stale},
        )

        assert resp.status_code == 302
        assert resp.headers["Location"].endswith("/users/create")
        with app.app_context():
            assert get_config().get_user("toolate") is None

    def test_client_create_with_stale_revision_flashes_and_creates_nothing(
        self, app, client, isolated_repo_config
    ):
        stale = current_revision(isolated_repo_config / "settings.yaml")
        client.post("/clients/create", data={"client_id": "other", "client_secret": "s"})

        resp = client.post(
            "/clients/create",
            data={
                "client_id": "toolate",
                "client_secret": "s",
                "expected_revision": stale,
            },
        )

        assert resp.status_code == 302
        assert resp.headers["Location"].endswith("/clients/create")
        with app.app_context():
            assert not any(
                c.client_id == "toolate" for c in get_config().settings.clients
            )

    def test_user_edit_with_stale_revision_flashes_and_leaves_user_untouched(
        self, app, client, isolated_repo_config
    ):
        stale = current_revision(isolated_repo_config / "users.yaml")
        # someone else writes users.yaml first
        client.post("/users/create", data={"username": "other", "password": "pw"})

        resp = client.post(
            "/users/admin/edit",
            data={"email": "attacker@example.org", "expected_revision": stale},
        )

        assert resp.status_code == 302
        assert resp.headers["Location"].endswith("/users/admin/edit")
        with app.app_context():
            assert get_config().get_user("admin").email != "attacker@example.org"

    def test_user_delete_with_stale_revision_flashes_and_leaves_user_untouched(
        self, app, client, isolated_repo_config
    ):
        client.post("/users/create", data={"username": "todelete", "password": "pw"})
        stale = current_revision(isolated_repo_config / "users.yaml")
        client.post("/users/create", data={"username": "other", "password": "pw"})

        resp = client.post(
            "/users/todelete/delete", data={"expected_revision": stale}
        )

        assert resp.status_code == 302
        with app.app_context():
            assert get_config().get_user("todelete") is not None

    def test_client_edit_with_stale_revision_flashes_and_leaves_client_untouched(
        self, app, client, isolated_repo_config
    ):
        stale = current_revision(isolated_repo_config / "settings.yaml")
        client.post(
            "/clients/create", data={"client_id": "other", "client_secret": "s"}
        )

        resp = client.post(
            "/clients/demo-client/edit",
            data={
                "client_secret": "hacked-secret",
                "description": "attacker",
                "expected_revision": stale,
            },
        )

        assert resp.status_code == 302
        assert resp.headers["Location"].endswith("/clients/demo-client/edit")
        with app.app_context():
            client_obj = next(
                c for c in get_config().settings.clients if c.client_id == "demo-client"
            )
        assert client_obj.description != "attacker"

    def test_client_delete_with_stale_revision_flashes_and_leaves_client_untouched(
        self, app, client, isolated_repo_config
    ):
        client.post(
            "/clients/create", data={"client_id": "todelete", "client_secret": "s"}
        )
        stale = current_revision(isolated_repo_config / "settings.yaml")
        client.post(
            "/clients/create", data={"client_id": "other", "client_secret": "s"}
        )

        resp = client.post(
            "/clients/todelete/delete", data={"expected_revision": stale}
        )

        assert resp.status_code == 302
        with app.app_context():
            assert any(
                c.client_id == "todelete" for c in get_config().settings.clients
            )

    def test_client_regenerate_secret_with_stale_revision_does_not_change_secret(
        self, app, client, isolated_repo_config
    ):
        with app.app_context():
            original_secret = next(
                c for c in get_config().settings.clients if c.client_id == "demo-client"
            ).client_secret
        stale = current_revision(isolated_repo_config / "settings.yaml")
        client.post(
            "/clients/create", data={"client_id": "other", "client_secret": "s"}
        )

        resp = client.post(
            "/clients/demo-client/regenerate-secret", data={"expected_revision": stale}
        )

        assert resp.status_code == 302
        with app.app_context():
            current_secret = next(
                c for c in get_config().settings.clients if c.client_id == "demo-client"
            ).client_secret
        assert current_secret == original_secret

    def test_settings_with_stale_revision_flashes_and_leaves_settings_untouched(
        self, app, client, isolated_repo_config
    ):
        stale = current_revision(isolated_repo_config / "settings.yaml")
        client.post(
            "/clients/create", data={"client_id": "other", "client_secret": "s"}
        )

        resp = client.post(
            "/settings", data={"audience": "attacker-aud", "expected_revision": stale}
        )

        assert resp.status_code == 302
        assert resp.headers["Location"].endswith("/settings")
        with app.app_context():
            assert get_config().settings.audience != "attacker-aud"

    def test_claims_with_stale_revision_flashes_and_leaves_prefixes_untouched(
        self, app, client, isolated_repo_config
    ):
        stale = current_revision(isolated_repo_config / "settings.yaml")
        client.post(
            "/clients/create", data={"client_id": "other", "client_secret": "s"}
        )

        resp = client.post(
            "/claims", data={"prefix_roles": "ATTACKER_", "expected_revision": stale}
        )

        assert resp.status_code == 302
        with app.app_context():
            assert get_config().settings.authority_prefixes.get("roles") != "ATTACKER_"


class TestFreshFormSubmissionStillSucceeds:
    """The precondition must not turn into a false positive against a
    form that was, in fact, submitted against the current revision."""

    def test_user_edit_with_current_revision_succeeds(self, app, client, isolated_repo_config):
        revision = current_revision(isolated_repo_config / "users.yaml")

        resp = client.post(
            "/users/admin/edit",
            data={"email": "fresh@example.org", "expected_revision": revision},
        )

        assert resp.status_code == 302
        with app.app_context():
            assert get_config().get_user("admin").email == "fresh@example.org"

    def test_settings_form_composes_all_four_sections_into_one_write(
        self, app, client, isolated_repo_config
    ):
        """The settings page applies oauth, saml, identity classes and
        login mode as one compare_and_replace call (#229 phase 4 review,
        blocking 1) - all four must land from a single fresh
        submission."""
        revision = current_revision(isolated_repo_config / "settings.yaml")

        resp = client.post(
            "/settings",
            data={
                "audience": "chained-aud",
                "saml_entity_id": "urn:chained",
                "allowed_identity_classes": "INTERNAL\nEXTERNAL",
                "login_mode": "password",
                "expected_revision": revision,
            },
        )

        assert resp.status_code == 302
        with app.app_context():
            settings = get_config().settings
        assert settings.audience == "chained-aud"
        assert settings.saml_entity_id == "urn:chained"
        assert settings.allowed_identity_classes == ["INTERNAL", "EXTERNAL"]

    def test_no_expected_revision_field_is_unconditional(
        self, app, client, isolated_repo_config
    ):
        """A POST with no expected_revision at all (an old cached page, a
        script, examples/test_agent.py) keeps today's last-write-wins -
        nothing about this phase should require every caller to opt in."""
        resp = client.post("/users/admin/edit", data={"email": "noopt@example.org"})

        assert resp.status_code == 302
        with app.app_context():
            assert get_config().get_user("admin").email == "noopt@example.org"


class TestSettingsFormIsAllOrNothing:
    """Regression pin for #229 phase 4 review, blocking 1: the settings
    page originally ran four separate compare_and_replace calls on
    settings.yaml, chained by revision. A conflict on write N left
    writes 1..N-1 already committed, their on_config_saved hooks already
    fired and the runtime already reloaded, while the flash claimed
    nothing had landed at all - reproduced live by the review with an
    on_config_saved hook that rewrites settings.yaml after every save,
    moving the file's revision exactly as a second admin, the MCP
    companion or a mirror hook could between two of the four writes.

    update_settings_form composes every section into one write, so this
    hook firing after THAT one write is irrelevant to the request that
    triggered it - there is no second write in the same request left to
    conflict with. This test would fail on the old chained design (write
    1 lands, the hook moves the revision, write 2 conflicts, writes 3-4
    never run) and passes on the composed one."""

    def test_settings_post_with_a_moving_file_lands_all_or_nothing(self, tmp_path):
        app = _make_app_with_on_config_saved_hook(
            tmp_path, hook_command='sh -c \'echo "# touched by another actor" >> {path}\''
        )
        client = app.test_client()

        with app.app_context():
            revision = current_revision(get_yaml_writer().settings_file)

        resp = client.post(
            "/settings",
            data={
                "audience": "hooked-aud",
                "saml_entity_id": "urn:hooked",
                # Not the repo preset's default (INTERNAL/EXTERNAL) - a
                # value that matches the default too could "land" only
                # because it was already there, masking a partial write.
                "allowed_identity_classes": "PARTNER\nSERVICE",
                "login_mode": "password",
                "expected_revision": revision,
            },
        )

        assert resp.status_code == 302
        with app.app_context():
            settings = get_config().settings
        landed = {
            "audience": settings.audience == "hooked-aud",
            "saml_entity_id": settings.saml_entity_id == "urn:hooked",
            "allowed_identity_classes": settings.allowed_identity_classes
            == ["PARTNER", "SERVICE"],
        }
        assert all(landed.values()) or not any(landed.values()), (
            f"partial application, not all-or-nothing: {landed}"
        )
        # the hook fired at least once and the file did move - a no-op
        # hook would make this test vacuous
        with app.app_context():
            assert "# touched by another actor" in get_yaml_writer().settings_file.read_text()
