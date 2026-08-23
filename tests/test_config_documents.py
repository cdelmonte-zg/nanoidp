"""
#175 piece 2: settings.yaml and users.yaml load through document models.

The document models are now the single statement of the file format. These
tests pin (a) that their defaults equal the literals the loader used to
hard-code, (b) that every shipped file loads with zero warnings (the
"legacy keys keep loading" guard), (c) that unknown keys are reported with
their path instead of vanishing, and (d) that the round-trip conventions of
#127 are untouched.
"""

import copy
import glob
import logging
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from nanoidp.config import ConfigManager
from nanoidp.config_documents import (
    SettingsDocument,
    UsersDocument,
    document_defaults,
    load_settings_document,
    load_users_document,
)
from nanoidp.models import Settings
from nanoidp.serialization import apply_settings_document, expand_env_vars, load_yaml_document

REPO = Path(__file__).resolve().parent.parent
SHIPPED_SETTINGS = sorted(
    [REPO / "config" / "settings.yaml"] + [Path(p) for p in glob.glob(str(REPO / "examples" / "*" / "settings.yaml"))]
)
SHIPPED_USERS = sorted(
    [REPO / "config" / "users.yaml"] + [Path(p) for p in glob.glob(str(REPO / "examples" / "*" / "users.yaml"))]
)
# Captured at import time: the suite may rewrite config/ mid-run (#184 keeps
# that out of the repo, but the guard should not depend on test order).
SHIPPED_SETTINGS_DATA = {p: yaml.safe_load(p.read_text()) or {} for p in SHIPPED_SETTINGS}
SHIPPED_USERS_DATA = {p: yaml.safe_load(p.read_text()) or {} for p in SHIPPED_USERS}


def _write(tmp_path, settings=None, users=None):
    (tmp_path / "settings.yaml").write_text(yaml.safe_dump(settings if settings is not None else {"server": {"port": 8000}}))
    (tmp_path / "users.yaml").write_text(yaml.safe_dump(users if users is not None else {"users": {}}))
    return str(tmp_path)


class TestDefaultsMatchTheOldLoaderLiterals:
    """Every literal that used to live in ConfigManager._read_settings()."""

    def test_settings_section_defaults(self):
        d = SettingsDocument()
        assert (d.server.host, d.server.port, d.server.debug) == ("127.0.0.1", 8000, False)
        assert d.oauth.issuer == "http://localhost:8000"
        assert d.oauth.issuer_from_request is False
        assert d.oauth.issuer_allowlist is None
        assert d.oauth.device_verification_base_url is None
        assert d.oauth.issuer_from_proxy_headers is False
        assert d.oauth.audience == "default"
        assert d.oauth.token_expiry_minutes == 60
        assert d.oauth.refresh_token_rotation is False
        assert d.oauth.require_pkce is False
        assert d.oauth.clients == []
        assert d.oauth.logos_dir is None
        assert d.saml.entity_id is None and d.saml.sso_url is None
        assert d.saml.default_acs_url == "http://localhost:8080/login/saml2/sso/samlIdp"
        assert d.saml.sign_responses is True
        assert d.saml.export_roles is False and d.saml.export_groups is False
        assert d.saml.roles_attr_name == "roles" and d.saml.groups_attr_name == "groups"
        assert d.saml.c14n_algorithm == "exc_c14n"
        assert d.saml.want_authn_requests_signed is False
        assert d.saml.sp_certificates is None
        assert d.saml.strict_binding is False
        assert d.jwt.algorithm == "RS256" and d.jwt.keys_dir == "./keys"
        assert d.session.secret_key == "dev-secret-key-change-in-production"
        assert d.session.require_ui_login is False
        assert d.session.enforce_password_check is False
        assert d.logging.level == "INFO"
        assert d.logging.log_token_requests is True
        assert d.logging.log_saml_requests is True
        assert d.logging.verbose_logging is True
        assert d.login.mode == "password"
        assert d.security_profile == "dev"
        assert d.authority_prefixes == {}
        assert d.allowed_identity_classes == []

    def test_empty_document_builds_the_same_settings_as_an_empty_file(self, tmp_path):
        (tmp_path / "settings.yaml").write_text("")
        (tmp_path / "users.yaml").write_text("users: {}\n")
        from_file = ConfigManager(str(tmp_path)).settings
        assert from_file.model_dump() == SettingsDocument().to_settings().model_dump()

    def test_user_entry_defaults(self):
        users, default_user = UsersDocument(users={"alice": {}}).to_users()
        assert default_user == "admin"
        alice = users["alice"]
        assert alice.password is None
        assert alice.email == "alice@example.org"
        assert alice.roles == ["USER"]
        assert alice.groups == [] and alice.entitlements == [] and alice.source_acl == []
        assert alice.tenant == "default"
        assert alice.identity_class is None
        assert alice.attributes == {}

    def test_document_defaults_mapping_matches_models(self):
        defaults = document_defaults()
        assert defaults["security_profile"] == "dev"
        assert defaults["login.mode"] == "password"
        assert defaults["saml.default_acs_url"] == SettingsDocument().saml.default_acs_url
        assert defaults["server.port"] == 8000


class TestShippedFilesLoadWithoutWarnings:
    """The document models must know every key a shipped file carries: a
    warning here means a key was dropped from the contract, not a typo in
    the preset. Placeholders are expanded first, as the loader does."""

    @pytest.mark.parametrize("path", SHIPPED_SETTINGS, ids=lambda p: str(p.relative_to(REPO)))
    def test_settings(self, path, caplog):
        data = expand_env_vars(copy.deepcopy(SHIPPED_SETTINGS_DATA[path]))
        with caplog.at_level(logging.WARNING, logger="nanoidp.config_documents"):
            document = load_settings_document(data, path)
        assert not [r for r in caplog.records if "unknown key" in r.getMessage()], caplog.text
        if path.parent.name == "react-spa-pkce":
            # Pre-existing, independent of this refactor: the preset ships a
            # public client with client_secret "" which OAuthClient refuses
            # (min_length=1). Tracked under #188 (public clients).
            with pytest.raises(ValueError, match="client_secret"):
                document.to_settings()
        else:
            document.to_settings()

    @pytest.mark.parametrize("path", SHIPPED_USERS, ids=lambda p: str(p.relative_to(REPO)))
    def test_users(self, path, caplog):
        with caplog.at_level(logging.WARNING, logger="nanoidp.config_documents"):
            load_users_document(copy.deepcopy(SHIPPED_USERS_DATA[path]), path).to_users()
        assert not [r for r in caplog.records if "unknown key" in r.getMessage()], caplog.text

    def test_shipped_config_loads_identically_through_config_manager(self):
        """Full path (ConfigManager) on the committed preset."""
        config = ConfigManager(str(REPO / "config"))
        doc = load_settings_document(
            expand_env_vars(copy.deepcopy(SHIPPED_SETTINGS_DATA[REPO / "config" / "settings.yaml"])), Path("x")
        )
        assert config.settings.model_dump() == doc.to_settings().model_dump()
        assert set(config.users) == set(SHIPPED_USERS_DATA[REPO / "config" / "users.yaml"]["users"])


class TestUnknownKeysAreReportedNotSwallowed:
    def test_top_level_unknown_key(self, tmp_path, caplog):
        cfg = _write(tmp_path, {"server": {"port": 8000}, "isuer": "x"})
        with caplog.at_level(logging.WARNING):
            settings = ConfigManager(cfg).settings
        assert "settings.yaml: unknown key isuer (ignored)" in caplog.text
        assert settings.port == 8000

    def test_nested_unknown_key_has_dotted_path(self, tmp_path, caplog):
        cfg = _write(tmp_path, {"oauth": {"isuer": "http://wrong", "audience": "a"}})
        with caplog.at_level(logging.WARNING):
            settings = ConfigManager(cfg).settings
        assert "unknown key oauth.isuer (ignored)" in caplog.text
        assert settings.issuer == "http://localhost:8000"  # the typo did not apply
        assert settings.audience == "a"

    def test_unknown_key_inside_a_client_entry(self, tmp_path, caplog):
        cfg = _write(tmp_path, {"oauth": {"clients": [
            {"client_id": "c", "client_secret": "s", "redirect_uri": "http://x/cb"},
        ]}})
        with caplog.at_level(logging.WARNING):
            settings = ConfigManager(cfg).settings
        assert "unknown key oauth.clients[0].redirect_uri (ignored)" in caplog.text
        assert settings.clients[0].client_id == "c"
        assert settings.clients[0].redirect_uris == []

    def test_identical_settings_with_and_without_the_unknown_key(self, tmp_path):
        base = {"oauth": {"audience": "a", "token_expiry_minutes": 5}}
        with_typo = {"oauth": {**base["oauth"], "isuer": "x"}, "bogus": 1}
        a = ConfigManager(_write(tmp_path, base)).settings.model_dump()
        b = ConfigManager(_write(tmp_path, with_typo)).settings.model_dump()
        assert a == b

    def test_wrong_type_is_a_clear_error_with_path(self, tmp_path):
        cfg = _write(tmp_path, {"server": {"port": "eighty"}})
        with pytest.raises(ValueError, match=r"settings\.yaml: invalid value at server\.port"):
            ConfigManager(cfg)

    def test_domain_validators_still_run(self, tmp_path):
        """Constraints live on Settings, not on the document: port 70000 is
        refused exactly as before."""
        cfg = _write(tmp_path, {"server": {"port": 70000}})
        with pytest.raises(ValueError):
            ConfigManager(cfg)

    def test_unknown_user_fields_still_become_attributes(self, tmp_path, caplog):
        cfg = _write(tmp_path, users={"users": {"bob": {"password": "x", "department": "R&D", "attributes": {"level": 3}}}})
        with caplog.at_level(logging.WARNING):
            config = ConfigManager(cfg)
        assert "unknown key" not in caplog.text
        assert config.users["bob"].attributes == {"level": 3, "department": "R&D"}

    def test_unknown_top_level_users_key_is_reported(self, tmp_path, caplog):
        cfg = _write(tmp_path, users={"users": {}, "defualt_user": "x"})
        with caplog.at_level(logging.WARNING):
            config = ConfigManager(cfg)
        assert "users.yaml: unknown key defualt_user (ignored)" in caplog.text
        assert config.default_user == "admin"


class TestEdgeConventionsPreserved:
    def test_placeholders_expand_before_validation(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MY_PORT", "8123")
        monkeypatch.setenv("ALICE_PW", "s3cret")
        cfg = _write(
            tmp_path,
            {"server": {"port": "${MY_PORT:8000}"}, "oauth": {"audience": "${NOPE:aud}"}},
            {"users": {"alice": {"password": "${ALICE_PW}"}}},
        )
        config = ConfigManager(cfg)
        assert config.settings.port == 8123
        assert config.settings.audience == "aud"
        assert config.users["alice"].password == "s3cret"

    def test_bare_login_is_empty_but_other_bare_sections_are_errors(self, tmp_path):
        """Only `login:` was special-cased by the old loader (`or {}`); a bare
        `oauth:` / `saml:` / `server:` was a type error and stays one (#197
        review: null and missing differ)."""
        (tmp_path / "settings.yaml").write_text("login:\n")
        (tmp_path / "users.yaml").write_text("users: {}\n")
        assert ConfigManager(str(tmp_path)).settings.login_mode == "password"
        for section in ("oauth", "saml", "server", "session", "jwt", "logging"):
            (tmp_path / "settings.yaml").write_text(f"{section}:\n")
            with pytest.raises(ValueError, match=f"invalid value at {section}"):
                ConfigManager(str(tmp_path))

    def test_blank_saml_urls_mean_derived(self, tmp_path):
        cfg = _write(tmp_path, {"saml": {"entity_id": "", "sso_url": ""}})
        settings = ConfigManager(cfg).settings
        assert settings.saml_entity_id is None and settings.saml_sso_url is None

    def test_null_collections_are_errors_except_where_the_old_loader_said_or(self, tmp_path):
        """`issuer_allowlist` and `sp_certificates` used `... or []` and keep
        accepting null; `clients`, `allowed_identity_classes` did not and a
        null there is a type error with its path, as before."""
        cfg = _write(tmp_path, {"oauth": {"issuer_allowlist": None}, "saml": {"sp_certificates": None}})
        settings = ConfigManager(cfg).settings
        assert settings.issuer_allowlist == [] and settings.saml_sp_certificates == []
        with pytest.raises(ValueError, match="invalid value at oauth.clients"):
            ConfigManager(_write(tmp_path, {"oauth": {"clients": None}}))
        with pytest.raises(ValueError, match="invalid value at allowed_identity_classes"):
            ConfigManager(_write(tmp_path, {"allowed_identity_classes": None}))

    def test_user_null_fields_are_errors_but_missing_fields_default(self, tmp_path):
        _write(tmp_path)
        (tmp_path / "users.yaml").write_text(yaml.safe_dump({"users": {"a": {"password": "x"}}}))
        user = ConfigManager(str(tmp_path)).users["a"]
        assert user.roles == ["USER"] and user.groups == [] and user.email == "a@example.org"
        for field in ("roles", "groups", "entitlements", "source_acl", "attributes", "email"):
            (tmp_path / "users.yaml").write_text(yaml.safe_dump({"users": {"a": {"password": "x", field: None}}}))
            with pytest.raises((ValueError, ValidationError)):
                ConfigManager(str(tmp_path))
        # null password and identity_class are valid (Optional in the domain model)
        (tmp_path / "users.yaml").write_text(yaml.safe_dump({"users": {"a": {"password": None, "identity_class": None}}}))
        assert ConfigManager(str(tmp_path)).users["a"].password is None
        # bare `users:` was a type error and stays one
        (tmp_path / "users.yaml").write_text("users:\n")
        with pytest.raises(ValueError, match="invalid value at users"):
            ConfigManager(str(tmp_path))

    def test_compatibility_keys_are_not_validated(self, tmp_path):
        """Keys the old loader never read must keep loading with any value."""
        cfg = _write(tmp_path, {
            "cors_allowed_origins": "*",
            "session": {"permanent": "whatever"},
            "logging": {"format": 42},
            "oauth": {"refresh_token_expiry_minutes": "soon"},
            "device_flow": {"polling_interval": "x", "code_expiry_seconds": None},
        })
        settings = ConfigManager(cfg).settings
        assert settings.cors_allowed_origins == ["*"]
        # the container shape was never read either: a scalar or a bare line loads
        for value in ("whatever", None, 3):
            ConfigManager(_write(tmp_path, {"device_flow": value}))

    def test_blank_saml_attr_names_fall_back_to_defaults(self, tmp_path):
        """A bare `roles_attr_name:` reached Settings as None and the domain
        before-validator turned it into the default; the document model must
        let None through instead of rejecting it (#197 review)."""
        cfg = _write(tmp_path, {"saml": {"roles_attr_name": None, "groups_attr_name": None}})
        settings = ConfigManager(cfg).settings
        assert settings.saml_roles_attr_name == "roles"
        assert settings.saml_groups_attr_name == "groups"
        cfg = _write(tmp_path, {"saml": {"roles_attr_name": "  ", "groups_attr_name": ""}})
        settings = ConfigManager(cfg).settings
        assert settings.saml_roles_attr_name == "roles"
        assert settings.saml_groups_attr_name == "groups"

    def test_scalar_redirect_uri_is_coerced_and_bad_shape_is_client_scoped(self, tmp_path):
        cfg = _write(tmp_path, {"oauth": {"clients": [{"client_id": "c", "client_secret": "s", "redirect_uris": "http://x/cb"}]}})
        assert ConfigManager(cfg).settings.clients[0].redirect_uris == ["http://x/cb"]
        cfg = _write(tmp_path, {"oauth": {"clients": [{"client_id": "c", "client_secret": "s", "redirect_uris": {"a": 1}}]}})
        with pytest.raises(ValueError, match="Client 'c': redirect_uris must be a string or a list"):
            ConfigManager(cfg)

    def test_duplicate_client_id_message_unchanged(self, tmp_path):
        cfg = _write(tmp_path, {"oauth": {"clients": [
            {"client_id": "foo", "client_secret": "a"}, {"client_id": "foo", "client_secret": "b"},
        ]}})
        with pytest.raises(ValueError, match="Duplicate OAuth client_id 'foo'"):
            ConfigManager(cfg)

    def test_compat_keys_are_accepted_but_not_consumed(self, tmp_path, caplog):
        cfg = _write(tmp_path, {
            "cors_allowed_origins": ["http://a"],
            "device_flow": {"code_expiry_seconds": 1, "polling_interval": 2},
            "logging": {"format": "%(message)s"},
            "oauth": {"refresh_token_expiry_minutes": 5},
            "session": {"permanent": True},
        })
        with caplog.at_level(logging.WARNING):
            settings = ConfigManager(cfg).settings
        assert "unknown key" not in caplog.text
        # exactly as before this refactor: the keys never reached Settings
        assert settings.cors_allowed_origins == ["*"]


class TestWriterUsesDocumentDefaults:
    def test_round_trip_of_shipped_config_keeps_placeholders_and_is_idempotent(self):
        """#127 conventions, unchanged by this refactor: serializing the
        loaded Settings back onto the loaded document leaves every ${VAR}
        placeholder in place (the writer compares expanded values), and a
        second pass is a no-op. (The first pass does materialize managed
        keys the file omitted, e.g. logging.verbose_logging; that is the
        pre-existing writer behaviour, pinned by test_issue_127.)"""
        path = REPO / "config" / "settings.yaml"
        document = load_yaml_document(path)
        settings = ConfigManager(str(REPO / "config")).settings
        apply_settings_document(document, settings, defaults=document_defaults())
        assert document["server"]["port"] == "${PORT:8000}"
        assert document["oauth"]["issuer"] == "http://localhost:${PORT:8000}"
        once = copy.deepcopy(document)
        apply_settings_document(document, settings, defaults=document_defaults())
        assert document == once

    def test_defaults_drive_omit_at_default(self):
        doc = {}
        apply_settings_document(doc, Settings(), defaults=document_defaults())
        assert "security_profile" not in doc and "login" not in doc
        apply_settings_document(doc, Settings(security_profile="oauth21", login_mode="persona"), defaults=document_defaults())
        assert doc["security_profile"] == "oauth21" and doc["login"]["mode"] == "persona"

    def test_fallback_without_defaults_still_works(self):
        doc = {}
        apply_settings_document(doc, Settings(security_profile="stricter-dev"))
        assert doc["security_profile"] == "stricter-dev"
