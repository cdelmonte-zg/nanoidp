"""Settings, config lifecycle, discovery, audit and key tool handlers (#286).

Split out of the monolithic mcp_server module; bodies unchanged - including
the #229 revision-precondition semantics on save_config and the settings
normalizer table contract (tests/test_settings_plumbing_parity.py).
"""

from typing import Any

from ..config import ConfigManager, ReloadAfterSaveError
from ..config_validation import validate_config_result
from ..config_writer import ConflictError, LockUnavailableError
from ..hooks import HookError
from ..services import (
    build_discovery_document,
    get_audit_log,
    get_crypto_service,
)
from .normalize import _UPDATE_SETTINGS_FIELDS, _UPDATE_SETTINGS_NORMALIZERS


# Configuration
def _tool_get_settings(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    settings = config.settings
    return {
        # Same key as GET /api/config (#175): the contract an agent targets.
        "config_version": config.config_version,
        "config_validation": "strict" if config.strict_config else "warn",
        # The settings.yaml revision this runtime was loaded from (#229
        # phase 5), for save_config's expected_settings_revision.
        "settings_revision": config.settings_revision,
        "issuer": settings.issuer,
        "issuer_from_request": settings.issuer_from_request,
        "issuer_allowlist": settings.issuer_allowlist,
        "device_verification_base_url": settings.device_verification_base_url,
        "issuer_from_proxy_headers": settings.issuer_from_proxy_headers,
        "audience": settings.audience,
        "token_expiry_minutes": settings.token_expiry_minutes,
        # YAML-only (oauth.scopes_supported / oauth.scope_enforcement, #186)
        # - reported for visibility, like secret_key and require_ui_login,
        # but not in update_settings' input_schema below.
        "scopes_supported": settings.scopes_supported,
        "scope_enforcement": settings.scope_enforcement_active,
        "security_profile": settings.security_profile,
        # Same as GET /api/config (#172): whether the profile comes from
        # the CLI, and the values the effective profile forces.
        "profile_override": config.profile_override,
        "effective": {
            "require_pkce": settings.require_pkce,
            "password_hashing": settings.password_hashing,
            "rate_limit_enabled": settings.rate_limit_enabled,
            "debug": settings.debug,
        },
        "login_mode": settings.login_mode,
        "auto_login": settings.auto_login,
        "rate_limit_enabled": settings.rate_limit_enabled,
        "rate_limit_token_endpoint": settings.rate_limit_token_endpoint,
        "refresh_token_rotation": settings.refresh_token_rotation,
        "require_pkce": settings.require_pkce,
        "jwt_algorithm": settings.jwt_algorithm,
        "saml": {
            # MCP has no HTTP request, so derived values (#181) resolve
            # against the fixed settings.issuer, the same exception the
            # MCP discovery tools already make for issuer_from_request.
            "entity_id": settings.resolve_saml_entity_id(settings.issuer),
            "entity_id_derived": settings.saml_entity_id is None,
            "sso_url": settings.resolve_saml_sso_url(settings.issuer),
            "sso_url_derived": settings.saml_sso_url is None,
            "sign_responses": settings.saml_sign_responses,
            "c14n_algorithm": settings.saml_c14n_algorithm,
            "strict_binding": settings.strict_saml_binding,
            "want_authn_requests_signed": (settings.saml_want_authn_requests_signed),
            "sp_certificates": settings.saml_sp_certificates,
            "export_roles": settings.saml_export_roles,
            "export_groups": settings.saml_export_groups,
            "roles_attr_name": settings.saml_roles_attr_name,
            "groups_attr_name": settings.saml_groups_attr_name,
        },
        "logging": {
            "verbose_logging": settings.verbose_logging,
        },
        "authority_prefixes": settings.authority_prefixes,
        "allowed_identity_classes": settings.allowed_identity_classes,
        # Hooks and plugins (#185): same block as GET /api/config.
        "hooks": config.hooks.describe(),
    }


def _tool_reload_config(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    try:
        config.reload()
    except HookError as exc:
        return {"success": False, "error": f"Reload failed: {exc.message}", "kind": exc.kind}
    # Fresh revisions right in the response (#229 phase 5): after a
    # save_config conflict, reload -> reapply the change -> save with
    # these, without another read call in between.
    return {
        "success": True,
        "message": "Configuration reloaded",
        "users_revision": config.users_revision,
        "settings_revision": config.settings_revision,
    }


def _tool_validate_config(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    # The CLI's code path exactly (nanoidp.config_validation): no
    # ConfigManager is built, no hook runs, no plugin is imported, and
    # the running configuration is not touched or reloaded.
    # strict defaults to the manager's effective mode, so "what the next
    # reload would hit" stays true for a ConfigManager started with
    # --strict-config (#204 review); an explicit argument still wins.
    strict_arg = arguments.get("strict")
    effective = config.strict_config if strict_arg is None else bool(strict_arg)
    return validate_config_result(config.config_dir, effective)



def _tool_update_settings(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    settings = config.settings

    # Settings (unlike OAuthClient) has no validate_assignment, but the
    # tool's input_schema declares "enum": ["password", "persona"] for
    # login_mode, so call_tool()'s jsonschema pass already rejects an
    # invalid value before this handler ever runs.
    updated = []
    for field in _UPDATE_SETTINGS_FIELDS:
        if field not in arguments:
            continue
        value = arguments[field]
        normalize = _UPDATE_SETTINGS_NORMALIZERS.get(field)
        if normalize is not None:
            value = normalize(field, value)
        setattr(settings, field, value)
        updated.append(field)

    return {
        "success": True,
        "updated_fields": updated,
        "current_settings": {
            "issuer": settings.issuer,
            "issuer_from_request": settings.issuer_from_request,
            "issuer_allowlist": settings.issuer_allowlist,
            "device_verification_base_url": settings.device_verification_base_url,
            "issuer_from_proxy_headers": settings.issuer_from_proxy_headers,
            "audience": settings.audience,
            "token_expiry_minutes": settings.token_expiry_minutes,
            "refresh_token_rotation": settings.refresh_token_rotation,
            "require_pkce": settings.require_pkce,
            "login_mode": settings.login_mode,
            "auto_login": settings.auto_login,
            "saml_sign_responses": settings.saml_sign_responses,
            "saml_c14n_algorithm": settings.saml_c14n_algorithm,
            "strict_saml_binding": settings.strict_saml_binding,
            "saml_want_authn_requests_signed": (settings.saml_want_authn_requests_signed),
            "saml_sp_certificates": settings.saml_sp_certificates,
            "saml_export_roles": settings.saml_export_roles,
            "saml_export_groups": settings.saml_export_groups,
            "saml_roles_attr_name": settings.saml_roles_attr_name,
            "saml_groups_attr_name": settings.saml_groups_attr_name,
            "verbose_logging": settings.verbose_logging,
        },
    }


def _tool_save_config(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    try:
        # Optional preconditions (#229 phase 5): the revisions a read tool
        # (list_users/get_user, list_clients/get_client/get_settings) or
        # reload_config handed back. save() always writes BOTH files, so
        # there are exactly two modes and no third (#252 review): with no
        # revision supplied the save is unconditional last-write-wins,
        # same as save()'s own default and the UI's revision-less forms;
        # with EITHER revision supplied the whole save is conflict-checked,
        # the omitted one defaulting to the revision this runtime was
        # loaded from. Passing a caller's partial precondition straight
        # through would guard one file while this runtime's stale snapshot
        # silently overwrote the other - the exact lost update the
        # revisions exist to catch. "is None", not falsy: an explicit
        # empty string is a supplied (and stale) revision, refused as a
        # conflict rather than silently replaced.
        users_rev = arguments.get("expected_users_revision")
        settings_rev = arguments.get("expected_settings_revision")
        if users_rev is not None or settings_rev is not None:
            if users_rev is None:
                users_rev = config.users_revision
            if settings_rev is None:
                settings_rev = config.settings_revision
        config.save(
            expected_users_revision=users_rev,
            expected_settings_revision=settings_rev,
        )
        # The post-save reload refreshed the tracked revisions to what was
        # just written, so a follow-up save can chain from this response.
        return {
            "success": True,
            "message": "Configuration saved to YAML files",
            "users_revision": config.users_revision,
            "settings_revision": config.settings_revision,
        }
    except ConflictError as exc:
        # Nothing was written - a supplied expected_*_revision was stale.
        return {"success": False, "error": exc.message, "kind": exc.kind}
    except LockUnavailableError as exc:
        # Nothing was written either - the lock is acquired before
        # compare_and_replace_many touches any file (#229 review,
        # blocking 4). "lock_timeout" is worth retrying; the file's
        # filesystem does not support advisory locks at all under
        # "lock_unsupported", which a retry cannot fix.
        return {"success": False, "error": exc.message, "kind": exc.kind}
    except HookError as exc:
        # Both files were written; only the on_config_saved mirror push
        # failed under hooks.strict (#229).
        return {"success": False, "error": f"Save succeeded, mirror failed: {exc.message}", "kind": exc.kind}
    except ReloadAfterSaveError as exc:
        # Both files were written, but the runtime could not reload what
        # was just saved - the file on disk is authoritative; a caller
        # should not retry save() expecting a different outcome (#229
        # review, blocking 3).
        return {"success": False, "error": exc.message, "kind": exc.kind}
    except Exception as e:
        return {"success": False, "error": f"Failed to save config: {str(e)}"}




# Discovery
def _tool_get_oidc_discovery(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    # Shared with the HTTP /.well-known/openid-configuration endpoint so
    # the two documents can never drift apart (issue #40).
    return build_discovery_document(config.settings)


def _tool_get_jwks(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    crypto = get_crypto_service(config.settings.keys_dir)
    return crypto.get_jwks()


# Audit log (mirrors /api/audit*, issue #48)
def _tool_get_audit_log(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    audit = get_audit_log()
    entries = audit.get_entries(
        limit=arguments.get("limit", 100),
        event_type=arguments.get("event_type"),
        username=arguments.get("username"),
    )
    return {"entries": entries, "count": len(entries)}


def _tool_get_audit_stats(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    return get_audit_log().get_stats()


def _tool_clear_audit_log(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    get_audit_log().clear()
    return {"success": True, "message": "Audit log cleared"}


# Key management (mirrors /api/keys*, issue #48)
def _tool_get_keys_info(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    crypto = get_crypto_service(config.settings.keys_dir)
    return {
        "active_kid": crypto.kid,
        "previous_keys_count": len(crypto.previous_keys),
        "previous_kids": [k.kid for k in crypto.previous_keys],
        "max_previous_keys": crypto.max_previous_keys,
    }


def _tool_rotate_keys(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    crypto = get_crypto_service(config.settings.keys_dir)
    result = crypto.rotate_keys()
    get_audit_log().log(
        event_type="key_rotation",
        endpoint="mcp:rotate_keys",
        method="MCP",
        username="mcp",
        status="success",
        details={"old_kid": result["old_kid"], "new_kid": result["new_kid"]},
    )
    return {"success": True, **result}
