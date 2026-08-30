"""
REST API routes for management and monitoring.
"""

import logging

from flask import Blueprint, jsonify, request
from flask.typing import ResponseReturnValue

from ..config import get_config
from ..hooks import HookError
from ..services import get_audit_log, get_token_service
from ._auth import management_secret_required_for_api
from ._issuer import effective_issuer, effective_saml_entity_id, effective_saml_sso_url

logger = logging.getLogger(__name__)

api_bp = Blueprint("api", __name__, url_prefix="/api")
api_bp.before_request(management_secret_required_for_api)


@api_bp.route("/health")
def health() -> ResponseReturnValue:
    """Health check endpoint."""
    return jsonify({"status": "ok"})


@api_bp.route("/users")
def list_users() -> ResponseReturnValue:
    """List all configured users (without passwords)."""
    config = get_config()
    users = []
    for username, user in config.users.items():
        users.append({
            "username": username,
            "description": user.description,
            "email": user.email,
            "identity_class": user.identity_class,
            "roles": user.roles,
            "groups": user.groups,
            "tenant": user.tenant,
            "has_acl": len(user.source_acl) > 0,
            "has_entitlements": len(user.entitlements) > 0,
        })
    return jsonify({"users": users, "count": len(users)})


@api_bp.route("/users/<username>")
def get_user(username: str) -> ResponseReturnValue:
    """Get details for a specific user."""
    config = get_config()
    user = config.get_user(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    token_service = get_token_service()
    authorities = token_service.build_authorities(user)

    return jsonify({
        "username": user.username,
        "description": user.description,
        "email": user.email,
        "identity_class": user.identity_class,
        "entitlements": user.entitlements,
        "roles": user.roles,
        "groups": user.groups,
        "tenant": user.tenant,
        "source_acl": user.source_acl,
        "attributes": user.attributes,
        "authorities": authorities,
    })


@api_bp.route("/users/<username>/token", methods=["POST"])
def generate_token(username: str) -> ResponseReturnValue:
    """Generate a token for a user (for testing)."""
    config = get_config()
    user = config.get_user(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    body = request.get_json(silent=True) or {}
    exp_minutes = body.get("exp_minutes", config.settings.token_expiry_minutes)

    # Optional client binding (#73), mirroring the MCP generate_token tool: a
    # given client_id (which must name a real client) binds the token and issues
    # a spendable refresh token; without it the token is unbound and NO refresh
    # token is issued - since 3.0 a refresh token with no client_id binding is
    # refused, so returning one from this testing endpoint would be a dead
    # credential.
    client_id = body.get("client_id")
    if client_id is not None and config.get_client(client_id) is None:
        return jsonify({"error": f"Client '{client_id}' not found"}), 400

    token_service = get_token_service()
    # Same effective-issuer resolution as /token and discovery (#133): a
    # token minted here must verify against the discovery document that the
    # requesting hostname was just served.
    token_response = token_service.create_token(
        user=user,
        exp_minutes=exp_minutes,
        issuer=effective_issuer(config.settings),
        client_id=client_id,
        issue_refresh_token=client_id is not None,
    )

    return jsonify(token_response)


@api_bp.route("/audit")
def get_audit() -> ResponseReturnValue:
    """Get audit log entries."""
    audit = get_audit_log()

    limit = request.args.get("limit", 100, type=int)
    event_type = request.args.get("event_type")
    username = request.args.get("username")

    entries = audit.get_entries(limit=limit, event_type=event_type, username=username)

    return jsonify({
        "entries": entries,
        "count": len(entries),
    })


@api_bp.route("/audit/stats")
def get_audit_stats() -> ResponseReturnValue:
    """Get audit statistics."""
    audit = get_audit_log()
    return jsonify(audit.get_stats())


@api_bp.route("/audit/clear", methods=["POST"])
def clear_audit() -> ResponseReturnValue:
    """Clear the audit log."""
    audit = get_audit_log()
    audit.clear()
    return jsonify({"status": "cleared"})


@api_bp.route("/config")
def get_configuration() -> ResponseReturnValue:
    """Get current configuration (excluding secrets)."""
    config = get_config()
    settings = config.settings

    return jsonify({
        # Config schema version the loaded files follow (#175); absent = 1.
        "config_version": config.config_version,
        # Effective validation mode (#175 piece 4): strict from the CLI flag
        # or settings.yaml's config_validation; reported like security_profile
        # so the contract is observable.
        "config_validation": "strict" if config.strict_config else "warn",
        "server": {
            "host": settings.host,
            "port": settings.port,
        },
        "oauth": {
            "issuer": settings.issuer,
            "issuer_from_request": settings.issuer_from_request,
            # Companions of issuer_from_request: exposed so a config-agnostic
            # client (e2e/test_agent.py) can predict the effective issuer
            # instead of assuming an empty allowlist.
            "issuer_allowlist": settings.issuer_allowlist,
            "device_verification_base_url": settings.device_verification_base_url,
            "issuer_from_proxy_headers": settings.issuer_from_proxy_headers,
            "audience": settings.audience,
            "token_expiry_minutes": settings.token_expiry_minutes,
            "clients_count": len(settings.clients),
            # YAML-only (#186) - reported for visibility like the rest of
            # this block, never settable through this endpoint.
            "scopes_supported": settings.scopes_supported,
            "scope_enforcement": settings.scope_enforcement_active,
        },
        "saml": {
            # Effective values for THIS request (#181): explicit YAML value,
            # or derived from the effective issuer. The *_derived flags let a
            # client (the e2e agent rebuilding the settings form, an MCP
            # agent) tell the two apart, so it never posts a derived value
            # back as an explicit one and freezes it.
            "entity_id": effective_saml_entity_id(settings),
            "entity_id_derived": settings.saml_entity_id is None,
            "sso_url": effective_saml_sso_url(settings),
            "sso_url_derived": settings.saml_sso_url is None,
            # The e2e agent rebuilds the /settings form from this document, so
            # every form-editable SAML field must appear here - omitting one
            # makes the round-trip post it blank and the "blank = clear"
            # contract (#131) wipes it from settings.yaml (#165).
            "default_acs_url": settings.default_acs_url,
            "sign_responses": settings.saml_sign_responses,
            "c14n_algorithm": settings.saml_c14n_algorithm,
            "strict_binding": settings.strict_saml_binding,
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
        # Effective profile, i.e. after the CLI --profile override and the
        # stricter-dev hardening are applied (#172). profile_override tells
        # a client whether the value comes from the process, not the YAML.
        "security_profile": settings.security_profile,
        "profile_override": config.profile_override,
        "effective": {
            "require_pkce": settings.require_pkce,
            "password_hashing": settings.password_hashing,
            "rate_limit_enabled": settings.rate_limit_enabled,
            "debug": settings.debug,
        },
        # Hooks and plugins (#185): what is loaded, from which surface, and
        # the failure counters. YAML-only; reported, never settable here.
        "hooks": config.hooks.describe(),
        "users_count": len(config.users),
    })


@api_bp.route("/config/reload", methods=["POST"])
def reload_config() -> ResponseReturnValue:
    """Reload configuration from files."""
    config = get_config()
    try:
        config.reload()
    except HookError as exc:
        # A strict on_before_load or plugin-load failure is a JSON error, not
        # Flask's HTML 500: this endpoint's callers parse JSON. exc.message is
        # the registry's synthetic text (never a command, stderr or plugin
        # exception text) and exc.kind names the phase that failed.
        return jsonify({"status": "error", "error": exc.message, "kind": exc.kind}), 503
    return jsonify({
        "status": "reloaded",
        "users_count": len(config.users),
    })


@api_bp.route("/keys/rotate", methods=["POST"])
def rotate_keys() -> ResponseReturnValue:
    """Rotate cryptographic keys.

    Moves the current active key to 'previous' keys (kept for token validation)
    and generates a new active key for signing.

    Returns:
        JSON with old_kid, new_kid, and rotation details.
    """
    from ..services import get_crypto_service

    config = get_config()
    crypto = get_crypto_service(config.settings.keys_dir)

    result = crypto.rotate_keys()

    # Log to audit
    audit = get_audit_log()
    audit.log(
        event_type="key_rotation",
        endpoint="/api/keys/rotate",
        method="POST",
        username="api",
        status="success",
        details={"old_kid": result["old_kid"], "new_kid": result["new_kid"]},
    )

    logger.info(f"Key rotation completed via API: {result['old_kid']} → {result['new_kid']}")

    return jsonify({
        "success": True,
        **result,
    })


@api_bp.route("/keys/info")
def keys_info() -> ResponseReturnValue:
    """Get information about current cryptographic keys."""
    from ..services import get_crypto_service

    config = get_config()
    crypto = get_crypto_service(config.settings.keys_dir)

    return jsonify({
        "active_kid": crypto.kid,
        "previous_keys_count": len(crypto.previous_keys),
        "previous_kids": [k.kid for k in crypto.previous_keys],
        "max_previous_keys": crypto.max_previous_keys,
    })
