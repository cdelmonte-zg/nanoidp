"""
REST API routes for management and monitoring.
"""

import logging
from flask import Blueprint, jsonify, request

from ..config import get_config
from ..services import get_audit_log, get_token_service

logger = logging.getLogger(__name__)

api_bp = Blueprint("api", __name__, url_prefix="/api")


@api_bp.route("/health")
def health():
    """Health check endpoint."""
    return jsonify({"status": "ok"})


@api_bp.route("/users")
def list_users():
    """List all configured users (without passwords)."""
    config = get_config()
    users = []
    for username, user in config.users.items():
        users.append({
            "username": username,
            "email": user.email,
            "identity_class": user.identity_class,
            "roles": user.roles,
            "tenant": user.tenant,
            "has_acl": len(user.source_acl) > 0,
            "has_entitlements": len(user.entitlements) > 0,
        })
    return jsonify({"users": users, "count": len(users)})


@api_bp.route("/users/<username>")
def get_user(username: str):
    """Get details for a specific user."""
    config = get_config()
    user = config.get_user(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    token_service = get_token_service()
    authorities = token_service.build_authorities(user)

    return jsonify({
        "username": user.username,
        "email": user.email,
        "identity_class": user.identity_class,
        "entitlements": user.entitlements,
        "roles": user.roles,
        "tenant": user.tenant,
        "source_acl": user.source_acl,
        "attributes": user.attributes,
        "authorities": authorities,
    })


@api_bp.route("/users/<username>/token", methods=["POST"])
def generate_token(username: str):
    """Generate a token for a user (for testing)."""
    config = get_config()
    user = config.get_user(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    exp_minutes = request.json.get("exp_minutes", config.settings.token_expiry_minutes) if request.is_json else config.settings.token_expiry_minutes

    token_service = get_token_service()
    token_response = token_service.create_token(user=user, exp_minutes=exp_minutes)

    return jsonify(token_response)


@api_bp.route("/audit")
def get_audit():
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
def get_audit_stats():
    """Get audit statistics."""
    audit = get_audit_log()
    return jsonify(audit.get_stats())


@api_bp.route("/audit/clear", methods=["POST"])
def clear_audit():
    """Clear the audit log."""
    audit = get_audit_log()
    audit.clear()
    return jsonify({"status": "cleared"})


@api_bp.route("/config")
def get_configuration():
    """Get current configuration (excluding secrets)."""
    config = get_config()
    settings = config.settings

    return jsonify({
        "server": {
            "host": settings.host,
            "port": settings.port,
        },
        "oauth": {
            "issuer": settings.issuer,
            "audience": settings.audience,
            "token_expiry_minutes": settings.token_expiry_minutes,
            "clients_count": len(settings.clients),
        },
        "saml": {
            "entity_id": settings.saml_entity_id,
            "sso_url": settings.saml_sso_url,
        },
        "authority_prefixes": settings.authority_prefixes,
        "allowed_identity_classes": settings.allowed_identity_classes,
        "users_count": len(config.users),
    })


@api_bp.route("/config/reload", methods=["POST"])
def reload_config():
    """Reload configuration from files."""
    config = get_config()
    config.reload()
    return jsonify({
        "status": "reloaded",
        "users_count": len(config.users),
    })


@api_bp.route("/keys/rotate", methods=["POST"])
def rotate_keys():
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
def keys_info():
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
