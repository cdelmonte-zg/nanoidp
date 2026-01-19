"""
Web UI routes for the NanoIDP dashboard.
"""

import logging
import secrets
from flask import Blueprint, render_template, request, session, redirect, url_for, flash, Response
import json
import csv
from io import StringIO

from ..config import get_config, User, OAuthClient
from ..services import get_audit_log, get_yaml_writer, get_token_service

logger = logging.getLogger(__name__)

ui_bp = Blueprint("ui", __name__)


# ==================== Dashboard ====================

@ui_bp.route("/")
def index():
    """Dashboard home page."""
    config = get_config()
    audit = get_audit_log()

    return render_template(
        "index.html",
        users_count=len(config.users),
        stats=audit.get_stats(),
        settings=config.settings,
        current_user=session.get("user"),
        recent_events=audit.get_entries(limit=5),
    )


# ==================== Authentication ====================

@ui_bp.route("/login", methods=["GET", "POST"])
def login():
    """Login page for web UI.

    Note: SAML SSO uses inline login at /saml/sso to preserve binding context.
    This endpoint is for direct web UI access only.
    """
    config = get_config()
    audit = get_audit_log()

    if request.method == "GET":
        error = request.args.get("error")
        return render_template(
            "login.html",
            error=error,
            users=list(config.users.keys()),
        )

    # POST: validate credentials
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    req_info = {
        "ip_address": request.remote_addr or "unknown",
        "user_agent": request.headers.get("User-Agent", "unknown"),
    }

    if not username or not password:
        return redirect(url_for("ui.login", error="Username and password required"))

    user = config.authenticate(username, password)
    if not user:
        audit.log(
            event_type="login",
            endpoint="/login",
            method="POST",
            status="failed",
            username=username,
            details={"reason": "Invalid credentials"},
            **req_info,
        )
        return redirect(url_for("ui.login", error="Invalid credentials"))

    # Create session
    session["user"] = username
    session.permanent = True

    audit.log(
        event_type="login",
        endpoint="/login",
        method="POST",
        status="success",
        username=username,
        **req_info,
    )

    return redirect(url_for("ui.index"))


@ui_bp.route("/logout")
def logout():
    """Logout and clear session."""
    username = session.get("user")
    session.clear()

    if username:
        audit = get_audit_log()
        audit.log(
            event_type="logout",
            endpoint="/logout",
            method="GET",
            status="success",
            username=username,
            ip_address=request.remote_addr or "unknown",
            user_agent=request.headers.get("User-Agent", "unknown"),
        )

    return redirect(url_for("ui.index"))


# ==================== Users Management ====================

@ui_bp.route("/users")
def users():
    """Users management page."""
    config = get_config()
    return render_template(
        "users.html",
        users=config.users,
        current_user=session.get("user"),
    )


@ui_bp.route("/users/create", methods=["GET", "POST"])
def user_create():
    """Create new user."""
    config = get_config()

    if request.method == "GET":
        return render_template(
            "users_form.html",
            user=None,
            allowed_identity_classes=config.settings.allowed_identity_classes,
            current_user=session.get("user"),
        )

    # POST: Create user
    try:
        username = request.form.get("username", "").strip()
        if not username:
            flash("Username is required", "error")
            return redirect(url_for("ui.user_create"))

        password = request.form.get("password", "")
        if not password:
            flash("Password is required for new users", "error")
            return redirect(url_for("ui.user_create"))

        # Parse roles and entitlements
        roles = [r.strip() for r in request.form.get("roles", "").split(",") if r.strip()]
        entitlements = [e.strip() for e in request.form.get("entitlements", "").split("\n") if e.strip()]
        source_acl = [a.strip() for a in request.form.get("source_acl", "").split("\n") if a.strip()]

        # Parse dynamic attributes
        attr_keys = request.form.getlist("attr_key[]")
        attr_values = request.form.getlist("attr_value[]")
        attributes = {}
        for key, value in zip(attr_keys, attr_values):
            key = key.strip()
            value = value.strip()
            if key and value:
                attributes[key] = value

        user = User(
            username=username,
            password=password,
            email=request.form.get("email", ""),
            identity_class=request.form.get("identity_class") or None,
            entitlements=entitlements,
            roles=roles,
            tenant=request.form.get("tenant", "default"),
            source_acl=source_acl,
            attributes=attributes,
        )

        yaml_writer = get_yaml_writer()
        yaml_writer.save_user(user, is_new=True)

        flash(f"User '{username}' created successfully", "success")
        return redirect(url_for("ui.user_detail", username=username))

    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("ui.user_create"))
    except Exception as e:
        logger.exception("Failed to create user")
        flash(f"Failed to create user: {e}", "error")
        return redirect(url_for("ui.user_create"))


@ui_bp.route("/users/<username>")
def user_detail(username: str):
    """User detail page."""
    config = get_config()

    user = config.get_user(username)
    if not user:
        flash(f"User '{username}' not found", "error")
        return redirect(url_for("ui.users"))

    token_service = get_token_service()
    authorities = token_service.build_authorities(user)

    return render_template(
        "user_detail.html",
        user=user,
        authorities=authorities,
        current_user=session.get("user"),
    )


@ui_bp.route("/users/<username>/edit", methods=["GET", "POST"])
def user_edit(username: str):
    """Edit user."""
    config = get_config()

    user = config.get_user(username)
    if not user:
        flash(f"User '{username}' not found", "error")
        return redirect(url_for("ui.users"))

    if request.method == "GET":
        return render_template(
            "users_form.html",
            user=user,
            allowed_identity_classes=config.settings.allowed_identity_classes,
            current_user=session.get("user"),
        )

    # POST: Update user
    try:
        # Get password - keep existing if not provided
        password = request.form.get("password", "")
        if not password:
            password = user.password

        # Parse roles and entitlements
        roles = [r.strip() for r in request.form.get("roles", "").split(",") if r.strip()]
        entitlements = [e.strip() for e in request.form.get("entitlements", "").split("\n") if e.strip()]
        source_acl = [a.strip() for a in request.form.get("source_acl", "").split("\n") if a.strip()]

        # Parse dynamic attributes
        attr_keys = request.form.getlist("attr_key[]")
        attr_values = request.form.getlist("attr_value[]")
        attributes = {}
        for key, value in zip(attr_keys, attr_values):
            key = key.strip()
            value = value.strip()
            if key and value:
                attributes[key] = value

        updated_user = User(
            username=username,
            password=password,
            email=request.form.get("email", ""),
            identity_class=request.form.get("identity_class") or None,
            entitlements=entitlements,
            roles=roles,
            tenant=request.form.get("tenant", "default"),
            source_acl=source_acl,
            attributes=attributes,
        )

        yaml_writer = get_yaml_writer()
        yaml_writer.save_user(updated_user, is_new=False)

        flash(f"User '{username}' updated successfully", "success")
        return redirect(url_for("ui.user_detail", username=username))

    except Exception as e:
        logger.exception("Failed to update user")
        flash(f"Failed to update user: {e}", "error")
        return redirect(url_for("ui.user_edit", username=username))


@ui_bp.route("/users/<username>/delete", methods=["POST"])
def user_delete(username: str):
    """Delete user."""
    try:
        yaml_writer = get_yaml_writer()
        yaml_writer.delete_user(username)

        flash(f"User '{username}' deleted successfully", "success")
        return redirect(url_for("ui.users"))

    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("ui.users"))
    except Exception as e:
        logger.exception("Failed to delete user")
        flash(f"Failed to delete user: {e}", "error")
        return redirect(url_for("ui.users"))


# ==================== OAuth Clients Management ====================

@ui_bp.route("/clients")
def clients():
    """OAuth clients management page."""
    config = get_config()
    return render_template(
        "clients.html",
        clients=config.settings.clients,
        current_user=session.get("user"),
    )


@ui_bp.route("/clients/create", methods=["GET", "POST"])
def client_create():
    """Create new OAuth client."""
    if request.method == "GET":
        # Generate a random client secret
        generated_secret = secrets.token_urlsafe(32)
        return render_template(
            "clients_form.html",
            client=None,
            generated_secret=generated_secret,
            current_user=session.get("user"),
        )

    # POST: Create client
    try:
        client_id = request.form.get("client_id", "").strip()
        if not client_id:
            flash("Client ID is required", "error")
            return redirect(url_for("ui.client_create"))

        client_secret = request.form.get("client_secret", "").strip()
        if not client_secret:
            flash("Client Secret is required", "error")
            return redirect(url_for("ui.client_create"))

        client = OAuthClient(
            client_id=client_id,
            client_secret=client_secret,
            description=request.form.get("description", ""),
        )

        yaml_writer = get_yaml_writer()
        yaml_writer.save_client(client, is_new=True)

        flash(f"OAuth client '{client_id}' created successfully", "success")
        return redirect(url_for("ui.clients"))

    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("ui.client_create"))
    except Exception as e:
        logger.exception("Failed to create client")
        flash(f"Failed to create client: {e}", "error")
        return redirect(url_for("ui.client_create"))


@ui_bp.route("/clients/<client_id>/edit", methods=["GET", "POST"])
def client_edit(client_id: str):
    """Edit OAuth client."""
    config = get_config()

    # Find the client
    client = None
    for c in config.settings.clients:
        if c.client_id == client_id:
            client = c
            break

    if not client:
        flash(f"Client '{client_id}' not found", "error")
        return redirect(url_for("ui.clients"))

    if request.method == "GET":
        return render_template(
            "clients_form.html",
            client=client,
            generated_secret=None,
            current_user=session.get("user"),
        )

    # POST: Update client
    try:
        client_secret = request.form.get("client_secret", "").strip()
        if not client_secret:
            # Keep existing secret
            client_secret = client.client_secret

        updated_client = OAuthClient(
            client_id=client_id,
            client_secret=client_secret,
            description=request.form.get("description", ""),
        )

        yaml_writer = get_yaml_writer()
        yaml_writer.save_client(updated_client, is_new=False)

        flash(f"OAuth client '{client_id}' updated successfully", "success")
        return redirect(url_for("ui.clients"))

    except Exception as e:
        logger.exception("Failed to update client")
        flash(f"Failed to update client: {e}", "error")
        return redirect(url_for("ui.client_edit", client_id=client_id))


@ui_bp.route("/clients/<client_id>/delete", methods=["POST"])
def client_delete(client_id: str):
    """Delete OAuth client."""
    try:
        yaml_writer = get_yaml_writer()
        yaml_writer.delete_client(client_id)

        flash(f"OAuth client '{client_id}' deleted successfully", "success")
        return redirect(url_for("ui.clients"))

    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("ui.clients"))
    except Exception as e:
        logger.exception("Failed to delete client")
        flash(f"Failed to delete client: {e}", "error")
        return redirect(url_for("ui.clients"))


@ui_bp.route("/clients/<client_id>/regenerate-secret", methods=["POST"])
def client_regenerate_secret(client_id: str):
    """Regenerate OAuth client secret."""
    config = get_config()

    # Find the client
    client = None
    for c in config.settings.clients:
        if c.client_id == client_id:
            client = c
            break

    if not client:
        flash(f"Client '{client_id}' not found", "error")
        return redirect(url_for("ui.clients"))

    try:
        new_secret = secrets.token_urlsafe(32)

        updated_client = OAuthClient(
            client_id=client_id,
            client_secret=new_secret,
            description=client.description,
        )

        yaml_writer = get_yaml_writer()
        yaml_writer.save_client(updated_client, is_new=False)

        flash(f"New secret for '{client_id}': {new_secret}", "success")
        return redirect(url_for("ui.clients"))

    except Exception as e:
        logger.exception("Failed to regenerate client secret")
        flash(f"Failed to regenerate secret: {e}", "error")
        return redirect(url_for("ui.clients"))


# ==================== Settings ====================

@ui_bp.route("/settings", methods=["GET", "POST"])
def settings():
    """IdP settings configuration page."""
    config = get_config()

    if request.method == "GET":
        return render_template(
            "settings.html",
            settings=config.settings,
            current_user=session.get("user"),
        )

    # POST: Update settings
    try:
        yaml_writer = get_yaml_writer()

        # OAuth settings
        yaml_writer.update_oauth_settings(
            issuer=request.form.get("issuer"),
            audience=request.form.get("audience"),
            token_expiry_minutes=int(request.form.get("token_expiry_minutes", 60)),
        )

        # SAML settings
        yaml_writer.update_saml_settings(
            entity_id=request.form.get("saml_entity_id"),
            sso_url=request.form.get("saml_sso_url"),
            default_acs_url=request.form.get("default_acs_url"),
            sign_responses=request.form.get("saml_sign_responses") == "true",
            strict_binding=request.form.get("strict_saml_binding") == "true",
            c14n_algorithm=request.form.get("saml_c14n_algorithm"),
        )

        # Identity classes
        identity_classes = [ic.strip() for ic in request.form.get("allowed_identity_classes", "").split("\n") if ic.strip()]
        if identity_classes:
            yaml_writer.update_allowed_identity_classes(identity_classes)

        flash("Settings updated successfully", "success")
        return redirect(url_for("ui.settings"))

    except Exception as e:
        logger.exception("Failed to update settings")
        flash(f"Failed to update settings: {e}", "error")
        return redirect(url_for("ui.settings"))


# ==================== Keys Management ====================

@ui_bp.route("/keys")
def keys():
    """Keys and certificates management page."""
    import os
    from pathlib import Path
    from datetime import datetime
    config = get_config()
    from ..services import get_crypto_service

    crypto = get_crypto_service(config.settings.keys_dir)

    # Get key file modification time as proxy for creation date
    keys_dir = Path(config.settings.keys_dir)
    kid_file = keys_dir / "kid.txt"
    key_created = None
    if kid_file.exists():
        key_created = datetime.fromtimestamp(os.path.getmtime(kid_file)).strftime("%Y-%m-%d %H:%M:%S")

    # Get previous keys info
    previous_keys = []
    for prev_key in crypto.previous_keys:
        previous_keys.append({
            "kid": prev_key.kid,
            "created_at": prev_key.created_at if prev_key.created_at else "Unknown",
        })

    return render_template(
        "keys.html",
        kid=crypto.kid,
        public_key_pem=crypto.pub_pem.decode("utf-8"),
        certificate_pem=crypto.cert_pem.decode("utf-8") if crypto.cert_pem else None,
        keys_dir=config.settings.keys_dir,
        settings=config.settings,
        current_user=session.get("user"),
        key_created=key_created,
        previous_keys=previous_keys,
        max_previous_keys=config.settings.max_previous_keys,
    )


@ui_bp.route("/keys/regenerate", methods=["POST"])
def keys_regenerate():
    """Regenerate RSA keys and certificate."""
    config = get_config()
    from ..services import get_crypto_service

    try:
        crypto = get_crypto_service(config.settings.keys_dir)
        crypto.regenerate_keys()

        flash("Keys and certificate regenerated successfully", "success")
        return redirect(url_for("ui.keys"))

    except Exception as e:
        logger.exception("Failed to regenerate keys")
        flash(f"Failed to regenerate keys: {e}", "error")
        return redirect(url_for("ui.keys"))


@ui_bp.route("/keys/download/<key_type>")
def keys_download(key_type: str):
    """Download key or certificate."""
    config = get_config()
    from ..services import get_crypto_service

    crypto = get_crypto_service(config.settings.keys_dir)

    if key_type == "public_key":
        return Response(
            crypto.pub_pem,
            mimetype="application/x-pem-file",
            headers={"Content-Disposition": "attachment; filename=public_key.pem"}
        )
    elif key_type == "certificate":
        return Response(
            crypto.cert_pem,
            mimetype="application/x-pem-file",
            headers={"Content-Disposition": "attachment; filename=idp-cert.pem"}
        )
    else:
        flash("Invalid key type", "error")
        return redirect(url_for("ui.keys"))


# ==================== Claims Configuration ====================

@ui_bp.route("/claims", methods=["GET", "POST"])
def claims():
    """Claims and authority prefixes configuration."""
    config = get_config()

    if request.method == "GET":
        return render_template(
            "claims.html",
            settings=config.settings,
            current_user=session.get("user"),
        )

    # POST: Update authority prefixes
    try:
        yaml_writer = get_yaml_writer()

        prefixes = {}

        # Core prefixes
        for key in ["roles", "identity_class", "entitlements"]:
            value = request.form.get(f"prefix_{key}", "").strip()
            if value:
                prefixes[key] = value

        # Custom attribute prefixes
        custom_keys = request.form.getlist("custom_prefix_key[]")
        custom_values = request.form.getlist("custom_prefix_value[]")
        for key, value in zip(custom_keys, custom_values):
            key = key.strip()
            value = value.strip()
            if key and value:
                prefixes[key] = value

        yaml_writer.update_authority_prefixes(prefixes)

        flash("Authority prefixes updated successfully", "success")
        return redirect(url_for("ui.claims"))

    except Exception as e:
        logger.exception("Failed to update authority prefixes")
        flash(f"Failed to update prefixes: {e}", "error")
        return redirect(url_for("ui.claims"))


@ui_bp.route("/claims/preview/<username>")
def claims_preview(username: str):
    """Preview token claims for a user (AJAX endpoint)."""
    config = get_config()

    user = config.get_user(username)
    if not user:
        return {"error": "User not found"}, 404

    token_service = get_token_service()
    authorities = token_service.build_authorities(user)

    return {
        "username": user.username,
        "authorities": authorities,
        "claims": {
            "identity_class": user.identity_class,
            "entitlements": user.entitlements,
            "roles": user.roles,
            "tenant": user.tenant,
            "source_acl": user.source_acl,
            "attributes": user.attributes,
        }
    }


# ==================== Audit Log ====================

@ui_bp.route("/audit")
def audit():
    """Audit log page."""
    audit_log = get_audit_log()

    limit = request.args.get("limit", 50, type=int)
    event_type = request.args.get("event_type") or None
    client_id = request.args.get("client_id") or None
    search = request.args.get("search", "").strip() or None

    entries = audit_log.get_entries(limit=limit, event_type=event_type, client_id=client_id)

    # Apply search filter if provided
    if search:
        search_lower = search.lower()
        entries = [
            e for e in entries
            if search_lower in str(e.get("username", "")).lower()
            or search_lower in str(e.get("endpoint", "")).lower()
            or search_lower in str(e.get("event_type", "")).lower()
            or search_lower in str(e.get("client_id", "")).lower()
            or search_lower in str(e.get("details", "")).lower()
        ]

    stats = audit_log.get_stats()
    client_ids = audit_log.get_unique_client_ids()

    return render_template(
        "audit.html",
        entries=entries,
        stats=stats,
        limit=limit,
        event_type=event_type,
        client_id=client_id,
        client_ids=client_ids,
        search=search,
        current_user=session.get("user"),
    )


@ui_bp.route("/audit/export/<format>")
def audit_export(format: str):
    """Export audit log with applied filters."""
    audit_log = get_audit_log()

    # Get filter parameters from query string
    limit = request.args.get("limit", 1000, type=int)
    event_type = request.args.get("event_type") or None
    client_id = request.args.get("client_id") or None

    # Use higher limit for exports but still respect filters
    entries = audit_log.get_entries(limit=limit, event_type=event_type, client_id=client_id)

    # Build filename with filter info
    filename_parts = ["audit_log"]
    if event_type:
        filename_parts.append(event_type)
    if client_id:
        filename_parts.append(client_id)
    filename = "_".join(filename_parts)

    if format == "json":
        return Response(
            json.dumps(entries, indent=2, default=str),
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment; filename={filename}.json"}
        )
    elif format == "csv":
        output = StringIO()
        if entries:
            writer = csv.DictWriter(output, fieldnames=entries[0].keys())
            writer.writeheader()
            for entry in entries:
                # Flatten any nested dicts
                flat_entry = {k: json.dumps(v) if isinstance(v, (dict, list)) else v for k, v in entry.items()}
                writer.writerow(flat_entry)

        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}.csv"}
        )
    else:
        flash("Invalid export format", "error")
        return redirect(url_for("ui.audit"))


@ui_bp.route("/audit/clear", methods=["POST"])
def audit_clear():
    """Clear the audit log."""
    audit_log = get_audit_log()
    audit_log.clear()

    flash("Audit log cleared", "success")
    return redirect(url_for("ui.audit"))


# ==================== Token Testing ====================

@ui_bp.route("/test")
def test_page():
    """Token testing page."""
    config = get_config()
    return render_template(
        "test.html",
        users=list(config.users.keys()),
        current_user=session.get("user"),
        settings=config.settings,
    )
