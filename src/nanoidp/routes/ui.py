"""
Web UI routes for the NanoIDP dashboard.
"""

import csv
import json
import logging
import secrets
from io import StringIO

from flask import (
    Blueprint,
    Response,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask.typing import ResponseReturnValue

from ..branding import effective_logos_dir
from ..config import OAuthClient, User, get_config
from ..hooks import HookError
from ..services import get_audit_log, get_token_service, get_yaml_writer
from ._audit import audit_event
from ._auth import (
    management_secret_required_for_ui,
    mark_management_verified,
    ui_login_required,
    verify_management_secret,
)
from ._issuer import effective_saml_entity_id, effective_saml_sso_url

logger = logging.getLogger(__name__)

ui_bp = Blueprint("ui", __name__)
ui_bp.before_request(ui_login_required)
ui_bp.before_request(management_secret_required_for_ui)


# ==================== Dashboard ====================

@ui_bp.route("/")
def index() -> ResponseReturnValue:
    """Dashboard home page."""
    config = get_config()
    audit = get_audit_log()

    return render_template(
        "index.html",
        users_count=len(config.users),
        saml_entity_id=effective_saml_entity_id(config.settings),
        stats=audit.get_stats(),
        settings=config.settings,
        current_user=session.get("user"),
        recent_events=audit.get_entries(limit=5),
    )


# ==================== Authentication ====================

@ui_bp.route("/login", methods=["GET", "POST"])
def login() -> ResponseReturnValue:
    """Login page for web UI.

    Note: SAML SSO uses inline login at /saml/sso to preserve binding context.
    This endpoint is for direct web UI access only.
    """
    config = get_config()
    persona_mode = config.settings.persona_mode_enabled

    if request.method == "GET":
        error = request.args.get("error")
        return render_template(
            "login.html",
            error=error,
            users=list(config.users.keys()),
            persona_mode=persona_mode,
            management_secret_configured=bool(config.settings.management_secret),
        )

    # POST: persona mode selects a user by identity, no password prompt;
    # password mode is unchanged.
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if (persona_mode and not username) or (not persona_mode and (not username or not password)):
        error = "Select a user" if persona_mode else "Username and password required"
        return redirect(url_for("ui.login", error=error))

    user = config.interactive_authenticate(username, password)

    if not user:
        audit_event(
            "login",
            "failed",
            endpoint="/login",
            username=username,
            details={"reason": "Invalid credentials"},
        )
        return redirect(url_for("ui.login", error="Invalid credentials"))

    # Create session
    session["user"] = username
    # Recorded so a session authenticated here and later reused by SAML SSO
    # reports the correct AuthnContextClassRef (persona logins must not
    # claim PasswordProtectedTransport).
    session["auth_method"] = "persona" if persona_mode else "password"
    session.permanent = True

    audit_event(
        "login",
        "success",
        endpoint="/login",
        username=username,
    )

    return redirect(url_for("ui.index"))


@ui_bp.route("/logout")
def logout() -> ResponseReturnValue:
    """Logout and clear session."""
    username = session.get("user")
    session.clear()

    if username:
        audit_event(
            "logout",
            "success",
            endpoint="/logout",
            username=username,
        )

    return redirect(url_for("ui.index"))


@ui_bp.route("/management/unlock", methods=["POST"])
def management_unlock() -> ResponseReturnValue:
    """Prove knowledge of management_secret once, for the rest of the session.

    Independent of login()/logout() above - this is the write guard, not the
    session front door (see management_secret in models.py). Exempted from
    management_secret_required_for_ui itself, since gating the unlock action
    on the thing it unlocks would be circular.
    """
    candidate = request.form.get("management_secret", "")

    if not verify_management_secret(candidate):
        # login.html renders an `error` query param, not flash() messages.
        return redirect(url_for("ui.login", error="Invalid management secret."))

    mark_management_verified()
    # ui.index extends base.html, which does render flash() messages.
    flash("Management secret accepted - mutating actions unlocked for this session.", "success")
    return redirect(url_for("ui.index"))


# ==================== Users Management ====================

@ui_bp.route("/users")
def users() -> ResponseReturnValue:
    """Users management page."""
    config = get_config()
    return render_template(
        "users.html",
        users=config.users,
        current_user=session.get("user"),
    )


@ui_bp.route("/users/create", methods=["GET", "POST"])
def user_create() -> ResponseReturnValue:
    """Create new user."""
    config = get_config()

    if request.method == "GET":
        return render_template(
            "users_form.html",
            user=None,
            allowed_identity_classes=config.settings.allowed_identity_classes,
            persona_mode=config.settings.persona_mode_enabled,
            current_user=session.get("user"),
        )

    # POST: Create user
    try:
        username = request.form.get("username", "").strip()
        if not username:
            flash("Username is required", "error")
            return redirect(url_for("ui.user_create"))

        # A password-less user only makes sense in persona mode; only the
        # blank-check is stripped, the stored value is kept verbatim.
        raw_password = request.form.get("password", "")
        password = None if not raw_password.strip() else raw_password
        if password is None and not config.settings.persona_mode_enabled:
            flash("Password is required for new users", "error")
            return redirect(url_for("ui.user_create"))

        # Parse roles and entitlements
        roles = [r.strip() for r in request.form.get("roles", "").split(",") if r.strip()]
        groups = [g.strip() for g in request.form.get("groups", "").split(",") if g.strip()]
        entitlements = [e.strip() for e in request.form.get("entitlements", "").split("\n") if e.strip()]
        source_acl = [a.strip() for a in request.form.get("source_acl", "").split("\n") if a.strip()]

        # Parse dynamic attributes
        attr_keys = request.form.getlist("attr_key[]")
        attr_values = request.form.getlist("attr_value[]")
        attributes = {}
        for key, value in zip(attr_keys, attr_values, strict=False):
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
            groups=groups,
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
def user_detail(username: str) -> ResponseReturnValue:
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
def user_edit(username: str) -> ResponseReturnValue:
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
            persona_mode=config.settings.persona_mode_enabled,
            current_user=session.get("user"),
        )

    # POST: Update user
    try:
        # Get password - keep existing if not provided. user.password is
        # Optional[str] (a persona-mode-only user has none), hence the
        # annotation - without it mypy infers plain str from request.form.get().
        password: str | None = request.form.get("password", "")
        if not password:
            password = user.password

        # Parse roles and entitlements
        roles = [r.strip() for r in request.form.get("roles", "").split(",") if r.strip()]
        groups = [g.strip() for g in request.form.get("groups", "").split(",") if g.strip()]
        entitlements = [e.strip() for e in request.form.get("entitlements", "").split("\n") if e.strip()]
        source_acl = [a.strip() for a in request.form.get("source_acl", "").split("\n") if a.strip()]

        # Parse dynamic attributes
        attr_keys = request.form.getlist("attr_key[]")
        attr_values = request.form.getlist("attr_value[]")
        attributes = {}
        for key, value in zip(attr_keys, attr_values, strict=False):
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
            groups=groups,
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
def user_delete(username: str) -> ResponseReturnValue:
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
def clients() -> ResponseReturnValue:
    """OAuth clients management page."""
    config = get_config()
    return render_template(
        "clients.html",
        clients=config.settings.clients,
        current_user=session.get("user"),
    )


def _parse_textarea_list(form_value: str) -> list[str]:
    """Parse a newline-separated textarea form field into a clean list of strings."""
    return [a.strip() for a in (form_value or "").splitlines() if a.strip()]


@ui_bp.route("/clients/create", methods=["GET", "POST"])
def client_create() -> ResponseReturnValue:
    """Create new OAuth client."""
    if request.method == "GET":
        # Generate a random client secret
        generated_secret = secrets.token_urlsafe(32)
        logos_dir = effective_logos_dir(
            get_config().settings.logos_dir, current_app.static_folder
        )
        return render_template(
            "clients_form.html",
            client=None,
            generated_secret=generated_secret,
            logos_dir=logos_dir,
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
            background_color=request.form.get("background_color") or None,
            header_color=request.form.get("header_color") or None,
            footer_color=request.form.get("footer_color") or None,
            show_client_id=bool(request.form.get("show_client_id")),
            show_description=bool(request.form.get("show_description")),
            additional_audiences=_parse_textarea_list(
                request.form.get("additional_audiences", "")
            ),
            redirect_uris=_parse_textarea_list(request.form.get("redirect_uris", "")),
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
def client_edit(client_id: str) -> ResponseReturnValue:
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
        logos_dir = effective_logos_dir(
            config.settings.logos_dir, current_app.static_folder
        )
        return render_template(
            "clients_form.html",
            client=client,
            generated_secret=None,
            logos_dir=logos_dir,
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
            background_color=request.form.get("background_color") or None,
            header_color=request.form.get("header_color") or None,
            footer_color=request.form.get("footer_color") or None,
            show_client_id=bool(request.form.get("show_client_id")),
            show_description=bool(request.form.get("show_description")),
            additional_audiences=_parse_textarea_list(
                request.form.get("additional_audiences", "")
            ),
            redirect_uris=_parse_textarea_list(request.form.get("redirect_uris", "")),
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
def client_delete(client_id: str) -> ResponseReturnValue:
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
def client_regenerate_secret(client_id: str) -> ResponseReturnValue:
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

        # Copy the whole client and change only the secret: rebuilding it
        # field by field is how #32 lost additional_audiences here, and how
        # the branding fields (colors, show_* flags) were silently reset
        # until #215's review caught it. model_copy carries every field,
        # including ones added after this line was written.
        updated_client = client.model_copy(update={"client_secret": new_secret})

        yaml_writer = get_yaml_writer()
        yaml_writer.save_client(updated_client, is_new=False)

        flash(f"New secret for '{client_id}': {new_secret}", "success")
        return redirect(url_for("ui.clients"))

    except Exception as e:
        logger.exception("Failed to regenerate client secret")
        flash(f"Failed to regenerate secret: {e}", "error")
        return redirect(url_for("ui.clients"))


# ==================== Settings ====================

def _form_bool(name: str) -> bool | None:
    """Checkbox value under the "absent = unchanged" contract (#131).

    An unchecked checkbox never appears in a submitted form, so on its own it
    is indistinguishable from a field that was not on the form at all. The
    settings template therefore carries a hidden ``<name>__on_form`` marker for
    every checkbox it renders. Name present -> its submitted state; marker
    alone -> the box was rendered and left unchecked (False); neither -> the
    field was not part of this form, leave the setting unchanged (None).
    """
    if name in request.form:
        return request.form.get(name) == "true"
    if f"{name}__on_form" in request.form:
        return False
    return None


def _form_text(name: str) -> str | None:
    """Text field: absent from the form means unchanged, blank means clear."""
    value = request.form.get(name)
    return value.strip() if value is not None else None


def _form_textarea_list(name: str) -> list[str] | None:
    """Textarea list: absent from the form means unchanged, blank means clear."""
    raw = request.form.get(name)
    return _parse_textarea_list(raw) if raw is not None else None


@ui_bp.route("/settings", methods=["GET", "POST"])
def settings() -> ResponseReturnValue:
    """IdP settings configuration page."""
    config = get_config()

    if request.method == "GET":
        return render_template(
            "settings.html",
            settings=config.settings,
            # Shown as placeholders when the fields are derived (#181)
            effective_saml_entity_id=effective_saml_entity_id(config.settings),
            effective_saml_sso_url=effective_saml_sso_url(config.settings),
            current_user=session.get("user"),
        )

    # POST: Update settings
    try:
        yaml_writer = get_yaml_writer()

        # Every value follows the "absent = unchanged" contract (#131): a field
        # missing from the submitted form is passed as None and the YAML writer
        # leaves it alone, so a partial form (a stale tab, a script, the e2e
        # agent's c14n round-trip) can no longer silently reset settings it
        # never carried. Present-but-blank still means "clear".
        expiry_raw = request.form.get("token_expiry_minutes")

        # OAuth settings
        yaml_writer.update_oauth_settings(
            issuer=_form_text("issuer"),
            issuer_from_request=_form_bool("issuer_from_request"),
            issuer_allowlist=_form_textarea_list("issuer_allowlist"),
            device_verification_base_url=_form_text("device_verification_base_url"),
            issuer_from_proxy_headers=_form_bool("issuer_from_proxy_headers"),
            audience=_form_text("audience"),
            token_expiry_minutes=int(expiry_raw) if expiry_raw else None,
            require_pkce=_form_bool("require_pkce"),
            refresh_token_rotation=_form_bool("refresh_token_rotation"),
            logos_dir=_form_text("logos_dir"),
        )

        # SAML settings
        yaml_writer.update_saml_settings(
            entity_id=_form_text("saml_entity_id"),
            sso_url=_form_text("saml_sso_url"),
            default_acs_url=_form_text("default_acs_url"),
            sign_responses=_form_bool("saml_sign_responses"),
            strict_binding=_form_bool("strict_saml_binding"),
            want_authn_requests_signed=_form_bool("saml_want_authn_requests_signed"),
            sp_certificates=_form_textarea_list("saml_sp_certificates"),
            c14n_algorithm=_form_text("saml_c14n_algorithm"),
            export_roles=_form_bool("saml_export_roles"),
            export_groups=_form_bool("saml_export_groups"),
            roles_attr_name=_form_text("saml_roles_attr_name"),
            groups_attr_name=_form_text("saml_groups_attr_name"),
        )

        # Identity classes
        identity_classes = [ic.strip() for ic in request.form.get("allowed_identity_classes", "").split("\n") if ic.strip()]
        if identity_classes:
            yaml_writer.update_allowed_identity_classes(identity_classes)

        # Login mode (persona login, local dev convenience)
        yaml_writer.update_login_settings(mode=_form_text("login_mode"))

        flash("Settings updated successfully", "success")
        return redirect(url_for("ui.settings"))

    except HookError as e:
        # The local write and the reload already happened (#185): the form's
        # values are in effect, only the mirror hook failed. The message
        # names the hook and its source, never the command.
        logger.warning("Settings saved locally; mirror hook failed: %s", e)
        flash(f"Settings saved locally; mirror hook failed: {e}", "error")
        return redirect(url_for("ui.settings"))
    except Exception as e:
        logger.exception("Failed to update settings")
        flash(f"Failed to update settings: {e}", "error")
        return redirect(url_for("ui.settings"))


# ==================== Keys Management ====================

@ui_bp.route("/keys")
def keys() -> ResponseReturnValue:
    """Keys and certificates management page."""
    import os
    from datetime import datetime
    from pathlib import Path
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
def keys_regenerate() -> ResponseReturnValue:
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
def keys_download(key_type: str) -> ResponseReturnValue:
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
def claims() -> ResponseReturnValue:
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
        for key in ["roles", "groups", "identity_class", "entitlements"]:
            value = request.form.get(f"prefix_{key}", "").strip()
            if value:
                prefixes[key] = value

        # Custom attribute prefixes
        custom_keys = request.form.getlist("custom_prefix_key[]")
        custom_values = request.form.getlist("custom_prefix_value[]")
        for key, value in zip(custom_keys, custom_values, strict=False):
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
def claims_preview(username: str) -> ResponseReturnValue:
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
            "groups": user.groups,
            "tenant": user.tenant,
            "source_acl": user.source_acl,
            "attributes": user.attributes,
        }
    }


# ==================== Audit Log ====================

@ui_bp.route("/audit")
def audit() -> ResponseReturnValue:
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
def audit_export(format: str) -> ResponseReturnValue:
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
def audit_clear() -> ResponseReturnValue:
    """Clear the audit log."""
    audit_log = get_audit_log()
    audit_log.clear()

    flash("Audit log cleared", "success")
    return redirect(url_for("ui.audit"))


# ==================== Token Testing ====================

@ui_bp.route("/test")
def test_page() -> ResponseReturnValue:
    """Token testing page."""
    config = get_config()
    return render_template(
        "test.html",
        users=list(config.users.keys()),
        current_user=session.get("user"),
        settings=config.settings,
    )
