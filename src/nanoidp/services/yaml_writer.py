"""
YAML configuration writer service.
Provides atomic write operations for YAML configuration files.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config import OAuthClient, Settings, User, get_config
from ..config_documents import document_defaults
from ..hooks import HookError
from ..serialization import (
    OWNED_SETTINGS,
    atomic_write_yaml,
    client_id_matches,
    client_to_yaml,
    is_unchanged,
    load_yaml_document,
    merge_client_entry,
    merge_optional_nested_field,
    user_to_yaml,
)

logger = logging.getLogger(__name__)


class YamlWriter:
    """Service for safely writing YAML configuration files."""

    def __init__(self, config_dir: Optional[str] = None) -> None:
        config = get_config()
        self.config_dir = Path(config_dir or config.config_dir)
        self.users_file = self.config_dir / "users.yaml"
        self.settings_file = self.config_dir / "settings.yaml"

    def _atomic_write(self, file_path: Path, data: Dict[str, Any]) -> None:
        """Atomically write a YAML document (shared implementation, #83), then
        run the single post-write contract (#185):

            write local -> notify the mirror (on_config_saved) -> refresh the
            runtime FROM LOCAL DISK -> propagate a mirror failure if strict.

        The refresh is ConfigManager.reload_local(), never reload(): a
        reload() would run on_before_load and could pull a stale or
        failed-to-update mirror back over the file just written, turning a
        mirror hiccup into a silent rollback (#185 review). The disk is the
        newest state after our own write; only an explicit reload consults
        the mirror.
        """
        atomic_write_yaml(file_path, data)
        kind = "users" if file_path.name == "users.yaml" else "settings"
        config = get_config()
        hook_error: Optional[HookError] = None
        try:
            config.notify_saved(file_path, kind)
        except HookError as exc:
            hook_error = exc
        config.reload_local()
        if hook_error is not None:
            raise hook_error

    def _load_users_yaml(self) -> Dict[str, Any]:
        """Load the current users.yaml content."""
        if not self.users_file.exists():
            return {"users": {}, "default_user": "admin"}
        return load_yaml_document(self.users_file)

    def _load_settings_yaml(self) -> Dict[str, Any]:
        """Load the current settings.yaml content."""
        return load_yaml_document(self.settings_file)

    # ==================== User Operations ====================

    def save_user(self, user: User, is_new: bool = False) -> None:
        """
        Save or update a user in users.yaml.

        Args:
            user: The User object to save
            is_new: If True, will fail if user already exists
        """
        data = self._load_users_yaml()

        if is_new and user.username in data.get("users", {}):
            raise ValueError(f"User '{user.username}' already exists")

        data.setdefault("users", {})[user.username] = user_to_yaml(user)

        self._atomic_write(self.users_file, data)

    def delete_user(self, username: str) -> None:
        """
        Delete a user from users.yaml.

        Args:
            username: The username to delete
        """
        data = self._load_users_yaml()

        if username not in data.get("users", {}):
            raise ValueError(f"User '{username}' not found")

        del data["users"][username]

        # If deleted user was the default, update default_user
        if data.get("default_user") == username:
            remaining_users = list(data.get("users", {}).keys())
            data["default_user"] = remaining_users[0] if remaining_users else ""

        self._atomic_write(self.users_file, data)

    def set_default_user(self, username: str) -> None:
        """Set the default user for client_credentials grant."""
        data = self._load_users_yaml()

        if username not in data.get("users", {}):
            raise ValueError(f"User '{username}' not found")

        data["default_user"] = username

        self._atomic_write(self.users_file, data)

    # ==================== OAuth Client Operations ====================

    def save_client(self, client: OAuthClient, is_new: bool = False) -> None:
        """
        Save or update an OAuth client in settings.yaml.

        Args:
            client: The OAuthClient object to save
            is_new: If True, will fail if client already exists
        """
        data = self._load_settings_yaml()

        clients = data.setdefault("oauth", {}).setdefault("clients", [])

        # Check if client exists. Match through client_id_matches so a raw
        # ${CLIENT_ID:...} placeholder entry is recognised as the same client
        # instead of being appended as a duplicate (#127).
        existing_idx = None
        for idx, c in enumerate(clients):
            if client_id_matches(c, client.client_id):
                existing_idx = idx
                break

        if is_new and existing_idx is not None:
            raise ValueError(f"Client '{client.client_id}' already exists")

        if existing_idx is not None:
            clients[existing_idx] = merge_client_entry(clients[existing_idx], client)
        else:
            clients.append(client_to_yaml(client))

        self._atomic_write(self.settings_file, data)

    def delete_client(self, client_id: str) -> None:
        """Delete an OAuth client from settings.yaml."""
        data = self._load_settings_yaml()

        clients = data.get("oauth", {}).get("clients", [])
        # Match through client_id_matches so a client whose id is an env
        # placeholder can still be deleted (#127).
        new_clients = [c for c in clients if not client_id_matches(c, client_id)]

        if len(new_clients) == len(clients):
            raise ValueError(f"Client '{client_id}' not found")

        data["oauth"]["clients"] = new_clients

        self._atomic_write(self.settings_file, data)

    # ==================== Settings Operations ====================

    def _apply_provided_settings(self, section_name: str, provided: "Dict[str, Any]") -> None:
        """Apply form-provided values for one settings.yaml section (#214).

        The per-field encoding comes from serialization.OWNED_SETTINGS, the
        same table apply_settings_document drives from - one row per owned
        key instead of one hand-written if-block per field. Semantics per
        value: None was not on the form and leaves the file alone (#131);
        for a non-"plain" row a provided-but-falsy value clears the key
        (absent = default/derived); everything else is written only when
        the expanded on-disk value actually differs (#127), so untouched
        ``${VAR}`` placeholders and comments survive.
        """
        data = self._load_settings_yaml()
        section = data.setdefault(section_name, {})
        rows = {f.key: f for f in OWNED_SETTINGS if f.section == section_name}
        for key, value in provided.items():
            if value is None:
                continue
            field = rows[key]
            compare = value if (field.doc_mode == "plain" or value) else field.empty
            if not is_unchanged(section.get(key), compare):
                if field.doc_mode != "plain" and not value:
                    section.pop(key, None)
                else:
                    section[key] = value
        self._atomic_write(self.settings_file, data)

    def update_oauth_settings(
        self,
        issuer: Optional[str] = None,
        issuer_from_request: Optional[bool] = None,
        issuer_allowlist: Optional[List[str]] = None,
        device_verification_base_url: Optional[str] = None,
        issuer_from_proxy_headers: Optional[bool] = None,
        audience: Optional[str] = None,
        token_expiry_minutes: Optional[int] = None,
        require_pkce: Optional[bool] = None,
        refresh_token_rotation: Optional[bool] = None,
        logos_dir: Optional[str] = None,
    ) -> None:
        """Update OAuth settings (per-field encodings: OWNED_SETTINGS, #214).

        Skips writing a field whose expanded on-disk value already matches
        what's being submitted, so unchanged ``${VAR}`` placeholders and
        comments survive a form save that only changed other fields (#127).
        """
        self._apply_provided_settings(
            "oauth",
            {
                "issuer": issuer,
                "issuer_from_request": issuer_from_request,
                "issuer_allowlist": issuer_allowlist,
                "device_verification_base_url": device_verification_base_url,
                "issuer_from_proxy_headers": issuer_from_proxy_headers,
                "audience": audience,
                "token_expiry_minutes": token_expiry_minutes,
                "require_pkce": require_pkce,
                "refresh_token_rotation": refresh_token_rotation,
                "logos_dir": logos_dir,
            },
        )

    def update_saml_settings(
        self,
        entity_id: Optional[str] = None,
        sso_url: Optional[str] = None,
        default_acs_url: Optional[str] = None,
        sign_responses: Optional[bool] = None,
        strict_binding: Optional[bool] = None,
        want_authn_requests_signed: Optional[bool] = None,
        sp_certificates: Optional[List[str]] = None,
        c14n_algorithm: Optional[str] = None,
        export_roles: Optional[bool] = None,
        export_groups: Optional[bool] = None,
        roles_attr_name: Optional[str] = None,
        groups_attr_name: Optional[str] = None,
    ) -> None:
        """Update SAML settings (same #127 guard; encodings: OWNED_SETTINGS).

        Blank clears entity_id/sso_url: absent = derived from the effective
        issuer (#181), the same "present-but-blank = clear" contract as #131.
        """
        self._apply_provided_settings(
            "saml",
            {
                "entity_id": entity_id,
                "sso_url": sso_url,
                "default_acs_url": default_acs_url,
                "sign_responses": sign_responses,
                "strict_binding": strict_binding,
                "want_authn_requests_signed": want_authn_requests_signed,
                "sp_certificates": sp_certificates,
                "c14n_algorithm": c14n_algorithm,
                "export_roles": export_roles,
                "export_groups": export_groups,
                "roles_attr_name": roles_attr_name,
                "groups_attr_name": groups_attr_name,
            },
        )

    def update_authority_prefixes(self, prefixes: Dict[str, str]) -> None:
        """Update authority prefix mappings."""
        data = self._load_settings_yaml()
        if not is_unchanged(data.get("authority_prefixes"), prefixes):
            data["authority_prefixes"] = prefixes

        self._atomic_write(self.settings_file, data)

    def update_allowed_identity_classes(self, classes: List[str]) -> None:
        """Update allowed identity classes."""
        data = self._load_settings_yaml()
        if not is_unchanged(data.get("allowed_identity_classes"), classes):
            data["allowed_identity_classes"] = classes

        self._atomic_write(self.settings_file, data)

    def update_login_settings(self, mode: Optional[str] = None) -> None:
        """Update the 'login' section (persona login mode, local dev
        convenience). 'password' is the default and is never persisted -
        the 'login' section is omitted entirely at the default, same as
        'security_profile' at 'dev' (#83/#87 read-modify-write conventions).

        Unlike other text fields' "absent = unchanged, blank = clear"
        convention (#131), there is no sensible "cleared" login mode, so a
        blank value is treated the same as absent: left unchanged, not
        written to disk. A present, non-blank value is validated against
        the same `{"password", "persona"}` set as ``Settings.login_mode``
        *before* anything is written, so an invalid value (e.g. a typo)
        raises instead of persisting a mode the server can't start with.
        """
        data = self._load_settings_yaml()
        login_mode_default = document_defaults()["login.mode"]

        if mode:
            Settings.validate_login_mode(mode)
            merge_optional_nested_field(data, "login", "mode", mode, login_mode_default)

        self._atomic_write(self.settings_file, data)


# Global instance
_yaml_writer: Optional[YamlWriter] = None


def get_yaml_writer() -> YamlWriter:
    """Get or create the global YAML writer instance."""
    global _yaml_writer
    if _yaml_writer is None:
        _yaml_writer = YamlWriter()
    return _yaml_writer
