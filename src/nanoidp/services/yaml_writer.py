"""
YAML configuration writer service.
Provides atomic write operations for YAML configuration files.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config import OAuthClient, Settings, User, get_config
from ..serialization import (
    atomic_write_yaml,
    client_id_matches,
    client_to_yaml,
    is_unchanged,
    load_yaml_document,
    merge_client_entry,
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
        """Atomically write a YAML document (shared implementation, #83)."""
        atomic_write_yaml(file_path, data)

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

        # Reload config to pick up changes
        get_config().reload()

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

        # Reload config to pick up changes
        get_config().reload()

    def set_default_user(self, username: str) -> None:
        """Set the default user for client_credentials grant."""
        data = self._load_users_yaml()

        if username not in data.get("users", {}):
            raise ValueError(f"User '{username}' not found")

        data["default_user"] = username

        self._atomic_write(self.users_file, data)
        get_config().reload()

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
        get_config().reload()

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
        get_config().reload()

    # ==================== Settings Operations ====================

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
    ) -> None:
        """Update OAuth settings.

        Skips writing a field whose expanded on-disk value already matches
        what's being submitted, so unchanged ``${VAR}`` placeholders and
        comments survive a form save that only changed other fields (#127).
        """
        data = self._load_settings_yaml()
        oauth = data.setdefault("oauth", {})

        if issuer is not None and not is_unchanged(oauth.get("issuer"), issuer):
            oauth["issuer"] = issuer
        if issuer_from_request is not None and not is_unchanged(
            oauth.get("issuer_from_request"), issuer_from_request
        ):
            oauth["issuer_from_request"] = issuer_from_request
        if issuer_allowlist is not None:
            if issuer_allowlist:
                if not is_unchanged(oauth.get("issuer_allowlist"), issuer_allowlist):
                    oauth["issuer_allowlist"] = issuer_allowlist
            else:
                oauth.pop("issuer_allowlist", None)
        if device_verification_base_url is not None:
            next_url = device_verification_base_url or ""
            if not is_unchanged(
                oauth.get("device_verification_base_url"),
                next_url,
            ):
                if device_verification_base_url:
                    oauth["device_verification_base_url"] = device_verification_base_url
                else:
                    oauth.pop("device_verification_base_url", None)
        if issuer_from_proxy_headers is not None and not is_unchanged(
            oauth.get("issuer_from_proxy_headers"), issuer_from_proxy_headers
        ):
            oauth["issuer_from_proxy_headers"] = issuer_from_proxy_headers
        if audience is not None and not is_unchanged(oauth.get("audience"), audience):
            oauth["audience"] = audience
        if token_expiry_minutes is not None and not is_unchanged(
            oauth.get("token_expiry_minutes"), token_expiry_minutes
        ):
            oauth["token_expiry_minutes"] = token_expiry_minutes
        if require_pkce is not None and not is_unchanged(
            oauth.get("require_pkce"), require_pkce
        ):
            oauth["require_pkce"] = require_pkce
        if refresh_token_rotation is not None and not is_unchanged(
            oauth.get("refresh_token_rotation"), refresh_token_rotation
        ):
            oauth["refresh_token_rotation"] = refresh_token_rotation

        self._atomic_write(self.settings_file, data)
        get_config().reload()

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
        """Update SAML settings (same unchanged-field guard as #127 above)."""
        data = self._load_settings_yaml()
        saml = data.setdefault("saml", {})

        if entity_id is not None and not is_unchanged(saml.get("entity_id"), entity_id):
            saml["entity_id"] = entity_id
        if sso_url is not None and not is_unchanged(saml.get("sso_url"), sso_url):
            saml["sso_url"] = sso_url
        if default_acs_url is not None and not is_unchanged(
            saml.get("default_acs_url"), default_acs_url
        ):
            saml["default_acs_url"] = default_acs_url
        if sign_responses is not None and not is_unchanged(
            saml.get("sign_responses"), sign_responses
        ):
            saml["sign_responses"] = sign_responses
        if strict_binding is not None and not is_unchanged(
            saml.get("strict_binding"), strict_binding
        ):
            saml["strict_binding"] = strict_binding
        if want_authn_requests_signed is not None and not is_unchanged(
            saml.get("want_authn_requests_signed"), want_authn_requests_signed
        ):
            saml["want_authn_requests_signed"] = want_authn_requests_signed
        if sp_certificates is not None:
            if sp_certificates:
                if not is_unchanged(saml.get("sp_certificates"), sp_certificates):
                    saml["sp_certificates"] = sp_certificates
            else:
                saml.pop("sp_certificates", None)
        if c14n_algorithm is not None and not is_unchanged(
            saml.get("c14n_algorithm"), c14n_algorithm
        ):
            saml["c14n_algorithm"] = c14n_algorithm
        if export_roles is not None and not is_unchanged(
            saml.get("export_roles"), export_roles
        ):
            saml["export_roles"] = export_roles
        if export_groups is not None and not is_unchanged(
            saml.get("export_groups"), export_groups
        ):
            saml["export_groups"] = export_groups
        # Empty string drops the key so the default name applies again.
        if roles_attr_name is not None:
            if roles_attr_name:
                if not is_unchanged(saml.get("roles_attr_name"), roles_attr_name):
                    saml["roles_attr_name"] = roles_attr_name
            else:
                saml.pop("roles_attr_name", None)
        if groups_attr_name is not None:
            if groups_attr_name:
                if not is_unchanged(saml.get("groups_attr_name"), groups_attr_name):
                    saml["groups_attr_name"] = groups_attr_name
            else:
                saml.pop("groups_attr_name", None)

        self._atomic_write(self.settings_file, data)
        get_config().reload()

    def update_authority_prefixes(self, prefixes: Dict[str, str]) -> None:
        """Update authority prefix mappings."""
        data = self._load_settings_yaml()
        if not is_unchanged(data.get("authority_prefixes"), prefixes):
            data["authority_prefixes"] = prefixes

        self._atomic_write(self.settings_file, data)
        get_config().reload()

    def update_allowed_identity_classes(self, classes: List[str]) -> None:
        """Update allowed identity classes."""
        data = self._load_settings_yaml()
        if not is_unchanged(data.get("allowed_identity_classes"), classes):
            data["allowed_identity_classes"] = classes

        self._atomic_write(self.settings_file, data)
        get_config().reload()

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
        login_mode_default = "password"

        if mode:
            Settings.validate_login_mode(mode)
            login_section = data.get("login") or {}
            current_mode = login_section.get("mode", login_mode_default)
            if not is_unchanged(current_mode, mode):
                if mode != login_mode_default:
                    data.setdefault("login", {})["mode"] = mode
                elif "login" in data:
                    data["login"].pop("mode", None)
                    if not data["login"]:
                        data.pop("login", None)

        self._atomic_write(self.settings_file, data)
        get_config().reload()


# Global instance
_yaml_writer: Optional[YamlWriter] = None


def get_yaml_writer() -> YamlWriter:
    """Get or create the global YAML writer instance."""
    global _yaml_writer
    if _yaml_writer is None:
        _yaml_writer = YamlWriter()
    return _yaml_writer
