"""
YAML configuration writer service.
Provides atomic write operations for YAML configuration files.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from ..config import OAuthClient, User, get_config
from ..serialization import atomic_write_yaml, client_to_yaml, user_to_yaml

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

        with open(self.users_file, "r") as f:
            return yaml.safe_load(f) or {"users": {}, "default_user": "admin"}

    def _load_settings_yaml(self) -> Dict[str, Any]:
        """Load the current settings.yaml content."""
        if not self.settings_file.exists():
            return {}

        with open(self.settings_file, "r") as f:
            return yaml.safe_load(f) or {}

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

        # Check if client exists
        existing_idx = None
        for idx, c in enumerate(clients):
            if c.get("client_id") == client.client_id:
                existing_idx = idx
                break

        if is_new and existing_idx is not None:
            raise ValueError(f"Client '{client.client_id}' already exists")

        client_data = client_to_yaml(client)

        if existing_idx is not None:
            clients[existing_idx] = client_data
        else:
            clients.append(client_data)

        self._atomic_write(self.settings_file, data)
        get_config().reload()

    def delete_client(self, client_id: str) -> None:
        """Delete an OAuth client from settings.yaml."""
        data = self._load_settings_yaml()

        clients = data.get("oauth", {}).get("clients", [])
        new_clients = [c for c in clients if c.get("client_id") != client_id]

        if len(new_clients) == len(clients):
            raise ValueError(f"Client '{client_id}' not found")

        data["oauth"]["clients"] = new_clients

        self._atomic_write(self.settings_file, data)
        get_config().reload()

    # ==================== Settings Operations ====================

    def update_oauth_settings(
        self,
        issuer: Optional[str] = None,
        audience: Optional[str] = None,
        token_expiry_minutes: Optional[int] = None,
        require_pkce: Optional[bool] = None,
        refresh_token_rotation: Optional[bool] = None,
    ) -> None:
        """Update OAuth settings."""
        data = self._load_settings_yaml()
        oauth = data.setdefault("oauth", {})

        if issuer is not None:
            oauth["issuer"] = issuer
        if audience is not None:
            oauth["audience"] = audience
        if token_expiry_minutes is not None:
            oauth["token_expiry_minutes"] = token_expiry_minutes
        if require_pkce is not None:
            oauth["require_pkce"] = require_pkce
        if refresh_token_rotation is not None:
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
    ) -> None:
        """Update SAML settings."""
        data = self._load_settings_yaml()
        saml = data.setdefault("saml", {})

        if entity_id is not None:
            saml["entity_id"] = entity_id
        if sso_url is not None:
            saml["sso_url"] = sso_url
        if default_acs_url is not None:
            saml["default_acs_url"] = default_acs_url
        if sign_responses is not None:
            saml["sign_responses"] = sign_responses
        if strict_binding is not None:
            saml["strict_binding"] = strict_binding
        if want_authn_requests_signed is not None:
            saml["want_authn_requests_signed"] = want_authn_requests_signed
        if sp_certificates is not None:
            if sp_certificates:
                saml["sp_certificates"] = sp_certificates
            else:
                saml.pop("sp_certificates", None)
        if c14n_algorithm is not None:
            saml["c14n_algorithm"] = c14n_algorithm

        self._atomic_write(self.settings_file, data)
        get_config().reload()

    def update_authority_prefixes(self, prefixes: Dict[str, str]) -> None:
        """Update authority prefix mappings."""
        data = self._load_settings_yaml()
        data["authority_prefixes"] = prefixes

        self._atomic_write(self.settings_file, data)
        get_config().reload()

    def update_allowed_identity_classes(self, classes: List[str]) -> None:
        """Update allowed identity classes."""
        data = self._load_settings_yaml()
        data["allowed_identity_classes"] = classes

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
