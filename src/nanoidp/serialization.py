"""
Single source of truth for serializing config objects into their YAML documents.

``ConfigManager.save()`` and the ``YamlWriter`` behind the web UI used to each
build their own YAML entries. The duplication drifted repeatedly — #32 (UI
saves dropped ``additional_audiences``), #78 (``redirect_uris`` had to be added
in two places), #82 (``security_profile`` persisted only via ``ConfigManager``)
— and ``ConfigManager`` rewrote ``settings.yaml`` from scratch, deleting every
section it didn't own (#87). Both paths now delegate here (#83): entry builders
produce identical entries, and ``apply_settings_document`` is read-modify-write,
so keys this module doesn't manage (``jwt``, ``session``, custom keys) survive
any save.

This module deliberately has no runtime imports from the package (models are
type-checking-only), so it can be imported from ``config.py`` without cycles.
"""

from __future__ import annotations

import logging
import os
import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict

import yaml

if TYPE_CHECKING:
    from .config import OAuthClient, Settings, User

logger = logging.getLogger(__name__)


def client_to_yaml(client: OAuthClient) -> Dict[str, Any]:
    """Build the settings.yaml entry for an OAuth client.

    Optional list fields are omitted when empty, so a default client stays a
    three-line entry.
    """
    entry: Dict[str, Any] = {
        "client_id": client.client_id,
        "client_secret": client.client_secret,
        "description": client.description,
    }
    if client.additional_audiences:
        entry["additional_audiences"] = client.additional_audiences
    if client.redirect_uris:
        entry["redirect_uris"] = client.redirect_uris
    return entry


def user_to_yaml(user: User) -> Dict[str, Any]:
    """Build the users.yaml entry for a user.

    Canonical form is sparse: optional fields and model defaults
    (``tenant: default``, empty lists) are omitted and restored by the loader's
    defaults on the next read.
    """
    entry: Dict[str, Any] = {
        "password": user.password,
        "email": user.email,
    }
    if user.identity_class:
        entry["identity_class"] = user.identity_class
    if user.entitlements:
        entry["entitlements"] = user.entitlements
    if user.roles:
        entry["roles"] = user.roles
    if user.tenant and user.tenant != "default":
        entry["tenant"] = user.tenant
    if user.source_acl:
        entry["source_acl"] = user.source_acl
    if user.attributes:
        entry["attributes"] = user.attributes
    return entry


def apply_settings_document(
    document: Dict[str, Any], settings: Settings
) -> Dict[str, Any]:
    """Update the settings.yaml keys this codebase manages, in place.

    Read-modify-write: ``document`` is the currently persisted document (or
    ``{}``), and only owned keys are (re)written — anything else (``jwt``,
    ``session``, ``logging`` keys other than ``verbose_logging``, unknown
    custom keys) is preserved verbatim (#87). Optional owned keys are removed
    when back at their defaults, so a cleared ``security_profile`` does not
    linger in the file.
    """
    server = document.setdefault("server", {})
    server["host"] = settings.host
    server["port"] = settings.port

    oauth = document.setdefault("oauth", {})
    oauth["issuer"] = settings.issuer
    oauth["audience"] = settings.audience
    oauth["token_expiry_minutes"] = settings.token_expiry_minutes
    oauth["refresh_token_rotation"] = settings.refresh_token_rotation
    oauth["require_pkce"] = settings.require_pkce
    oauth["clients"] = [client_to_yaml(client) for client in settings.clients]

    saml = document.setdefault("saml", {})
    saml["entity_id"] = settings.saml_entity_id
    saml["sso_url"] = settings.saml_sso_url
    saml["default_acs_url"] = settings.default_acs_url
    saml["sign_responses"] = settings.saml_sign_responses
    saml["c14n_algorithm"] = settings.saml_c14n_algorithm
    saml["strict_binding"] = settings.strict_saml_binding
    saml["want_authn_requests_signed"] = settings.saml_want_authn_requests_signed
    if settings.saml_sp_certificates:
        saml["sp_certificates"] = settings.saml_sp_certificates
    else:
        saml.pop("sp_certificates", None)

    document.setdefault("logging", {})["verbose_logging"] = settings.verbose_logging
    document["authority_prefixes"] = settings.authority_prefixes

    if settings.allowed_identity_classes:
        document["allowed_identity_classes"] = settings.allowed_identity_classes
    else:
        document.pop("allowed_identity_classes", None)

    if settings.security_profile != "dev":
        document["security_profile"] = settings.security_profile
    else:
        document.pop("security_profile", None)

    return document


def apply_users_document(
    document: Dict[str, Any], users: Dict[str, User], default_user: str
) -> Dict[str, Any]:
    """Update the users.yaml keys this codebase manages, in place.

    The full user map is owned; unknown top-level keys are preserved.
    """
    document["users"] = {
        username: user_to_yaml(user) for username, user in users.items()
    }
    document["default_user"] = default_user
    return document


def atomic_write_yaml(file_path: Path, data: Dict[str, Any]) -> None:
    """Atomically write a YAML document, with a .bak of the previous version.

    Writes to a temp file in the same directory and renames over the target;
    on failure the previous content is restored from the backup.
    """
    backup_path = file_path.with_suffix(".yaml.bak")
    if file_path.exists():
        shutil.copy2(file_path, backup_path)

    fd, temp_path = tempfile.mkstemp(
        suffix=".yaml", prefix=file_path.stem + "_", dir=file_path.parent
    )
    try:
        with os.fdopen(fd, "w") as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
        os.replace(temp_path, file_path)
        logger.info(f"Successfully wrote {file_path}")
    except Exception as e:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
        if backup_path.exists():
            shutil.copy2(backup_path, file_path)
            logger.warning(f"Restored {file_path} from backup after write failure")
        raise RuntimeError(f"Failed to write {file_path}: {e}") from e
