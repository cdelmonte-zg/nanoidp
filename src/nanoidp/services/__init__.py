"""Services module for NanoIDP."""

from .activation import activate_services
from .audit import AuditLog, get_audit_log
from .auth_code import AuthCodeStore, AuthorizationCode, get_auth_code_store
from .crypto import (
    EXTERNAL_KEYS_NOT_ROTATABLE,
    EXTERNAL_KEYS_NOT_ROTATABLE_KIND,
    KEYS_DIRECTORY_LOCK_UNAVAILABLE,
    KEYS_DIRECTORY_NOT_WRITABLE,
    CryptoService,
    ExternalKeysNotRotatable,
    activate_crypto_service,
    get_crypto_service,
    rotation_refusal,
)
from .device_code import (
    DeviceCodeGrant,
    DeviceCodeStore,
    DevicePollOutcome,
    DeviceVerifyOutcome,
    get_device_code_store,
)
from .discovery import build_discovery_document
from .identities import IdentityResolver, get_identities, identities_for
from .revocation import RevocationStore, get_revocation_store
from .token import TokenService, get_token_service
from .yaml_writer import YamlWriter, get_yaml_writer

__all__ = [
    "build_discovery_document",
    "IdentityResolver",
    "get_identities",
    "identities_for",
    "CryptoService",
    "EXTERNAL_KEYS_NOT_ROTATABLE",
    "EXTERNAL_KEYS_NOT_ROTATABLE_KIND",
    "KEYS_DIRECTORY_LOCK_UNAVAILABLE",
    "KEYS_DIRECTORY_NOT_WRITABLE",
    "rotation_refusal",
    "ExternalKeysNotRotatable",
    "get_crypto_service",
    "activate_crypto_service",
    "activate_services",
    "TokenService",
    "get_token_service",
    "AuditLog",
    "get_audit_log",
    "YamlWriter",
    "get_yaml_writer",
    "AuthCodeStore",
    "AuthorizationCode",
    "get_auth_code_store",
    "DeviceCodeGrant",
    "DeviceCodeStore",
    "DevicePollOutcome",
    "DeviceVerifyOutcome",
    "get_device_code_store",
    "RevocationStore",
    "get_revocation_store",
]
