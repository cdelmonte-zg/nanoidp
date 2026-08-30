"""Argument normalization/pre-validation helpers for the MCP tools (#286).

Split out of the monolithic mcp_server module; bodies unchanged. The
pre-validation rule these implement: reject before ANY assignment, so an
invalid argument can never leave another requested field partially applied.
"""

import re
from typing import Any, Callable, Optional

from ..models import HEX_COLOR_PATTERN, normalize_saml_attr_name

_TOKEN_ENDPOINT_AUTH_METHODS = ("client_secret_basic", "client_secret_post", "none")


def _normalize_auth_method(value: Any) -> str:
    """Pre-validate token_endpoint_auth_method before any assignment (#188),
    same principle as the hex colors: a bad value must reject the call, not
    leave a client half-updated."""
    if value not in _TOKEN_ENDPOINT_AUTH_METHODS:
        raise ValueError(
            "token_endpoint_auth_method must be one of "
            + ", ".join(_TOKEN_ENDPOINT_AUTH_METHODS)
        )
    return str(value)


_LAYOUTS = ("vertical", "horizontal")


def _normalize_layout(value: Any) -> str:
    """Pre-validate layout before any assignment (#249), same
    pre-validation principle as token_endpoint_auth_method above."""
    if value not in _LAYOUTS:
        raise ValueError("layout must be one of " + ", ".join(_LAYOUTS))
    return str(value)



def _normalize_str_list(value: Any, field: str) -> list[str]:
    """Coerce a raw list argument into a list of non-empty strings.

    Only ``None`` (argument omitted) and an empty list mean "no values"; any
    other non-list (``""``, ``0``, ``False``) is a type error and is rejected,
    rather than silently coerced to ``[]`` (#37).
    """
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(a, str) for a in value):
        raise ValueError(f"{field} must be a list of strings")
    return [a for a in value if a]


def _normalize_audiences(value: Any) -> list[str]:
    """Coerce a raw audiences argument (see ``_normalize_str_list``)."""
    return _normalize_str_list(value, "additional_audiences")



_HEX_COLOR_RE = re.compile(HEX_COLOR_PATTERN)


def _normalize_hex_color(value: Any, field: str) -> Optional[str]:
    """Coerce a raw color argument: falsy (omitted/empty) clears it, otherwise
    it must match OAuthClient's own hex pattern - checked here too so a bad
    value is caught before any other field on the client is mutated (#37).
    """
    if not value:
        return None
    if not isinstance(value, str) or not _HEX_COLOR_RE.match(value):
        raise ValueError(f"{field} must be a hex color like '#1a1a2e'")
    return value



def _blank_to_none(name: str, value: Any) -> Any:
    """ "" = clear: back to the derived/unset value (#181), mirroring the UI."""
    return value or None


def _normalize_update_list(name: str, value: Any) -> Any:
    return _normalize_str_list(value, name)


def _normalize_update_attr_name(name: str, value: Any) -> Any:
    return normalize_saml_attr_name(name, value)


# update_settings' writable fields, in the response's updated_fields order.
# Names double as Settings attribute names; tests/test_settings_plumbing_parity.py
# asserts this tuple against the tool's input_schema, so the two cannot drift.
_UPDATE_SETTINGS_FIELDS: tuple[str, ...] = (
    "issuer",
    "issuer_from_request",
    "issuer_allowlist",
    "device_verification_base_url",
    "issuer_from_proxy_headers",
    "audience",
    "token_expiry_minutes",
    "saml_entity_id",
    "saml_sso_url",
    "saml_sign_responses",
    "saml_export_roles",
    "saml_export_groups",
    "saml_roles_attr_name",
    "saml_groups_attr_name",
    "saml_c14n_algorithm",
    "strict_saml_binding",
    "saml_want_authn_requests_signed",
    "saml_sp_certificates",
    "verbose_logging",
    "refresh_token_rotation",
    "require_pkce",
    "login_mode",
)

_UPDATE_SETTINGS_NORMALIZERS: dict[str, Callable[[str, Any], Any]] = {
    "issuer_allowlist": _normalize_update_list,
    "saml_sp_certificates": _normalize_update_list,
    "saml_roles_attr_name": _normalize_update_attr_name,
    "saml_groups_attr_name": _normalize_update_attr_name,
    "device_verification_base_url": _blank_to_none,
    "saml_entity_id": _blank_to_none,
    "saml_sso_url": _blank_to_none,
}

