"""
Single source of truth for serializing config objects into their YAML documents.

``ConfigManager.save()`` and the ``YamlWriter`` behind the web UI used to each
build their own YAML entries. The duplication drifted repeatedly - #32 (UI
saves dropped ``additional_audiences``), #78 (``redirect_uris`` had to be added
in two places), #82 (``security_profile`` persisted only via ``ConfigManager``)
- and ``ConfigManager`` rewrote ``settings.yaml`` from scratch, deleting every
section it didn't own (#87). Both paths now delegate here (#83): entry builders
produce identical entries, and ``apply_settings_document`` is read-modify-write,
so keys this module doesn't manage (``jwt``, ``session``, custom keys) survive
any save.

This module deliberately has no runtime imports from the package (models are
type-checking-only), so it can be imported from ``config.py`` without cycles.

Issue #127: saving settings used to silently discard comments, inline ``#``
text and ``${VAR:default}`` placeholders, because the write path round-tripped
through plain PyYAML (no comment support) and always wrote the *expanded*
in-memory value even when a field was never actually changed. This module now
does the load/dump with ``ruamel.yaml`` in round-trip mode (comments and quote
style survive), quotes free-form text values so an embedded ``#`` can't be
mistaken for a comment, and skips writing any key whose expanded on-disk value
already matches what's being saved, so unchanged placeholders survive.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap
from ruamel.yaml.scalarstring import SingleQuotedScalarString

if TYPE_CHECKING:
    from .config import OAuthClient, Settings, User

logger = logging.getLogger(__name__)

# Round-trip YAML instance: preserves comments and quote style, and matches
# the project's existing dash-at-parent-indent list style (#127).
_yaml_rt = YAML(typ="rt")
_yaml_rt.indent(mapping=2, sequence=2, offset=0)
_yaml_rt.preserve_quotes = True
_yaml_rt.width = 4096  # avoid re-wrapping long values (URLs, descriptions)

_ENV_VAR_RE = re.compile(r'\$\{([A-Za-z_][A-Za-z0-9_]*)(?::([^}]*))?\}')


def expand_env_vars(value: Any) -> Any:
    """Recursively expand ${NAME} / ${NAME:default} placeholders in YAML values.

    - ${NAME}          → os.environ[NAME] (empty string if not set)
    - ${NAME:default}  → os.environ.get(NAME, 'default')

    Only string leaf values are processed; dicts/lists are traversed recursively.
    """
    if isinstance(value, str):
        def _replace(m: re.Match) -> str:
            var_name, default = m.group(1), m.group(2)
            if default is None:
                return os.environ.get(var_name, "")
            return os.environ.get(var_name, default)
        return _ENV_VAR_RE.sub(_replace, value)
    if isinstance(value, dict):
        return {k: expand_env_vars(v) for k, v in value.items()}
    if isinstance(value, list):
        return [expand_env_vars(item) for item in value]
    return value


def is_unchanged(current_raw: Any, new_value: Any) -> bool:
    """True if ``new_value`` matches the current raw value once any ``${VAR}``
    placeholders in it are expanded - i.e. this field was not actually changed
    and the raw text (placeholder, comments, quoting) can be left untouched.

    A ``${VAR:default}`` placeholder always expands to a ``str`` (#127), even
    when the settings field it feeds is an ``int``/``bool`` (e.g.
    ``port: ${PORT:8000}`` vs. ``settings.port == 8000``), so the expanded
    value is coerced to ``new_value``'s type before comparing.
    """
    expanded = expand_env_vars(current_raw)
    if isinstance(expanded, str) and not isinstance(new_value, str):
        try:
            if isinstance(new_value, bool):
                expanded = expanded.strip().lower() in ("true", "1", "yes", "on")
            elif isinstance(new_value, int):
                expanded = int(expanded)
            elif isinstance(new_value, float):
                expanded = float(expanded)
        except ValueError:
            pass  # leave as str; comparison below will just be False
    return expanded == new_value


def _quoted(value: str) -> SingleQuotedScalarString:
    """Force single-quoted style so an embedded ``#`` is never mistaken for a
    comment and stray leading/trailing whitespace survives (#127).
    """
    return SingleQuotedScalarString(value)


def client_id_matches(raw_entry: Any, client_id: str) -> bool:
    """True if a raw settings.yaml client entry identifies the in-memory client
    with ``client_id``.

    ``client_id`` itself can be an env placeholder (``client_id: ${CLIENT_ID:app1}``),
    which is expanded to its resolved value in the loaded ``Settings`` (#127).
    Comparing the raw ``${CLIENT_ID:app1}`` against the expanded ``app1`` with
    ``==`` would miss the entry, so the merge would treat it as a brand-new
    client and rewrite it from expanded values - materializing any env-backed
    secret in the process. Match through ``is_unchanged`` so the placeholder
    expands before the comparison.
    """
    if not isinstance(raw_entry, dict):
        return False
    return is_unchanged(raw_entry.get("client_id"), client_id)


def load_yaml_document(file_path: Path) -> Dict[str, Any]:
    """Load a YAML document preserving comments/quote style for a later
    round-trip write. Returns an empty ``CommentedMap`` if the file is
    missing or empty.
    """
    if not file_path.exists():
        return CommentedMap()
    with open(file_path, "r") as f:
        return _yaml_rt.load(f) or CommentedMap()


def client_to_yaml(client: OAuthClient) -> Dict[str, Any]:
    """Build the settings.yaml entry for an OAuth client.

    Optional list fields are omitted when empty, so a default client stays a
    three-line entry. Free-form text is quoted so it round-trips safely even
    if it contains ``#`` (#127).
    """
    entry: Dict[str, Any] = {
        "client_id": client.client_id,
        "client_secret": _quoted(client.client_secret),
        "description": _quoted(client.description),
    }
    if client.additional_audiences:
        entry["additional_audiences"] = client.additional_audiences
    if client.redirect_uris:
        entry["redirect_uris"] = client.redirect_uris
    return entry


def merge_client_entry(raw_entry: Dict[str, Any], client: OAuthClient) -> Dict[str, Any]:
    """Update a single raw settings.yaml client entry from ``client``, field by
    field, guarded by ``is_unchanged()`` (#127/#138).

    Shared by ``merge_oauth_clients()`` (full-list merge) and
    ``YamlWriter.save_client()`` (single-entry update) so the merge rules -
    which fields are quoted, when an emptied optional list field is dropped -
    only exist once. Returns a new dict; ``raw_entry`` is not mutated.
    """
    updated = raw_entry.copy()
    for field_name, new_value in (
        ("client_id", client.client_id),
        ("client_secret", client.client_secret),
        ("description", client.description),
    ):
        if not is_unchanged(raw_entry.get(field_name), new_value):
            if field_name in {"client_secret", "description"}:
                updated[field_name] = _quoted(str(new_value))
            else:
                updated[field_name] = new_value

    for field_name, new_list_value in (
        ("additional_audiences", client.additional_audiences),
        ("redirect_uris", client.redirect_uris),
    ):
        if not is_unchanged(raw_entry.get(field_name), new_list_value):
            if new_list_value:
                updated[field_name] = new_list_value
            else:
                updated.pop(field_name, None)

    return updated


def merge_oauth_clients(
    raw_clients: Any, settings_clients: list["OAuthClient"]
) -> list[Dict[str, Any]]:
    """Merge OAuth client entries by client_id without rewriting untouched
    env-backed secret placeholders or sibling entries.

    Raw list entries are treated as the source of truth for values that are
    still unchanged, but genuine edits replace the matching fields without
    rebuilding the whole list. Added clients are appended; removed ones drop out.
    """
    raw_entries = [r for r in raw_clients if isinstance(r, dict)] if isinstance(
        raw_clients, list
    ) else []

    merged: list[Dict[str, Any]] = []

    for client in settings_clients:
        # Match by expanded client_id so a raw ``${CLIENT_ID:app1}`` entry is
        # recognised as the same client and its placeholders are preserved (#127).
        raw_entry = next(
            (r for r in raw_entries if client_id_matches(r, client.client_id)), None
        )
        if raw_entry is None:
            merged.append(client_to_yaml(client))
        else:
            merged.append(merge_client_entry(raw_entry, client))

    return merged


def user_to_yaml(user: User) -> Dict[str, Any]:
    """Build the users.yaml entry for a user.

    Canonical form is sparse: optional fields and model defaults
    (``tenant: default``, empty lists) are omitted and restored by the loader's
    defaults on the next read. Free-form text is quoted so it round-trips
    safely even if it contains ``#`` (#127). ``password`` is omitted entirely
    when ``None`` - a persona-mode-only user, as opposed to an empty-string
    password (which the model rejects outright).
    """
    entry: Dict[str, Any] = {}
    if user.password is not None:
        entry["password"] = _quoted(user.password)
    entry["email"] = user.email
    if user.identity_class:
        entry["identity_class"] = user.identity_class
    if user.entitlements:
        entry["entitlements"] = user.entitlements
    if user.roles:
        entry["roles"] = user.roles
    if user.groups:
        entry["groups"] = user.groups
    if user.tenant and user.tenant != "default":
        entry["tenant"] = user.tenant
    if user.source_acl:
        entry["source_acl"] = user.source_acl
    if user.attributes:
        entry["attributes"] = {
            k: (_quoted(v) if isinstance(v, str) else v)
            for k, v in user.attributes.items()
        }
    return entry


def apply_settings_document(
    document: Dict[str, Any], settings: Settings
) -> Dict[str, Any]:
    """Update the settings.yaml keys this codebase manages, in place.

    Read-modify-write: ``document`` is the currently persisted document (or
    ``{}``), and only owned keys are (re)written - anything else (``jwt``,
    ``session``, ``logging`` keys other than ``verbose_logging``, unknown
    custom keys) is preserved verbatim (#87). Optional owned keys are removed
    when back at their defaults, so a cleared ``security_profile`` does not
    linger in the file.

    Each field is only overwritten when its expanded on-disk value actually
    differs from the new one (#127), so untouched ``${VAR}`` placeholders,
    comments and quote style survive a save that changed something else.
    """
    server = document.setdefault("server", {})
    if not is_unchanged(server.get("host"), settings.host):
        server["host"] = settings.host
    if not is_unchanged(server.get("port"), settings.port):
        server["port"] = settings.port

    oauth = document.setdefault("oauth", {})
    if not is_unchanged(oauth.get("issuer"), settings.issuer):
        oauth["issuer"] = settings.issuer
    if not is_unchanged(oauth.get("issuer_from_request"), settings.issuer_from_request):
        oauth["issuer_from_request"] = settings.issuer_from_request
    if not is_unchanged(oauth.get("issuer_allowlist"), settings.issuer_allowlist or []):
        if settings.issuer_allowlist:
            oauth["issuer_allowlist"] = settings.issuer_allowlist
        else:
            oauth.pop("issuer_allowlist", None)
    device_verification_base_url = settings.device_verification_base_url or ""
    if not is_unchanged(
        oauth.get("device_verification_base_url"),
        device_verification_base_url,
    ):
        if settings.device_verification_base_url:
            oauth["device_verification_base_url"] = settings.device_verification_base_url
        else:
            oauth.pop("device_verification_base_url", None)
    if not is_unchanged(
        oauth.get("issuer_from_proxy_headers"), settings.issuer_from_proxy_headers
    ):
        oauth["issuer_from_proxy_headers"] = settings.issuer_from_proxy_headers
    if not is_unchanged(oauth.get("audience"), settings.audience):
        oauth["audience"] = settings.audience
    if not is_unchanged(oauth.get("token_expiry_minutes"), settings.token_expiry_minutes):
        oauth["token_expiry_minutes"] = settings.token_expiry_minutes
    if not is_unchanged(
        oauth.get("refresh_token_rotation"), settings.refresh_token_rotation
    ):
        oauth["refresh_token_rotation"] = settings.refresh_token_rotation
    if not is_unchanged(oauth.get("require_pkce"), settings.require_pkce):
        oauth["require_pkce"] = settings.require_pkce
    new_clients = merge_oauth_clients(oauth.get("clients", []), settings.clients)
    if new_clients != oauth.get("clients", []):
        if new_clients:
            oauth["clients"] = new_clients
        else:
            oauth.pop("clients", None)

    saml = document.setdefault("saml", {})
    if not is_unchanged(saml.get("entity_id"), settings.saml_entity_id):
        saml["entity_id"] = settings.saml_entity_id
    if not is_unchanged(saml.get("sso_url"), settings.saml_sso_url):
        saml["sso_url"] = settings.saml_sso_url
    if not is_unchanged(saml.get("default_acs_url"), settings.default_acs_url):
        saml["default_acs_url"] = settings.default_acs_url
    if not is_unchanged(saml.get("sign_responses"), settings.saml_sign_responses):
        saml["sign_responses"] = settings.saml_sign_responses
    if not is_unchanged(saml.get("export_roles"), settings.saml_export_roles):
        saml["export_roles"] = settings.saml_export_roles
    if not is_unchanged(saml.get("export_groups"), settings.saml_export_groups):
        saml["export_groups"] = settings.saml_export_groups
    if not is_unchanged(saml.get("roles_attr_name"), settings.saml_roles_attr_name):
        saml["roles_attr_name"] = settings.saml_roles_attr_name
    if not is_unchanged(saml.get("groups_attr_name"), settings.saml_groups_attr_name):
        saml["groups_attr_name"] = settings.saml_groups_attr_name
    if not is_unchanged(saml.get("c14n_algorithm"), settings.saml_c14n_algorithm):
        saml["c14n_algorithm"] = settings.saml_c14n_algorithm
    if not is_unchanged(saml.get("strict_binding"), settings.strict_saml_binding):
        saml["strict_binding"] = settings.strict_saml_binding
    if not is_unchanged(
        saml.get("want_authn_requests_signed"), settings.saml_want_authn_requests_signed
    ):
        saml["want_authn_requests_signed"] = settings.saml_want_authn_requests_signed
    if not is_unchanged(saml.get("sp_certificates"), settings.saml_sp_certificates or []):
        if settings.saml_sp_certificates:
            saml["sp_certificates"] = settings.saml_sp_certificates
        else:
            saml.pop("sp_certificates", None)

    logging_section = document.setdefault("logging", {})
    if not is_unchanged(logging_section.get("verbose_logging"), settings.verbose_logging):
        logging_section["verbose_logging"] = settings.verbose_logging

    if not is_unchanged(document.get("authority_prefixes"), settings.authority_prefixes):
        document["authority_prefixes"] = settings.authority_prefixes

    if not is_unchanged(
        document.get("allowed_identity_classes"), settings.allowed_identity_classes or []
    ):
        if settings.allowed_identity_classes:
            document["allowed_identity_classes"] = settings.allowed_identity_classes
        else:
            document.pop("allowed_identity_classes", None)

    security_profile_default = "dev"
    current_security_profile = document.get("security_profile", security_profile_default)
    if not is_unchanged(current_security_profile, settings.security_profile):
        if settings.security_profile != security_profile_default:
            document["security_profile"] = settings.security_profile
        else:
            document.pop("security_profile", None)

    login_mode_default = "password"
    login_section = document.get("login") or {}
    current_login_mode = login_section.get("mode", login_mode_default)
    if not is_unchanged(current_login_mode, settings.login_mode):
        if settings.login_mode != login_mode_default:
            document.setdefault("login", {})["mode"] = settings.login_mode
        elif "login" in document:
            document["login"].pop("mode", None)
            if not document["login"]:
                document.pop("login", None)

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
    on failure the previous content is restored from the backup. Dumps with
    ``ruamel.yaml`` in round-trip mode so comments and quote style captured by
    ``load_yaml_document`` survive (#127).
    """
    backup_path = file_path.with_suffix(".yaml.bak")
    if file_path.exists():
        shutil.copy2(file_path, backup_path)

    fd, temp_path = tempfile.mkstemp(
        suffix=".yaml", prefix=file_path.stem + "_", dir=file_path.parent
    )
    try:
        with os.fdopen(fd, "w") as f:
            _yaml_rt.dump(data, f)
        os.replace(temp_path, file_path)
        logger.info(f"Successfully wrote {file_path}")
    except Exception as e:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
        if backup_path.exists():
            shutil.copy2(backup_path, file_path)
            logger.warning(f"Restored {file_path} from backup after write failure")
        raise RuntimeError(f"Failed to write {file_path}: {e}") from e
