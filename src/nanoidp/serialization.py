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
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Mapping, Optional

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

_ENV_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::([^}]*))?\}")


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


def merge_optional_nested_field(
    document: Dict[str, Any],
    section_key: str,
    field_key: str,
    value: Any,
    default: Any,
) -> None:
    """Write ``document[section_key][field_key] = value``, omitting the field
    (and the whole section, once empty) when ``value`` equals ``default`` -
    the "omit at default" convention shared by every optional settings
    section (``security_profile``, ``login.mode``, ...). A bare
    ``section_key:`` line in YAML parses to ``{section_key: None}``, not a
    missing key, hence ``or {}`` rather than a ``.get(..., {})`` default.

    Shared between ``apply_settings_document`` (below) and
    ``YamlWriter.update_login_settings`` so the merge logic isn't duplicated
    at each call site.
    """
    section = document.get(section_key) or {}
    current = section.get(field_key, default)
    if is_unchanged(current, value):
        return
    if value != default:
        # Not `setdefault(section_key, {})`: a bare `section_key:` line
        # already has the key present with a `None` value, and setdefault
        # only fills in *missing* keys - it would hand back that `None`
        # unchanged and the subscript assignment below would raise.
        if document.get(section_key) is None:
            document[section_key] = {}
        document[section_key][field_key] = value
    elif section_key in document:
        document[section_key].pop(field_key, None)
        if not document[section_key]:
            document.pop(section_key, None)


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


# Config schema version (#175, piece 1). One integer, not semver: optional
# additions never bump it; renames, removals or semantic changes do, together
# with a migration step in the loader.
#
# Two constants on purpose (#175 review): CONFIG_VERSION is the newest
# contract this release understands and moves with each bump;
# IMPLICIT_CONFIG_VERSION is what a file WITHOUT the key declares and is
# frozen at 1 forever, because files written before the key existed must
# keep loading as v1 (and migrating from there) no matter how far
# CONFIG_VERSION advances.
CONFIG_VERSION = 1
IMPLICIT_CONFIG_VERSION = 1


def check_config_version(data: Dict[str, Any], file_path: Path) -> int:
    """Validate a document's top-level ``config_version`` and return the
    effective value (``IMPLICIT_CONFIG_VERSION``, i.e. 1, when the key is
    absent - never the current ``CONFIG_VERSION``).

    ``config_version`` is the version of the configuration directory's
    contract as a whole, not of one file: ``settings.yaml`` and
    ``users.yaml`` declare the same number, each file is validated
    independently against ``CONFIG_VERSION`` with this function, and a
    future bump applies to both files together with one loader migration.
    The value must be a literal integer: the check runs before ``${VAR}``
    expansion by design, so a placeholder here is rejected.

    Raises ``ValueError`` naming the file, the value found and the supported
    version when the value is not a positive integer or is newer than this
    release understands. Lower or equal versions load normally.
    """
    if "config_version" not in data:
        return IMPLICIT_CONFIG_VERSION
    value = data["config_version"]
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(
            f"{file_path}: config_version must be a positive integer, "
            f"found {value!r} (this release supports config_version {CONFIG_VERSION})"
        )
    if value > CONFIG_VERSION:
        raise ValueError(
            f"{file_path}: config_version {value} is newer than this release "
            f"supports (config_version {CONFIG_VERSION}); upgrade nanoidp or "
            f"downgrade the file"
        )
    return value


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
    if client.background_color:
        entry["background_color"] = client.background_color
    if client.header_color:
        entry["header_color"] = client.header_color
    if client.footer_color:
        entry["footer_color"] = client.footer_color
    if not client.show_client_id:
        entry["show_client_id"] = False
    if client.show_description:
        entry["show_description"] = True
    if client.additional_audiences:
        entry["additional_audiences"] = client.additional_audiences
    if client.redirect_uris:
        entry["redirect_uris"] = client.redirect_uris
    if client.allowed_scopes:
        entry["allowed_scopes"] = client.allowed_scopes
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
        ("background_color", client.background_color),
        ("header_color", client.header_color),
        ("footer_color", client.footer_color),
    ):
        if not is_unchanged(raw_entry.get(field_name), new_value):
            if field_name in {"client_secret", "description"}:
                updated[field_name] = _quoted(str(new_value))
            else:
                updated[field_name] = new_value if new_value else None
                if updated[field_name] is None:
                    updated.pop(field_name, None)

    for field_name, new_bool_value, default_value in (
        ("show_client_id", client.show_client_id, True),
        ("show_description", client.show_description, False),
    ):
        if not is_unchanged(raw_entry.get(field_name), new_bool_value):
            if new_bool_value != default_value:
                updated[field_name] = new_bool_value
            else:
                updated.pop(field_name, None)

    for field_name, new_list_value in (
        ("additional_audiences", client.additional_audiences),
        ("redirect_uris", client.redirect_uris),
        ("allowed_scopes", client.allowed_scopes),
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
    raw_entries = (
        [r for r in raw_clients if isinstance(r, dict)] if isinstance(raw_clients, list) else []
    )

    merged: list[Dict[str, Any]] = []

    for client in settings_clients:
        # Match by expanded client_id so a raw ``${CLIENT_ID:app1}`` entry is
        # recognised as the same client and its placeholders are preserved (#127).
        raw_entry = next((r for r in raw_entries if client_id_matches(r, client.client_id)), None)
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
            k: (_quoted(v) if isinstance(v, str) else v) for k, v in user.attributes.items()
        }
    return entry


# Fallback used when a caller passes no ``defaults`` mapping. The source of
# truth is ``config_documents.document_defaults()`` (the document models);
# this module cannot import it at runtime (import contract, #149), so
# callers hand it in and these two literals only cover legacy call sites.
_FALLBACK_DEFAULTS: Dict[str, Any] = {
    "security_profile": "dev",
    "login.mode": "password",
}


@dataclass(frozen=True)
class OwnedSetting:
    """One settings.yaml key this codebase manages (#214).

    The single description of where a Settings attribute lives in the file
    and how its absence is encoded; ``apply_settings_document`` below and
    ``yaml_writer.update_oauth_settings``/``update_saml_settings`` both
    drive from ``OWNED_SETTINGS`` instead of repeating one if-block per
    field. A test asserts every row against the document models
    (config_documents), so the models stay the single source of truth.

    ``doc_mode`` is how ``apply_settings_document`` encodes the attribute:
    - "plain": always written when changed.
    - "omit_when_falsy": a falsy value means the key is absent from the
      file (``empty`` is the falsy stand-in used for the unchanged check).
    - "omit_when_none": None means absent (derived values, #181); any
      non-None value, including "", is written.
    The writer's per-call semantics are simpler and shared: a kwarg that is
    None was not on the form (leave the file alone, #131); for non-plain
    rows a falsy provided value clears the key.
    """

    section: str  # "" = a top-level key
    key: str
    attr: str  # the Settings attribute name
    doc_mode: str = "plain"
    empty: Any = None


OWNED_SETTINGS: tuple[OwnedSetting, ...] = (
    OwnedSetting("server", "host", "host"),
    OwnedSetting("server", "port", "port"),
    OwnedSetting("oauth", "issuer", "issuer"),
    OwnedSetting("oauth", "issuer_from_request", "issuer_from_request"),
    OwnedSetting("oauth", "issuer_allowlist", "issuer_allowlist", "omit_when_falsy", []),
    OwnedSetting(
        "oauth",
        "device_verification_base_url",
        "device_verification_base_url",
        "omit_when_falsy",
        "",
    ),
    OwnedSetting("oauth", "issuer_from_proxy_headers", "issuer_from_proxy_headers"),
    OwnedSetting("oauth", "audience", "audience"),
    OwnedSetting("oauth", "token_expiry_minutes", "token_expiry_minutes"),
    OwnedSetting("oauth", "refresh_token_rotation", "refresh_token_rotation"),
    OwnedSetting("oauth", "require_pkce", "require_pkce"),
    OwnedSetting("oauth", "logos_dir", "logos_dir", "omit_when_falsy", ""),
    OwnedSetting("saml", "entity_id", "saml_entity_id", "omit_when_none"),
    OwnedSetting("saml", "sso_url", "saml_sso_url", "omit_when_none"),
    OwnedSetting("saml", "default_acs_url", "default_acs_url"),
    OwnedSetting("saml", "sign_responses", "saml_sign_responses"),
    OwnedSetting("saml", "export_roles", "saml_export_roles"),
    OwnedSetting("saml", "export_groups", "saml_export_groups"),
    OwnedSetting("saml", "roles_attr_name", "saml_roles_attr_name"),
    OwnedSetting("saml", "groups_attr_name", "saml_groups_attr_name"),
    OwnedSetting("saml", "c14n_algorithm", "saml_c14n_algorithm"),
    OwnedSetting("saml", "strict_binding", "strict_saml_binding"),
    OwnedSetting("saml", "want_authn_requests_signed", "saml_want_authn_requests_signed"),
    OwnedSetting("saml", "sp_certificates", "saml_sp_certificates", "omit_when_falsy", []),
    OwnedSetting("logging", "verbose_logging", "verbose_logging"),
    OwnedSetting("", "authority_prefixes", "authority_prefixes"),
    OwnedSetting("", "allowed_identity_classes", "allowed_identity_classes", "omit_when_falsy", []),
)


def apply_settings_document(
    document: Dict[str, Any],
    settings: Settings,
    defaults: Optional[Mapping[str, Any]] = None,
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

    The per-field encodings live on ``OWNED_SETTINGS`` (#214); only the two
    defaults-dependent keys (``security_profile``, ``login.mode``) are
    handled explicitly below.
    """
    for field in OWNED_SETTINGS:
        target = document if not field.section else document.setdefault(field.section, {})
        value = getattr(settings, field.attr)
        if field.doc_mode == "plain":
            if not is_unchanged(target.get(field.key), value):
                target[field.key] = value
        elif field.doc_mode == "omit_when_falsy":
            if not is_unchanged(target.get(field.key), value or field.empty):
                if value:
                    target[field.key] = value
                else:
                    target.pop(field.key, None)
        else:  # omit_when_none: derived-when-absent (#181)
            if value is None:
                target.pop(field.key, None)
            elif not is_unchanged(target.get(field.key), value):
                target[field.key] = value

    # Clients are a merged list, not a scalar key: each entry round-trips
    # through merge_client_entry, so they stay outside OWNED_SETTINGS.
    oauth = document.setdefault("oauth", {})
    new_clients = merge_oauth_clients(oauth.get("clients", []), settings.clients)
    if new_clients != oauth.get("clients", []):
        if new_clients:
            oauth["clients"] = new_clients
        else:
            oauth.pop("clients", None)

    # "Omit at default" decisions read the loader's defaults (#175 piece 2).
    resolved_defaults = defaults if defaults is not None else _FALLBACK_DEFAULTS
    security_profile_default = resolved_defaults["security_profile"]
    current_security_profile = document.get("security_profile", security_profile_default)
    if not is_unchanged(current_security_profile, settings.security_profile):
        if settings.security_profile != security_profile_default:
            document["security_profile"] = settings.security_profile
        else:
            document.pop("security_profile", None)

    login_mode_default = resolved_defaults["login.mode"]
    merge_optional_nested_field(document, "login", "mode", settings.login_mode, login_mode_default)

    return document


def apply_users_document(
    document: Dict[str, Any], users: Dict[str, User], default_user: str
) -> Dict[str, Any]:
    """Update the users.yaml keys this codebase manages, in place.

    The full user map is owned; unknown top-level keys are preserved.
    """
    document["users"] = {username: user_to_yaml(user) for username, user in users.items()}
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
