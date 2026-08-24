"""
Document models: the YAML contract of ``settings.yaml`` and ``users.yaml``.

One Pydantic model per YAML section, with field names equal to the YAML keys
and defaults equal to what the loader used to hard-code in ``config.py``
(#175, piece 2). The flow is ``YAML -> document model -> domain model``:

- ``SettingsDocument`` / ``UsersDocument`` describe exactly what a file may
  contain (``extra="forbid"`` at every level except a user entry, see
  ``UserEntry``), so an unknown key is detected with its dotted path instead
  of being silently ignored by a hand-written ``.get()`` chain.
- ``to_settings()`` / ``to_users()`` build the existing domain models
  (``Settings``, ``User``, ``OAuthClient``) unchanged; every validator those
  models carry keeps running, so nothing that failed before loads now.

``${VAR}`` placeholders are expanded and ``config_version`` is checked by the
loader BEFORE a document is built (``serialization.expand_env_vars`` and
``check_config_version``), so this module only ever sees plain values. It
imports ``models`` and nothing else from the package; ``serialization.py``
must not import it at runtime (import contract, #149), which is why the
writer receives the defaults it needs as a mapping (``document_defaults``)
rather than importing this module.

Keys that shipped files carry but the loader never consumed (``cors_allowed_origins``,
``device_flow``, ``logging.format``, ``oauth.refresh_token_expiry_minutes``,
``session.permanent``) are declared here so they keep loading without a
warning; they are still not consumed, exactly as before. Turning any of them
into behaviour is a separate change, not a side effect of this refactor.
"""

from __future__ import annotations

import copy
import logging
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple, Type, TypeVar

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from .models import (
    OAuthClient,
    Settings,
    User,
    _coerce_additional_audiences,
    _coerce_client_str_list,
)

logger = logging.getLogger(__name__)

DocumentT = TypeVar("DocumentT", bound=BaseModel)

_FORBID = ConfigDict(extra="forbid")

# Accepted values of the top-level ``config_validation`` key (#175 piece 4).
VALIDATION_MODES = ("warn", "strict")


class ServerSection(BaseModel):
    model_config = _FORBID

    host: str = "127.0.0.1"
    port: int = 8000
    debug: bool = False


class ClientEntry(BaseModel):
    """One ``oauth.clients[]`` entry. ``additional_audiences`` and
    ``redirect_uris`` stay ``Any`` here because the loader accepts a scalar
    string as a one-element list and reports unsupported shapes with a
    client-scoped message (#35); that coercion runs in ``to_client()``."""

    model_config = _FORBID

    client_id: str = ""
    client_secret: str = ""
    description: str = ""
    background_color: Optional[str] = None
    header_color: Optional[str] = None
    footer_color: Optional[str] = None
    show_client_id: bool = True
    show_description: bool = False
    additional_audiences: Any = None
    redirect_uris: Any = None

    def to_client(self) -> OAuthClient:
        return OAuthClient(
            client_id=self.client_id,
            client_secret=self.client_secret,
            description=self.description,
            background_color=self.background_color,
            header_color=self.header_color,
            footer_color=self.footer_color,
            show_client_id=self.show_client_id,
            show_description=self.show_description,
            additional_audiences=_coerce_additional_audiences(
                self.additional_audiences, self.client_id
            ),
            redirect_uris=_coerce_client_str_list(
                self.redirect_uris, self.client_id, "redirect_uris"
            ),
        )


class OAuthSection(BaseModel):
    model_config = _FORBID

    issuer: str = "http://localhost:8000"
    issuer_from_request: bool = False
    issuer_allowlist: Optional[List[str]] = None
    device_verification_base_url: Optional[str] = None
    issuer_from_proxy_headers: bool = False
    audience: str = "default"
    token_expiry_minutes: int = 60
    refresh_token_rotation: bool = False
    require_pkce: bool = False
    # Absent = no clients; an explicit `clients:` (null) is a type error, as
    # it was for the old loader (#197 review: null and missing differ).
    clients: List[ClientEntry] = Field(default_factory=list)
    logos_dir: Optional[str] = None
    # Present in shipped presets, never consumed by the loader (accepted for
    # compatibility; see the module docstring).
    # Accepted for compatibility (shipped presets carry it), never consumed and
    # therefore never validated: the old loader did not read it at all, so any
    # value must keep loading (#197 review).
    refresh_token_expiry_minutes: Any = None


class SamlSection(BaseModel):
    model_config = _FORBID

    # Absent or blank means "derived from the effective issuer" (#181).
    entity_id: Optional[str] = None
    sso_url: Optional[str] = None
    default_acs_url: str = "http://localhost:8080/login/saml2/sso/samlIdp"
    sign_responses: bool = True
    export_roles: bool = False
    export_groups: bool = False
    # Optional on purpose: the domain model's before-validator
    # (normalize_saml_attr_name) turns None/blank into the default, and a
    # bare `roles_attr_name:` line must keep reaching it (#197 review).
    roles_attr_name: Optional[str] = "roles"
    groups_attr_name: Optional[str] = "groups"
    c14n_algorithm: str = "exc_c14n"
    want_authn_requests_signed: bool = False
    sp_certificates: Optional[List[str]] = None
    strict_binding: bool = False


class JwtSection(BaseModel):
    model_config = _FORBID

    algorithm: str = "RS256"
    keys_dir: str = "./keys"


class SessionSection(BaseModel):
    model_config = _FORBID

    secret_key: str = "dev-secret-key-change-in-production"
    require_ui_login: bool = False
    enforce_password_check: bool = False
    # Shipped presets carry it; the app sets session.permanent itself.
    permanent: Any = None  # accepted for compatibility, never consumed


class LoggingSection(BaseModel):
    model_config = _FORBID

    level: str = "INFO"
    log_token_requests: bool = True
    log_saml_requests: bool = True
    verbose_logging: bool = True
    # Shipped presets carry it; logging.basicConfig uses a fixed format.
    format: Any = None  # accepted for compatibility, never consumed


class LoginSection(BaseModel):
    model_config = _FORBID

    mode: str = "password"


class HooksSection(BaseModel):
    """``hooks:`` (#185): shell commands run at the three extension points.

    Absent = no hooks. ``strict`` applies to plugins too; ``timeout_seconds``
    is for shell hooks only (a plugin manages its own timeouts). Policy
    values declared here override ``bootstrap.yaml``'s; undeclared ones do
    not (``model_fields_set`` decides). YAML-only (and ``bootstrap.yaml``/env): never settable from the UI
    or MCP, since a command editable through the surface it observes would
    be a remote-execution primitive.
    """

    model_config = _FORBID

    on_before_load: Optional[str] = None
    on_config_saved: Optional[str] = None
    on_audit_event: Optional[str] = None
    strict: bool = False
    timeout_seconds: float = Field(default=10.0, gt=0)


def _validate_plugins_mapping(value: Any) -> Dict[str, Dict[str, Any]]:
    """``plugins:`` is a mapping of plugin name -> its own settings mapping.

    The only section with plugin-owned keys: the core validates the shape
    (name -> mapping, a bare ``name:`` meaning no settings) and nothing
    inside, because the keys belong to the plugin (#185).
    """
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("plugins must be a mapping of plugin name -> settings mapping")
    result: Dict[str, Dict[str, Any]] = {}
    for name, settings in value.items():
        if not isinstance(name, str) or not name:
            raise ValueError("plugin names must be non-empty strings")
        if settings is None:
            result[name] = {}
        elif isinstance(settings, dict):
            result[name] = dict(settings)
        else:
            raise ValueError(f"plugins.{name} must be a mapping (or empty)")
    return result



_SECTIONS = ("server", "oauth", "saml", "jwt", "session", "logging", "login")


class SettingsDocument(BaseModel):
    """Top-level shape of ``settings.yaml``."""

    model_config = _FORBID

    # Validated by serialization.check_config_version before the document is
    # built; declared so the key is known.
    config_version: Optional[int] = None
    server: ServerSection = Field(default_factory=ServerSection)
    oauth: OAuthSection = Field(default_factory=OAuthSection)
    saml: SamlSection = Field(default_factory=SamlSection)
    jwt: JwtSection = Field(default_factory=JwtSection)
    session: SessionSection = Field(default_factory=SessionSection)
    logging: LoggingSection = Field(default_factory=LoggingSection)
    login: LoginSection = Field(default_factory=LoginSection)
    security_profile: str = "dev"
    # How the loader reacts to an unknown key in this configuration directory
    # (#175 piece 4). "warn" (default) logs it with its dotted path and
    # ignores it; "strict" refuses to load. The server's --strict-config flag
    # wins over this value for that run and is never written back. The value
    # is read from the raw YAML before the document is validated, because it
    # decides how this very validation reports; it applies to users.yaml and
    # bootstrap.yaml too, one contract per directory.
    config_validation: str = "warn"
    authority_prefixes: Dict[str, str] = Field(default_factory=dict)
    allowed_identity_classes: List[str] = Field(default_factory=list)
    # Accepted for compatibility, not consumed (module docstring).
    # Accepted for compatibility, never consumed (the old loader never read it;
    # CORS stays ["*"]), hence Any: no new validation on an ignored key.
    cors_allowed_origins: Any = None
    # Never read by the old loader, so neither the container shape nor its
    # keys are validated: `device_flow: whatever` and a bare `device_flow:`
    # loaded before and still do (#197 review).
    device_flow: Any = None
    # Extension points (#185). Absent = off.
    hooks: HooksSection = Field(default_factory=HooksSection)
    plugins: Dict[str, Dict[str, Any]] = Field(default_factory=dict)

    @field_validator("plugins", mode="before")
    @classmethod
    def _plugins_shape(cls, value: Any) -> Dict[str, Dict[str, Any]]:
        return _validate_plugins_mapping(value)

    @field_validator("config_validation")
    @classmethod
    def _known_validation_mode(cls, value: str) -> str:
        if value not in VALIDATION_MODES:
            raise ValueError(
                f"config_validation must be one of {', '.join(VALIDATION_MODES)}"
            )
        return value

    @model_validator(mode="before")
    @classmethod
    def _bare_login_is_empty(cls, data: Any) -> Any:
        """A bare ``login:`` line parses to ``{"login": None}``, not a missing
        key. The old loader special-cased exactly this one section
        (``data.get("login") or {}``); every other bare section was, and
        stays, a type error: null and missing are different things (#197
        review)."""
        if isinstance(data, dict) and "login" in data and data["login"] is None:
            data = {**data, "login": {}}
        return data

    def to_settings(self) -> Settings:
        """Build the domain ``Settings`` exactly as the old loader did."""
        clients = [entry.to_client() for entry in self.oauth.clients]

        # A client_id must be unique. Duplicates - including two ${VAR}
        # placeholders that expand to the same value - make client lookup
        # ambiguous and cause the settings-save merge to match the wrong raw
        # entry, which can materialize an env-backed secret (#127/#151). Fail
        # fast rather than silently corrupt settings.yaml on the next save.
        seen_client_ids: set[str] = set()
        for parsed_client in clients:
            if parsed_client.client_id in seen_client_ids:
                raise ValueError(
                    f"Duplicate OAuth client_id '{parsed_client.client_id}' in "
                    "settings.yaml; client ids must be unique (check for env "
                    "placeholders that expand to the same value)"
                )
            seen_client_ids.add(parsed_client.client_id)

        return Settings(
            host=self.server.host,
            port=self.server.port,
            debug=self.server.debug,
            issuer=self.oauth.issuer,
            issuer_from_request=self.oauth.issuer_from_request,
            issuer_allowlist=self.oauth.issuer_allowlist or [],
            device_verification_base_url=self.oauth.device_verification_base_url,
            issuer_from_proxy_headers=self.oauth.issuer_from_proxy_headers,
            audience=self.oauth.audience,
            token_expiry_minutes=self.oauth.token_expiry_minutes,
            refresh_token_rotation=self.oauth.refresh_token_rotation,
            require_pkce=self.oauth.require_pkce,
            clients=clients,
            logos_dir=self.oauth.logos_dir,
            saml_entity_id=self.saml.entity_id or None,
            saml_sso_url=self.saml.sso_url or None,
            default_acs_url=self.saml.default_acs_url,
            saml_sign_responses=self.saml.sign_responses,
            saml_export_roles=self.saml.export_roles,
            saml_export_groups=self.saml.export_groups,
            # None passes through on purpose: Settings' before-validator
            # normalizes it to the default, exactly as the old loader let it.
            saml_roles_attr_name=self.saml.roles_attr_name,  # type: ignore[arg-type]
            saml_groups_attr_name=self.saml.groups_attr_name,  # type: ignore[arg-type]
            saml_c14n_algorithm=self.saml.c14n_algorithm,
            saml_want_authn_requests_signed=self.saml.want_authn_requests_signed,
            saml_sp_certificates=self.saml.sp_certificates or [],
            strict_saml_binding=self.saml.strict_binding,
            jwt_algorithm=self.jwt.algorithm,
            keys_dir=self.jwt.keys_dir,
            login_mode=self.login.mode,
            security_profile=self.security_profile,
            authority_prefixes=self.authority_prefixes,
            allowed_identity_classes=self.allowed_identity_classes,
            secret_key=self.session.secret_key,
            require_ui_login=self.session.require_ui_login,
            enforce_password_check=self.session.enforce_password_check,
            log_level=self.logging.level,
            log_token_requests=self.logging.log_token_requests,
            log_saml_requests=self.logging.log_saml_requests,
            verbose_logging=self.logging.verbose_logging,
        )


class BootstrapDocument(BaseModel):
    """``bootstrap.yaml`` (#185): the hook surface that exists before
    ``settings.yaml`` can be read. Only ``hooks:`` and ``plugins:`` are
    allowed, validated by the same section models; anything else is refused
    so the file cannot quietly grow into a second settings file."""

    model_config = _FORBID

    hooks: HooksSection = Field(default_factory=HooksSection)
    plugins: Dict[str, Dict[str, Any]] = Field(default_factory=dict)

    @field_validator("plugins", mode="before")
    @classmethod
    def _plugins_shape(cls, value: Any) -> Dict[str, Dict[str, Any]]:
        return _validate_plugins_mapping(value)

    @model_validator(mode="before")
    @classmethod
    def _bare_sections_are_empty(cls, data: Any) -> Any:
        if isinstance(data, dict):
            for key in ("hooks", "plugins"):
                if key in data and data[key] is None:
                    data = {**data, key: {}}
        return data


# Keys of a user entry the domain model knows. Anything else in a user's
# mapping has always been folded into ``attributes`` (backward compatibility
# with pre-``attributes:`` files), so a user entry is the one place that must
# NOT forbid extras.
_USER_KNOWN_FIELDS = frozenset(
    {"password", "email", "identity_class", "entitlements", "roles", "groups",
     "tenant", "source_acl", "attributes"}
)


class UserEntry(BaseModel):
    """One ``users.<name>`` mapping. Defaults mirror the old loader: a
    missing ``password`` is ``None`` (persona-only user), ``roles`` default
    to ``["USER"]``, ``email`` to ``<username>@example.org`` (filled in by
    ``to_user`` because it needs the key)."""

    model_config = ConfigDict(extra="allow")

    # Missing -> default, explicit null -> validation error, exactly like the
    # old ``user_data.get(key, default)`` followed by the domain model's
    # validators (#197 review). ``password`` and ``identity_class`` are the
    # two fields whose domain type is Optional, so null is valid there.
    password: Optional[str] = None
    email: Optional[str] = None
    identity_class: Optional[str] = None
    entitlements: List[str] = Field(default_factory=list)
    roles: List[str] = Field(default_factory=lambda: ["USER"])
    groups: List[str] = Field(default_factory=list)
    tenant: str = "default"
    source_acl: List[str] = Field(default_factory=list)
    attributes: Dict[str, Any] = Field(default_factory=dict)

    def to_user(self, username: str) -> User:
        attributes: Dict[str, Any] = dict(self.attributes)
        # Any field not in the known set becomes an attribute (legacy files).
        for key, value in (self.model_extra or {}).items():
            if key not in _USER_KNOWN_FIELDS and key not in attributes:
                attributes[key] = value
        return User(
            username=username,
            password=self.password,
            # Default depends on the key, so "absent" is detected through
            # model_fields_set; an explicit `email: null` reaches User.email
            # (a str) and fails there, as it did before.
            email=(
                # An explicit null is passed through on purpose so that
                # User.email (a str) rejects it at runtime, as before.
                self.email  # type: ignore[arg-type]
                if "email" in self.model_fields_set
                else f"{username}@example.org"
            ),
            identity_class=self.identity_class,
            entitlements=self.entitlements,
            roles=self.roles,
            groups=self.groups,
            tenant=self.tenant,
            source_acl=self.source_acl,
            attributes=attributes,
        )


class UsersDocument(BaseModel):
    """Top-level shape of ``users.yaml``."""

    model_config = _FORBID

    config_version: Optional[int] = None
    default_user: str = "admin"
    # Absent = no users; a bare `users:` (null) is a type error, as before.
    users: Dict[str, UserEntry] = Field(default_factory=dict)

    def to_users(self) -> Tuple[Dict[str, User], str]:
        users = {
            username: entry.to_user(username)
            for username, entry in self.users.items()
        }
        return users, self.default_user


def _dotted(loc: Tuple[Any, ...]) -> str:
    parts: List[str] = []
    for item in loc:
        if isinstance(item, int):
            parts[-1] = f"{parts[-1]}[{item}]" if parts else f"[{item}]"
        else:
            parts.append(str(item))
    return ".".join(parts)


def _drop_path(data: Any, loc: Tuple[Any, ...]) -> None:
    target = data
    for item in loc[:-1]:
        target = target[item]
    if isinstance(target, dict):
        target.pop(loc[-1], None)


def unknown_key_message(file_path: Path, loc: Tuple[Any, ...]) -> str:
    """The one wording of an unknown-key finding, shared by the warning, the
    strict error and ``nanoidp validate-config`` (#175 piece 4)."""
    return f"{file_path}: unknown key {_dotted(loc)}"


def _load_document(
    model: Type[DocumentT],
    data: Dict[str, Any],
    file_path: Path,
    *,
    strict: bool = False,
    on_unknown: Optional[Callable[[str], None]] = None,
) -> DocumentT:
    """Validate ``data`` against ``model``.

    Unknown keys (``extra_forbidden``) are reported with their dotted path,
    removed, and validation is retried, so a typo such as ``oauth.isuer`` no
    longer vanishes silently (#175) while files that load today keep loading.
    Any other error (wrong type, invalid value) raises a ``ValueError``
    naming the file and the path.

    ``strict`` (``config_validation: strict`` or ``--strict-config``, #175
    piece 4) turns the unknown key into that same ``ValueError`` instead:
    same text, no ``(ignored)`` suffix, raised at load and at every reload.
    ``on_unknown`` receives the message instead of the logger when a caller
    collects findings rather than starting the server
    (``nanoidp validate-config``).
    """
    working = data
    for _attempt in range(2):
        try:
            return model.model_validate(working)
        except ValidationError as exc:
            unknown = [e for e in exc.errors() if e["type"] == "extra_forbidden"]
            others = [e for e in exc.errors() if e["type"] != "extra_forbidden"]
            if others or not unknown:
                first = others[0] if others else unknown[0]
                raise ValueError(
                    f"{file_path}: invalid value at {_dotted(first['loc']) or '<root>'}: "
                    f"{first['msg']}"
                ) from exc
            if strict:
                raise ValueError(unknown_key_message(file_path, unknown[0]["loc"])) from exc
            working = copy.deepcopy(working) if working is data else working
            for error in unknown:
                message = unknown_key_message(file_path, error["loc"])
                if on_unknown is not None:
                    on_unknown(message)
                else:
                    logger.warning(f"{message} (ignored)")
                _drop_path(working, error["loc"])
    return model.model_validate(working)  # pragma: no cover - second pass raised


def load_settings_document(
    data: Dict[str, Any],
    file_path: Path,
    *,
    strict: bool = False,
    on_unknown: Optional[Callable[[str], None]] = None,
) -> SettingsDocument:
    return _load_document(
        SettingsDocument, data, file_path, strict=strict, on_unknown=on_unknown
    )


def load_users_document(
    data: Dict[str, Any],
    file_path: Path,
    *,
    strict: bool = False,
    on_unknown: Optional[Callable[[str], None]] = None,
) -> UsersDocument:
    return _load_document(
        UsersDocument, data, file_path, strict=strict, on_unknown=on_unknown
    )


def load_bootstrap_document(
    data: Dict[str, Any],
    file_path: Path,
    *,
    strict: bool = False,
    on_unknown: Optional[Callable[[str], None]] = None,
) -> BootstrapDocument:
    """``bootstrap.yaml`` goes through the same unknown-key / wrong-type
    reporting as ``settings.yaml`` (review before 2.7.0rc4), and the same
    strictness: it is declared in settings.yaml, one contract per directory."""
    return _load_document(
        BootstrapDocument, data, file_path, strict=strict, on_unknown=on_unknown
    )


def declared_validation_mode(data: Mapping[str, Any]) -> str:
    """The ``config_validation`` a raw settings.yaml mapping declares.

    Read from the raw YAML, before the document is built, because it decides
    how that build reports an unknown key - and before the registry reads
    ``bootstrap.yaml``, which is loaded first but follows settings.yaml's
    choice. An unrecognized value returns the default and is left to the
    document validator, which reports it with its path like any bad value.
    """
    value = data.get("config_validation")
    return value if value in VALIDATION_MODES else "warn"


def document_defaults() -> Dict[str, Any]:
    """Flat ``section.key -> default`` mapping of every settings.yaml key.

    Handed to the writer (``serialization.apply_settings_document`` and the
    ``YamlWriter``) so "omit at default" decisions read the same defaults the
    loader applies, without ``serialization.py`` importing this module.
    """
    doc = SettingsDocument()
    defaults: Dict[str, Any] = {}
    for key, value in doc.model_dump().items():
        if key in _SECTIONS:
            for sub_key, sub_value in value.items():
                defaults[f"{key}.{sub_key}"] = sub_value
        else:
            defaults[key] = value
    return defaults
