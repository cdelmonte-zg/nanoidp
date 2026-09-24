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

Five keys used to be declared here only so that files carrying them loaded
without a warning, with any value, and did nothing (#441). Four are
settings now (``oauth.refresh_token_expiry_minutes``, ``device_flow``,
``cors_allowed_origins``); ``logging.format`` and ``session.permanent`` are
not declared any more, so they are reported like every unknown key.
"""

from __future__ import annotations

import copy
import logging
import os
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Literal,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Type,
    TypeVar,
)

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from .models import (
    DEFAULT_SCOPES_SUPPORTED,
    SAML_C14N_DEFAULT,
    LoginMode,
    OAuthClient,
    RuntimeStoreKind,
    SamlC14nAlgorithm,
    Settings,
    User,
    _coerce_additional_audiences,
    _coerce_client_str_list,
    normalize_saml_c14n_algorithm,
)
from .serialization import check_config_version, expand_env_vars

logger = logging.getLogger(__name__)

DocumentT = TypeVar("DocumentT", bound=BaseModel)

_FORBID = ConfigDict(extra="forbid")
# The document roots. pydantic honours hide_input_in_errors on the outermost
# model of a validation, so the flag on a root covers every nested section:
# a rejected value, a secret included, never appears as input_value=... in
# the error the loader chains its own message to (#352, #350).
_ROOT = ConfigDict(extra="forbid", hide_input_in_errors=True)

# Accepted values of the top-level ``config_validation`` key (#175 piece 4).
VALIDATION_MODES = ("warn", "strict")


class ServerSection(BaseModel):
    model_config = _FORBID

    host: str = "127.0.0.1"
    port: int = 8000
    debug: bool = False
    # Rate limiting on /token (#304): configurable from YAML at last - the
    # Settings fields existed since early versions but no document section
    # carried them, so only the stricter-dev profile could ever flip them.
    rate_limit_enabled: bool = False
    rate_limit_token_endpoint: str = "10/minute"


class ClientEntry(BaseModel):
    """One ``oauth.clients[]`` entry. ``additional_audiences`` and
    ``redirect_uris`` stay ``Any`` here because the loader accepts a scalar
    string as a one-element list and reports unsupported shapes with a
    client-scoped message (#35); that coercion runs in ``to_client()``."""

    model_config = _FORBID

    client_id: str = ""
    client_secret: str = ""
    # A closed enum so the generated config schema advertises the three
    # values, and an invalid one fails at document-model load with a field
    # path (#188 / #254 review) rather than only in to_client().
    token_endpoint_auth_method: Literal[
        "client_secret_basic", "client_secret_post", "none"
    ] = "client_secret_basic"
    # Same closed-enum reasoning as token_endpoint_auth_method above (#249).
    layout: Literal["vertical", "horizontal"] = "vertical"
    description: str = ""
    background_color: Optional[str] = None
    header_color: Optional[str] = None
    footer_color: Optional[str] = None
    show_client_id: bool = True
    show_description: bool = False
    additional_audiences: Any = None
    redirect_uris: Any = None
    allowed_scopes: Any = None
    allowed_resources: Any = None

    def to_client(self) -> OAuthClient:
        return OAuthClient(
            client_id=self.client_id,
            # Absent/empty in YAML becomes None: valid for a public client
            # ('none'), rejected by the model for a confidential one (#188).
            client_secret=self.client_secret or None,
            token_endpoint_auth_method=self.token_endpoint_auth_method,
            layout=self.layout,
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
            allowed_scopes=_coerce_client_str_list(
                self.allowed_scopes, self.client_id, "allowed_scopes"
            ),
            allowed_resources=_coerce_client_str_list(
                self.allowed_resources, self.client_id, "allowed_resources"
            ),
        )


class DeviceFlowSection(BaseModel):
    """``device_flow``: the timing of the device authorization grant (#441).

    The defaults are the values that were hardcoded while this section was
    accepted and ignored."""

    model_config = _FORBID

    code_expiry_seconds: int = 600
    polling_interval: int = 5


class DynamicRegistrationSection(BaseModel):
    """``oauth.dynamic_registration`` (#190).

    Deliberately not in ``serialization.OWNED_SETTINGS``: the settings form
    and the MCP ``update_settings`` tool do not offer it. Opening an
    unauthenticated mutation endpoint on an instance that may be reachable
    from a network is a decision for the file, not for a form. Not being on
    that table means "not managed by those surfaces", never "dropped by the
    next save": ``apply_settings_document`` mutates the parsed document and
    leaves every key it does not own alone.
    """

    model_config = _FORBID

    enabled: bool = False
    max_clients: int = Field(default=100, ge=1, le=10000)


class ClientIdMetadataDocumentsSection(BaseModel):
    """``oauth.client_id_metadata_documents`` (#196).

    Off by default and, like ``dynamic_registration``, deliberately not in
    ``serialization.OWNED_SETTINGS``: turning on an outbound fetch driven by
    a client-supplied URL is a decision for the file, not for the settings
    form or the MCP update_settings tool.
    """

    model_config = _FORBID

    enabled: bool = False
    # Empty means nothing is fetched: an operator names the hosts. Exact
    # DNS names, no wildcards - a wildcard turns a list of hosts into a
    # list of zones, which is rarely what the person writing it meant.
    allowed_hosts: List[str] = Field(default_factory=list)
    # The draft's development exception, no wider: loopback only, and only
    # when this server is itself on loopback.
    allow_loopback: bool = False


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
    # Absent = the DEFAULT_SCOPES_SUPPORTED vocabulary (#186); None here (not
    # a default_factory of the tuple) so to_settings() can tell "declared
    # empty list" from "not declared" the same way issuer_allowlist does.
    scopes_supported: Optional[List[str]] = None
    scope_enforcement: bool = True
    logos_dir: Optional[str] = None
    dynamic_registration: DynamicRegistrationSection = Field(
        default_factory=DynamicRegistrationSection
    )
    client_id_metadata_documents: ClientIdMetadataDocumentsSection = Field(
        default_factory=ClientIdMetadataDocumentsSection
    )
    # Refresh tokens lived 7 days, hardcoded, while this key was accepted
    # and ignored (#441); the default keeps those 7 days.
    refresh_token_expiry_minutes: int = 10080


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
    # Closed set (#297), blank still meaning the default - the same
    # before-validator the domain model runs, so an unset ${VAR} keeps
    # loading here too.
    c14n_algorithm: SamlC14nAlgorithm = SAML_C14N_DEFAULT
    want_authn_requests_signed: bool = False
    sp_certificates: Optional[List[str]] = None
    strict_binding: bool = False

    @field_validator("c14n_algorithm", mode="before")
    @classmethod
    def _normalize_c14n_algorithm(cls, v: Any) -> Any:
        return normalize_saml_c14n_algorithm(v)


class ExternalKeysSection(BaseModel):
    """Operator-provided RSA signing keys (#358): both PEM paths together, or
    no ``external_keys`` block at all."""

    model_config = _FORBID

    private_key: str = Field(min_length=1)
    public_key: str = Field(min_length=1)
    # Omitted: the key id is the RFC 7638 thumbprint of the public key.
    kid: Optional[str] = Field(default=None, min_length=1)


class JwtSection(BaseModel):
    model_config = _FORBID

    algorithm: str = "RS256"
    keys_dir: str = "./keys"
    external_keys: Optional[ExternalKeysSection] = None
    # Same bounds as Settings.max_previous_keys.
    max_previous_keys: int = Field(default=2, ge=0, le=10)


class RuntimeSection(BaseModel):
    """Where runtime state is kept (#354). Read at activation, and a change
    needs a restart: never written by the settings form or MCP.

    ``path`` is the SQLite store's file, relative to the configuration
    directory (the identity of a store several processes share must not
    depend on where each was started), or absolute. Required with ``sqlite``
    and refused with ``memory``: a document carries no setting that does
    nothing."""

    model_config = _FORBID

    store: RuntimeStoreKind = "memory"
    path: Optional[str] = None

    @model_validator(mode="after")
    def _a_path_for_the_store_that_has_one(self) -> "RuntimeSection":
        if self.store == "sqlite":
            if self.path is None or not self.path.strip():
                raise ValueError("runtime.path is required with runtime.store: sqlite, and may not be empty")
            if self.path.strip().startswith("~"):
                # What ~ is depends on each process's HOME, and so would the
                # store: the identity of a shared store must not.
                raise ValueError(
                    "runtime.path may not start with ~: it would name a file of each process's HOME; "
                    "give it relative to the configuration directory, or absolute"
                )
        elif "path" in self.model_fields_set:
            # Present at all, null included: a setting that does nothing.
            raise ValueError(f"runtime.path is for runtime.store: sqlite, not {self.store}")
        return self


class SessionSection(BaseModel):
    model_config = _FORBID

    secret_key: str = "dev-secret-key-change-in-production"
    require_ui_login: bool = False
    enforce_password_check: bool = False
    # Absent -> fall back to the env vars in to_settings() (#163); present,
    # even as null/empty, means the operator deliberately said "off" and the
    # env vars are not consulted. See "management_secret" in models.py.
    management_secret: Optional[str] = None


class LoggingSection(BaseModel):
    model_config = _FORBID

    level: str = "INFO"
    log_token_requests: bool = True
    log_saml_requests: bool = True
    verbose_logging: bool = True


class LoginSection(BaseModel):
    model_config = _FORBID

    mode: LoginMode = "password"
    auto_login: bool = False
    two_step: bool = False
    totp: bool = False


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



_SECTIONS = (
    "server", "oauth", "saml", "jwt", "session", "logging", "login", "runtime", "device_flow",
)


class SettingsDocument(BaseModel):
    """Top-level shape of ``settings.yaml``."""

    model_config = _ROOT

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
    runtime: RuntimeSection = Field(default_factory=RuntimeSection)
    device_flow: DeviceFlowSection = Field(default_factory=DeviceFlowSection)
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
    # Absent = the security profile decides, as it always did: every origin
    # under dev and oauth21, localhost under stricter-dev. None here, not a
    # default list, so "not declared" stays distinguishable from a declared
    # list, the empty one included (#441).
    cors_allowed_origins: Optional[List[str]] = None
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
            rate_limit_enabled=self.server.rate_limit_enabled,
            rate_limit_token_endpoint=self.server.rate_limit_token_endpoint,
            issuer=self.oauth.issuer,
            issuer_from_request=self.oauth.issuer_from_request,
            issuer_allowlist=self.oauth.issuer_allowlist or [],
            device_verification_base_url=self.oauth.device_verification_base_url,
            issuer_from_proxy_headers=self.oauth.issuer_from_proxy_headers,
            audience=self.oauth.audience,
            token_expiry_minutes=self.oauth.token_expiry_minutes,
            refresh_token_expiry_minutes=self.oauth.refresh_token_expiry_minutes,
            refresh_token_rotation=self.oauth.refresh_token_rotation,
            require_pkce=self.oauth.require_pkce,
            clients=clients,
            scopes_supported=(
                self.oauth.scopes_supported
                if self.oauth.scopes_supported is not None
                else list(DEFAULT_SCOPES_SUPPORTED)
            ),
            scope_enforcement=self.oauth.scope_enforcement,
            client_id_metadata_documents_enabled=(
                self.oauth.client_id_metadata_documents.enabled
            ),
            client_id_metadata_documents_allowed_hosts=(
                self.oauth.client_id_metadata_documents.allowed_hosts
            ),
            client_id_metadata_documents_allow_loopback=(
                self.oauth.client_id_metadata_documents.allow_loopback
            ),
            dynamic_registration_enabled=self.oauth.dynamic_registration.enabled,
            dynamic_registration_max_clients=self.oauth.dynamic_registration.max_clients,
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
            external_private_key=(
                self.jwt.external_keys.private_key if self.jwt.external_keys else None
            ),
            external_public_key=(
                self.jwt.external_keys.public_key if self.jwt.external_keys else None
            ),
            external_key_id=self.jwt.external_keys.kid if self.jwt.external_keys else None,
            max_previous_keys=self.jwt.max_previous_keys,
            runtime_store=self.runtime.store,
            runtime_path=self.runtime.path,
            login_mode=self.login.mode,
            auto_login=self.login.auto_login,
            two_step=self.login.two_step,
            totp=self.login.totp,
            security_profile=self.security_profile,
            cors_allowed_origins=self.cors_allowed_origins,
            device_code_expiry_seconds=self.device_flow.code_expiry_seconds,
            device_polling_interval=self.device_flow.polling_interval,
            authority_prefixes=self.authority_prefixes,
            allowed_identity_classes=self.allowed_identity_classes,
            secret_key=self.session.secret_key,
            require_ui_login=self.session.require_ui_login,
            enforce_password_check=self.session.enforce_password_check,
            # An explicit key in settings.yaml's session: block wins over the
            # env vars even when its value is empty/null - presence in YAML
            # is the operator deliberately stating "off", distinct from the
            # key being absent (#163 review). Absent the key, fall back to
            # NANOIDP_MANAGEMENT_SECRET, then the legacy
            # NANOIDP_MCP_ADMIN_SECRET alias.
            management_secret=(
                (self.session.management_secret or None)
                if "management_secret" in self.session.model_fields_set
                else (
                    os.getenv("NANOIDP_MANAGEMENT_SECRET")
                    or os.getenv("NANOIDP_MCP_ADMIN_SECRET")
                    or None
                )
            ),
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

    model_config = _ROOT

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
    {"password", "description", "email", "identity_class", "entitlements", "roles", "groups",
     "tenant", "source_acl", "attributes", "totp_secret"}
)


class UserEntry(BaseModel):
    """One ``users.<name>`` mapping. Defaults mirror the old loader: a
    missing ``password`` is ``None`` (persona-only user), ``roles`` default
    to ``["USER"]``, ``email`` to ``<username>@example.org`` (filled in by
    ``to_user`` because it needs the key)."""

    # Inside UsersDocument the _ROOT flag is the one pydantic applies; the
    # entry keeps its own as defense in depth, so validating an entry on its
    # own (UserEntry.model_validate) cannot echo a password or a
    # totp_secret either (#352, #350).
    model_config = ConfigDict(extra="allow", hide_input_in_errors=True)

    # Missing -> default, explicit null -> validation error, exactly like the
    # old ``user_data.get(key, default)`` followed by the domain model's
    # validators (#197 review). ``password`` and ``identity_class`` are the
    # two fields whose domain type is Optional, so null is valid there.
    password: Optional[str] = None
    description: str = ""
    email: Optional[str] = None
    identity_class: Optional[str] = None
    entitlements: List[str] = Field(default_factory=list)
    roles: List[str] = Field(default_factory=lambda: ["USER"])
    groups: List[str] = Field(default_factory=list)
    tenant: str = "default"
    source_acl: List[str] = Field(default_factory=list)
    attributes: Dict[str, Any] = Field(default_factory=dict)
    totp_secret: Optional[str] = None

    def to_user(self, username: str) -> User:
        attributes: Dict[str, Any] = dict(self.attributes)
        # Any field not in the known set becomes an attribute (legacy files).
        for key, value in (self.model_extra or {}).items():
            if key not in _USER_KNOWN_FIELDS and key not in attributes:
                attributes[key] = value
        return User(
            username=username,
            password=self.password,
            description=self.description,
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
            totp_secret=self.totp_secret,
        )


class UsersDocument(BaseModel):
    """Top-level shape of ``users.yaml``."""

    model_config = _ROOT

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


class EntryInvalid(ValueError):
    """An entry given to parse_user_entry/parse_client_entry does not
    validate. ``message`` is the text built here from the model's own
    finding, the only part a caller may show: the exception itself carries
    the library error as its cause."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def _entry_error(source: str, document_prefix: str, exc: ValueError) -> ValueError:
    """One line naming the source and the entry's own field, for an entry
    validated inside a whole document: a loader message loses the document
    path (``users.<name>.`` / ``oauth.clients[0].``), a domain-model
    ValidationError keeps only its first message."""
    if isinstance(exc, ValidationError):
        first = exc.errors()[0]
        field = _dotted(first["loc"])
        message = first["msg"].removeprefix("Value error, ")
        return EntryInvalid(f"{source}: {field + ': ' if field else ''}{message}")
    return EntryInvalid(str(exc).replace(document_prefix, ""))


def parse_user_entry(username: str, data: Any, source: str) -> User:
    """One user from a mapping shaped like a ``users.yaml`` entry (#192): the
    same model, defaults and rules as a declared user, for a user created at
    runtime. ``source`` names where the data came from in the error."""
    if not isinstance(data, Mapping):
        raise EntryInvalid(f"{source}: expected a JSON object")
    try:
        document = _load_document(
            UsersDocument, {"users": {username: dict(data)}}, Path(source), strict=True
        )
        return document.to_users()[0][username]
    except ValueError as exc:
        raise _entry_error(source, f"users.{username}.", exc) from None


def parse_client_entry(data: Any, source: str) -> OAuthClient:
    """One client from a mapping shaped like an ``oauth.clients[]`` entry
    (#192): the same model, coercions and rules as a declared client."""
    if not isinstance(data, Mapping):
        raise EntryInvalid(f"{source}: expected a JSON object")
    try:
        document = _load_document(
            SettingsDocument, {"oauth": {"clients": [dict(data)]}}, Path(source), strict=True
        )
        return document.to_settings().clients[0]
    except ValueError as exc:
        raise _entry_error(source, "oauth.clients[0].", exc) from None


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


def _declared_strictness(documents: Sequence[Tuple[Path, Dict[str, Any]]]) -> bool:
    """The validation mode this directory declares, for every file in it.

    One contract per directory, the way a load reads it: settings.yaml
    decides and users.yaml follows. Read from the raw document, before the
    placeholders are expanded, because that is where the loader reads it -
    ``config_validation: ${VAR}`` is a literal there, not the variable's
    value, and the check must not be stricter than the load it predicts.

    A batch with no settings document cannot change what settings.yaml
    declares, and strictness only governs unknown keys, which these writers
    do not introduce; such a batch is checked the permissive way rather
    than reading a file this function was not handed.
    """
    for file_path, document in documents:
        if file_path.name != "users.yaml":
            return declared_validation_mode(document) == "strict"
    return False


def _reject_disagreeing_versions(
    documents: Sequence[Tuple[Path, Dict[str, Any]]]
) -> None:
    """``config_version``, in the loader's own order and with its own rule.

    The document models do not own this one: ``SettingsDocument`` says so
    where it declares the field, because the check runs on the raw mapping
    before ``${VAR}`` expansion and before the model is built, so a
    ``config_version: 999`` would pass every model and be refused by the
    next load.

    The second half is the directory's invariant rather than a file's: both
    files declare the same number. It can only be checked when both are in
    the batch, which is where it matters - ``ConfigManager.save()`` and the
    wizard write both. A single-file writer is not sent to read the other
    file: that is the snapshot question #246 owns, and reading it here
    would answer it wrongly.
    """
    versions: Dict[str, int] = {}
    for file_path, document in documents:
        try:
            versions[file_path.name] = check_config_version(document, file_path)
        except ValueError as exc:
            raise DocumentRejected(
                f"the change would leave {file_path.name} unloadable: "
                f"{_first_finding(file_path, exc)}"
            ) from exc
    settings_version = versions.get("settings.yaml")
    users_version = versions.get("users.yaml")
    if settings_version is not None and users_version is not None:
        if settings_version != users_version:
            raise DocumentRejected(
                f"the change would leave the configuration directory unloadable: "
                f"users.yaml declares config_version {users_version} and "
                f"settings.yaml declares {settings_version}; one directory "
                f"follows one contract version"
            )


def _first_finding(file_path: Path, exc: ValueError) -> str:
    """One line from a model's complaint, the way ``_entry_error`` reads one.

    A ``ValidationError`` prints several lines and a link to pydantic's
    documentation, which is not what a settings page should show. A loader
    ``ValueError`` already names the file, with the absolute path the server
    was started with: the caller has been told the file name once already
    and has no use for the server's directory layout. The value never
    appears either way: ``Settings`` sets ``hide_input_in_errors`` (#352).
    """
    if isinstance(exc, ValidationError):
        first = exc.errors()[0]
        field = _dotted(first["loc"])
        message = first["msg"].removeprefix("Value error, ")
        return f"{field + ': ' if field else ''}{message}"
    return str(exc).replace(f"{file_path}: ", "")


class DocumentRejected(ValueError):
    """A document a writer composed would not load, so it is not written.

    A refusal, not a failure: like ``ConflictError`` it is raised before
    anything reaches disk, and unlike ``ConfigurationRejected`` it never
    means "the file is written and the reload failed". Callers that tell
    those apart (``/api/runtime``, #192) must keep telling them apart.

    ``message`` is the text a caller may show: the model's own finding, with
    the file and the path to the offending key, and no value in it.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def reject_unloadable(documents: Sequence[Tuple[Path, Dict[str, Any]]]) -> None:
    """Refuse a write whose result the next load would not accept (#366).

    The write primitive replaces the file and only then reloads, so a
    document that the models refuse used to reach disk and leave a
    settings.yaml no process could start from: a blank ``oauth.issuer``,
    ``oauth.audience`` or ``server.rate_limit_token_endpoint`` is written as
    ``""``, which those fields reject. The same parse the loader runs,
    run one step earlier, turns that into a refusal with nothing written.

    ``${VAR}`` placeholders are expanded into a **copy** first, exactly as
    ``ConfigManager._stage_directory`` does, because that is the value the
    models will see; the document written keeps its placeholders. What this
    therefore answers is "would this file load in this environment", which
    is the question that matters and the only one available here.

    Strictness comes from the document's own ``config_validation``, the way
    a fresh process would read it. A running process whose CLI raised
    strictness beyond the file's can still refuse its own write afterwards,
    in the reload it already does - no worse than before, and not something
    this can see.
    """
    strict = _declared_strictness(documents)
    _reject_disagreeing_versions(documents)
    for file_path, document in documents:
        expanded = expand_env_vars(dict(document))
        try:
            if file_path.name == "users.yaml":
                load_users_document(expanded, file_path, strict=strict).to_users()
            else:
                load_settings_document(expanded, file_path, strict=strict).to_settings()
        except (ValueError, ValidationError) as exc:
            raise DocumentRejected(
                f"the change would leave {file_path.name} unloadable: "
                f"{_first_finding(file_path, exc)}"
            ) from exc
