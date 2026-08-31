"""
YAML configuration writer service.
Provides atomic write operations for YAML configuration files.
"""

import logging
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ..config import OAuthClient, Settings, User, get_config
from ..config_documents import document_defaults
from ..config_writer import compare_and_replace
from ..hooks import HookError
from ..serialization import (
    OWNED_SETTINGS,
    client_id_matches,
    client_to_yaml,
    is_unchanged,
    load_yaml_document,
    merge_client_entry,
    merge_optional_nested_field,
    user_to_yaml,
)

logger = logging.getLogger(__name__)


def _mutate_settings_section(
    document: Dict[str, Any], section_name: str, provided: Dict[str, Any]
) -> None:
    """Apply form-provided values for one settings.yaml section to an
    already-loaded document (#214; extracted from
    ``YamlWriter._apply_provided_settings`` in #229 phase 4 review,
    blocking 1, so several sections can be composed under one
    ``compare_and_replace`` call instead of each running its own).

    The per-field encoding comes from ``serialization.OWNED_SETTINGS``, the
    same table ``apply_settings_document`` drives from - one row per owned
    key instead of one hand-written if-block per field. Semantics per
    value: ``None`` was not on the form and leaves the file alone (#131);
    for a non-"plain" row a provided-but-falsy value clears the key
    (absent = default/derived); everything else is written only when
    the expanded on-disk value actually differs (#127), so untouched
    ``${VAR}`` placeholders and comments survive.
    """
    section = document.setdefault(section_name, {})
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


def _mutate_allowed_identity_classes(document: Dict[str, Any], classes: List[str]) -> None:
    """Extracted from ``YamlWriter.update_allowed_identity_classes`` (#229
    phase 4 review, blocking 1) for the same composition reason as
    ``_mutate_settings_section`` above."""
    if not is_unchanged(document.get("allowed_identity_classes"), classes):
        document["allowed_identity_classes"] = classes


def _mutate_login_mode(document: Dict[str, Any], mode: str, login_mode_default: str) -> None:
    """Extracted from ``YamlWriter.update_login_settings`` (#229 phase 4
    review, blocking 1); ``mode`` here is already known truthy and
    already validated by the caller - see that method's docstring for
    why validation happens before any write is even attempted."""
    merge_optional_nested_field(document, "login", "mode", mode, login_mode_default)


def _mutate_auto_login(document: Dict[str, Any], auto_login: bool, auto_login_default: bool) -> None:
    """``auto_login`` here is already known to be an explicit True/False
    from the caller, not None (#250: None means "absent from the form,
    leave unchanged", the same convention ``_mutate_login_mode`` follows
    for its own field)."""
    merge_optional_nested_field(document, "login", "auto_login", auto_login, auto_login_default)


def _login_settings_defaults() -> tuple[str, bool]:
    """``(login.mode default, login.auto_login default)`` from one
    ``document_defaults()`` call, shared by ``update_login_settings`` and
    ``update_settings_form`` instead of each rebuilding a full
    ``SettingsDocument`` twice for the same two values."""
    defaults = document_defaults()
    return defaults["login.mode"], defaults["login.auto_login"]


class YamlWriter:
    """Service for safely writing YAML configuration files."""

    def __init__(self, config_dir: Optional[str] = None) -> None:
        config = get_config()
        self.config_dir = Path(config_dir or config.config_dir)
        self.users_file = self.config_dir / "users.yaml"
        self.settings_file = self.config_dir / "settings.yaml"

    def _atomic_write(
        self,
        file_path: Path,
        mutate: Callable[[Dict[str, Any]], Any],
        expected_revision: Optional[str] = None,
    ) -> str:
        """Write via the shared compare-and-replace primitive (#229 phase 3),
        then run the single post-write contract (#185):

            check -> load -> mutate -> replace -> notify the mirror
            (on_config_saved) -> refresh the runtime FROM LOCAL DISK ->
            propagate a mirror failure if strict.

        ``mutate`` receives the freshly loaded document and edits it in
        place (``compare_and_replace``'s own contract) - every caller's
        existence/not-found check now happens *inside* ``mutate`` rather
        than on a document loaded beforehand, so it runs against the
        same document that gets written, under the same lock, instead of
        racing a concurrent writer between an earlier check and this
        write (the #229 the whole primitive exists to close).
        ``expected_revision`` (default ``None``, unconditional - today's
        last-write-wins) is a stale-precondition check: a mismatch
        raises ``ConflictError`` before the file is even loaded, let
        alone mutated.

        The refresh is ConfigManager.reload_local(), never reload(): a
        reload() would run on_before_load and could pull a stale or
        failed-to-update mirror back over the file just written, turning a
        mirror hiccup into a silent rollback (#185 review). The disk is the
        newest state after our own write; only an explicit reload consults
        the mirror.

        Returns the file's new revision (#229 phase 4): the settings
        page writes settings.yaml several times in one request, and each
        write after the first must check against the revision the
        *previous write in this same request* just produced, not the
        stale one the page was rendered with - otherwise every write
        after the first would always look conflicted.
        """
        new_revision = compare_and_replace(file_path, expected_revision, mutate)
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
        return new_revision

    def _load_settings_yaml(self) -> Dict[str, Any]:
        """Load the current settings.yaml content."""
        return load_yaml_document(self.settings_file)

    # ==================== User Operations ====================

    def save_user(
        self, user: User, is_new: bool = False, expected_revision: Optional[str] = None
    ) -> str:
        """
        Save or update a user in users.yaml.

        Args:
            user: The User object to save
            is_new: If True, will fail if user already exists
            expected_revision: #229 phase 3 - optional stale-write guard,
                unused by any caller yet
        """

        def mutate(data: Dict[str, Any]) -> None:
            # Match _load_users_yaml's old skeleton exactly (#229 phase 3
            # review, blocking 1): only a users.yaml that does not exist
            # at all gets {"users": {}, "default_user": "admin"} - an
            # existing file (even an empty one, or one simply missing the
            # key) must not gain a default_user it never had. Checked
            # here, inside mutate, because the lock is already held by
            # the time compare_and_replace calls this, so "does the file
            # exist" is accurate for the same load this mutation applies to.
            if not self.users_file.exists():
                data["users"] = {}
                data["default_user"] = "admin"
            data.setdefault("users", {})
            if is_new and user.username in data["users"]:
                raise ValueError(f"User '{user.username}' already exists")
            data["users"][user.username] = user_to_yaml(user)

        return self._atomic_write(self.users_file, mutate, expected_revision)

    def delete_user(self, username: str, expected_revision: Optional[str] = None) -> str:
        """
        Delete a user from users.yaml.

        Args:
            username: The username to delete
            expected_revision: #229 phase 3 - optional stale-write guard,
                unused by any caller yet
        """

        def mutate(data: Dict[str, Any]) -> None:
            # Same missing-vs-existing distinction as save_user's mutate
            # above (#229 phase 3 review, blocking 1).
            if not self.users_file.exists():
                data["users"] = {}
                data["default_user"] = "admin"
            data.setdefault("users", {})
            if username not in data["users"]:
                raise ValueError(f"User '{username}' not found")
            del data["users"][username]

            # If deleted user was the default, update default_user
            if data.get("default_user") == username:
                remaining_users = list(data["users"].keys())
                data["default_user"] = remaining_users[0] if remaining_users else ""

        return self._atomic_write(self.users_file, mutate, expected_revision)

    def set_default_user(self, username: str, expected_revision: Optional[str] = None) -> str:
        """Set the default user for client_credentials grant."""

        def mutate(data: Dict[str, Any]) -> None:
            data.setdefault("users", {})
            if username not in data["users"]:
                raise ValueError(f"User '{username}' not found")
            data["default_user"] = username

        return self._atomic_write(self.users_file, mutate, expected_revision)

    # ==================== OAuth Client Operations ====================

    def save_client(
        self, client: OAuthClient, is_new: bool = False, expected_revision: Optional[str] = None
    ) -> str:
        """
        Save or update an OAuth client in settings.yaml.

        Args:
            client: The OAuthClient object to save
            is_new: If True, will fail if client already exists
            expected_revision: #229 phase 3 - optional stale-write guard,
                unused by any caller yet
        """

        def mutate(data: Dict[str, Any]) -> None:
            clients = data.setdefault("oauth", {}).setdefault("clients", [])

            # Check if client exists. Match through client_id_matches so a
            # raw ${CLIENT_ID:...} placeholder entry is recognised as the
            # same client instead of being appended as a duplicate (#127).
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

        return self._atomic_write(self.settings_file, mutate, expected_revision)

    def delete_client(self, client_id: str, expected_revision: Optional[str] = None) -> str:
        """Delete an OAuth client from settings.yaml."""

        def mutate(data: Dict[str, Any]) -> None:
            clients = data.get("oauth", {}).get("clients", [])
            # Match through client_id_matches so a client whose id is an
            # env placeholder can still be deleted (#127).
            new_clients = [c for c in clients if not client_id_matches(c, client_id)]

            if len(new_clients) == len(clients):
                raise ValueError(f"Client '{client_id}' not found")

            data["oauth"]["clients"] = new_clients

        return self._atomic_write(self.settings_file, mutate, expected_revision)

    # ==================== Settings Operations ====================

    def _apply_provided_settings(
        self,
        section_name: str,
        provided: "Dict[str, Any]",
        expected_revision: Optional[str] = None,
    ) -> str:
        """Apply form-provided values for one settings.yaml section (#214)
        as a standalone write. See ``_mutate_settings_section`` for the
        actual per-field logic; ``update_settings_form`` below is the
        composed, single-write version several sections need together.
        """
        return self._atomic_write(
            self.settings_file,
            lambda data: _mutate_settings_section(data, section_name, provided),
            expected_revision,
        )

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
        expected_revision: Optional[str] = None,
    ) -> str:
        """Update OAuth settings (per-field encodings: OWNED_SETTINGS, #214).

        Skips writing a field whose expanded on-disk value already matches
        what's being submitted, so unchanged ``${VAR}`` placeholders and
        comments survive a form save that only changed other fields (#127).
        """
        return self._apply_provided_settings(
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
            expected_revision,
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
        expected_revision: Optional[str] = None,
    ) -> str:
        """Update SAML settings (same #127 guard; encodings: OWNED_SETTINGS).

        Blank clears entity_id/sso_url: absent = derived from the effective
        issuer (#181), the same "present-but-blank = clear" contract as #131.
        """
        return self._apply_provided_settings(
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
            expected_revision,
        )

    def update_authority_prefixes(
        self, prefixes: Dict[str, str], expected_revision: Optional[str] = None
    ) -> str:
        """Update authority prefix mappings."""

        def mutate(data: Dict[str, Any]) -> None:
            if not is_unchanged(data.get("authority_prefixes"), prefixes):
                data["authority_prefixes"] = prefixes

        return self._atomic_write(self.settings_file, mutate, expected_revision)

    def update_allowed_identity_classes(
        self, classes: List[str], expected_revision: Optional[str] = None
    ) -> str:
        """Update allowed identity classes."""
        return self._atomic_write(
            self.settings_file,
            lambda data: _mutate_allowed_identity_classes(data, classes),
            expected_revision,
        )

    def update_login_settings(
        self,
        mode: Optional[str] = None,
        auto_login: Optional[bool] = None,
        expected_revision: Optional[str] = None,
    ) -> str:
        """Update the 'login' section (persona login mode, local dev
        convenience). 'password' is the default and is never persisted -
        the 'login' section is omitted entirely at the default, same as
        'security_profile' at 'dev' (#83/#87 read-modify-write conventions).

        Unlike other text fields' "absent = unchanged, blank = clear"
        convention (#131), there is no sensible "cleared" login mode, so a
        blank value is treated the same as absent: left unchanged, not
        written to disk. A present, non-blank value is validated against
        the same `{"password", "persona"}` set as ``Settings.login_mode``
        *before* anything is written - including before the file is even
        loaded - so an invalid value (e.g. a typo) raises instead of
        persisting a mode the server can't start with.

        ``auto_login`` (#250) follows the checkbox convention instead:
        ``None`` means absent from the form (unchanged), an explicit
        ``True``/``False`` is written, omitted at its ``False`` default.
        No cross-field validation against ``mode`` here - see
        ``Settings.auto_login_enabled`` for why it is simply inert rather
        than rejected when ``login.mode`` isn't ``persona``.
        """
        if mode:
            Settings.validate_login_mode(mode)
        login_mode_default, auto_login_default = _login_settings_defaults()

        def mutate(data: Dict[str, Any]) -> None:
            if mode:
                _mutate_login_mode(data, mode, login_mode_default)
            if auto_login is not None:
                _mutate_auto_login(data, auto_login, auto_login_default)

        return self._atomic_write(self.settings_file, mutate, expected_revision)

    def update_settings_form(
        self,
        oauth_fields: Dict[str, Any],
        saml_fields: Dict[str, Any],
        allowed_identity_classes: Optional[List[str]] = None,
        login_mode: Optional[str] = None,
        auto_login: Optional[bool] = None,
        expected_revision: Optional[str] = None,
    ) -> str:
        """Apply the settings page's whole submission as ONE write (#229
        phase 4 review, blocking 1).

        The page originally called update_oauth_settings/
        update_saml_settings/update_allowed_identity_classes/
        update_login_settings in sequence - four separate
        compare_and_replace calls on the same file. Chaining each
        write's resulting revision into the next one's precondition
        made every individual write conflict-safe, but a conflict on
        write N still left writes 1..N-1 already committed, their
        on_config_saved hooks already fired and the runtime already
        reloaded - reproduced live (#248 review) with a hook that
        rewrites settings.yaml after every save: one submission with
        four changed fields landed only the first, the flash said
        "please reload and try again" for a page that had, in fact,
        already partly landed. That is the "save() can fail after
        committing" shape phase 2 closed for ConfigManager.save() by
        checking every precondition before writing anything - this is
        the same fix, one file instead of two.

        Composing every section's mutation under one compare_and_replace
        call means expected_revision covers the entire submission: a
        conflict here is all-or-nothing, exactly like a single-section
        write already was, and on_config_saved/reload_local each run
        once per settings save instead of up to four times.

        login_mode is validated before this call ever touches the file,
        same as update_login_settings above and for the same reason: an
        invalid value must never reach the file at all. ``auto_login``
        (#250) follows the checkbox convention (``None`` = unchanged) -
        see ``update_login_settings`` above.
        """
        if login_mode:
            Settings.validate_login_mode(login_mode)
        login_mode_default, auto_login_default = _login_settings_defaults()

        def mutate(data: Dict[str, Any]) -> None:
            _mutate_settings_section(data, "oauth", oauth_fields)
            _mutate_settings_section(data, "saml", saml_fields)
            if allowed_identity_classes:
                _mutate_allowed_identity_classes(data, allowed_identity_classes)
            if login_mode:
                _mutate_login_mode(data, login_mode, login_mode_default)
            if auto_login is not None:
                _mutate_auto_login(data, auto_login, auto_login_default)

        return self._atomic_write(self.settings_file, mutate, expected_revision)


# Global instance
_yaml_writer: Optional[YamlWriter] = None


def get_yaml_writer() -> YamlWriter:
    """Get or create the global YAML writer instance."""
    global _yaml_writer
    if _yaml_writer is None:
        _yaml_writer = YamlWriter()
    return _yaml_writer
