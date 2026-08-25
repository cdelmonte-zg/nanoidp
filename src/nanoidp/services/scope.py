"""
Per-client scope validation and invalid_scope rejection (issue #186).

/authorize, every /token grant, and /device_authorization all ask the same
question of a requested ``scope`` string: is every token in it something
this client may have? This module answers that once so those call sites in
``routes/oauth.py`` cannot drift on what ``invalid_scope`` means (RFC 6749
§4.1.2.1 for the authorization endpoint, §5.2 for the token endpoint).

Enforcement is opt-out (``Settings.scope_enforcement_active``, dev profile
only, #186): off restores exactly the pre-#186 behavior - any scope string
is accepted unchecked, and a client's ``allowed_scopes`` is not even
consulted for defaulting, only the endpoint's own historical default (if
any) applies.
"""

from dataclasses import dataclass
from typing import Iterable, Optional

from ..models import OAuthClient


@dataclass
class ScopeResult:
    """The outcome of validating a requested scope against a client.

    ``granted`` is the scope string to actually issue (already resolved from
    an omitted request); ``error_description`` is set, and ``granted`` is
    None, exactly when the request must be rejected as invalid_scope.
    """

    granted: Optional[str]
    error_description: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error_description is None


def resolve_scope(
    requested: Optional[str],
    client: OAuthClient,
    vocabulary: Iterable[str],
    enforcement_active: bool,
    *,
    default_when_omitted: Optional[str] = None,
    validate_only: bool = False,
) -> ScopeResult:
    """Validate (and, at a request surface, default) one scope string.

    - Enforcement off: ``requested`` (or ``default_when_omitted`` if it was
      omitted and ``validate_only`` is not set) passes through untouched - no
      vocabulary check, no per-client check, and ``client.allowed_scopes`` is
      not consulted at all, so a client's allow-list has no effect while
      enforcement is off.
    - Enforcement on, omitted (falsy ``requested``), ``validate_only=False``
      (the default - use at a request surface: /authorize,
      /device_authorization, and the password/client_credentials grants): a
      client with a non-empty ``allowed_scopes`` defaults to its full allowed
      set (space joined); an unrestricted client falls back to
      ``default_when_omitted``, same as when enforcement is off.
    - Enforcement on, omitted, ``validate_only=True`` (use at a RE-check of an
      already-granted scope: the refresh grant and authorization_code
      redemption): omitted stays omitted, unchecked and undefaulted. A grant
      minted with no scope at all - a legacy refresh token predating this
      setting, or one issued before ``allowed_scopes`` was set - has nothing
      to validate and must not have one manufactured for it; defaulting an
      absent *original* scope to the client's current full allowed set would
      let a refresh silently GRANT MORE than the original authorization ever
      did (#186 review, B1) - the opposite of the narrowing this grant is
      supposed to enforce.
    - Present (either mode): every space-separated token must be in
      ``vocabulary`` - a scope outside the global vocabulary is
      ``invalid_scope`` for every client, the "small behaviour change" #186
      calls out - and, when ``client.allowed_scopes`` is non-empty, every
      token must ALSO be in it.
    """
    if not enforcement_active:
        return ScopeResult(granted=requested if validate_only else requested or default_when_omitted)

    if validate_only:
        effective = requested
    else:
        effective = requested or (
            " ".join(client.allowed_scopes) if client.allowed_scopes else default_when_omitted
        )
    if not effective:
        return ScopeResult(granted=effective)

    tokens = effective.split()
    vocabulary_set = set(vocabulary)
    outside_vocabulary = sorted({t for t in tokens if t not in vocabulary_set})
    if outside_vocabulary:
        return ScopeResult(
            granted=None,
            error_description=(
                "Requested scope contains values outside the supported "
                f"vocabulary: {', '.join(outside_vocabulary)}"
            ),
        )

    if client.allowed_scopes:
        allowed = set(client.allowed_scopes)
        disallowed = sorted({t for t in tokens if t not in allowed})
        if disallowed:
            return ScopeResult(
                granted=None,
                error_description=(
                    f"Requested scope is not allowed for client "
                    f"'{client.client_id}': {', '.join(disallowed)}"
                ),
            )

    return ScopeResult(granted=effective)
