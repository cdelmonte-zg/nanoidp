"""What the bearer of an access token may see at /userinfo (#303).

Which claims a token's bearer gets is domain policy, not transport: the
scope-to-claim gating of OIDC Core §5.4, the nanoidp claims that have no
standard scope to gate them by, and the `claims` request parameter of §5.5.
It used to be assembled inside the route, where it could only be exercised
through an HTTP request.

The route keeps what is adapter: the Bearer token, its signature, audience
and `token_use`, the revocation check, the user lookup and the audit entry.
Past those, it calls this.
"""

from typing import Any, Dict, Optional

from ..config import User
from .token import resolve_user_claim, sanitize_claim_names

# The standard claims, and the scope that gates each of them when gating is
# active (OIDC Core §5.4).
_SCOPED_CLAIMS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("email", ("email", "email_verified")),
    ("profile", ("preferred_username",)),
)

# nanoidp's own claims have no standard OIDC scope, so they are returned for
# any valid token: gating them would be arbitrary and has no spec basis
# (#102).
_UNGATED_CLAIMS: tuple[str, ...] = ("roles", "groups", "tenant", "identity_class")


def build_userinfo_response(
    user: Optional[User],
    subject: Optional[str],
    granted_scope: Optional[str],
    scope_gating_active: bool,
    requested_claims: Any,
) -> Dict[str, Any]:
    """The UserInfo response for this token's bearer.

    ``granted_scope`` is the access token's ``scope`` claim (RFC 9068
    §2.2.3) and ``scope_gating_active`` says whether the standard claims are
    gated by it - true under the stricter profiles, false under the
    permissive ``dev`` default, which keeps returning them unconditionally
    so this is not a breaking change for existing setups (#102).

    ``requested_claims`` is the UserInfo member of the OIDC ``claims``
    request parameter as it was carried in the token payload, sanitized here
    because it may be hand-crafted: a malformed value is ignored rather than
    raised (#104).

    A subject with no user behind it answers with the subject alone, which
    is what the route has always returned.
    """
    response: Dict[str, Any] = {"sub": subject}
    if user is None:
        return response

    def put(claim_name: str) -> None:
        # Every claim resolves through the resolver that backs the `claims`
        # request parameter, so the two mappings cannot diverge (#113); a
        # claim it cannot supply is omitted.
        found, value = resolve_user_claim(user, claim_name)
        if found:
            response[claim_name] = value

    granted = set((granted_scope or "").split())
    for scope, claims in _SCOPED_CLAIMS:
        if not scope_gating_active or scope in granted:
            for claim_name in claims:
                put(claim_name)

    for claim_name in _UNGATED_CLAIMS:
        put(claim_name)

    # The raw attributes dict is the one deliberate exception to resolving
    # through resolve_user_claim: it is not a claim name.
    if user.attributes:
        response["attributes"] = user.attributes

    # Claims the client asked for are added even when the gating above
    # omitted them, provided nanoidp can supply them, and never overwrite a
    # claim already set (§5.5, #104).
    for claim_name in sanitize_claim_names(requested_claims) or []:
        if claim_name not in response:
            put(claim_name)

    return response
