"""What an introspection reports about a token, RFC 7662 §2.2 (#303).

The response is domain policy - which of the token's claims a resource
server is told, and what is said when the token does not carry one - so it
belongs next to the other protocol rules rather than inside the route. The
route keeps the adapter's work: authenticating the caller, verifying the
token, refusing an ID Token, checking revocation and auditing.
"""

from typing import Any, Dict, Mapping, Optional

# What the response says a token is, and the scope reported for a token
# issued before scopes were recorded on one.
_TOKEN_TYPE = "Bearer"
_DEFAULT_SCOPE = "openid"

# Claims copied through as they are: absent in the payload means absent in
# the response is NOT the rule here - RFC 7662 §2.2 has them optional, and
# nanoidp has always reported them, null included, for a token that lacks
# one.
_COPIED_CLAIMS: tuple[str, ...] = ("aud", "iss", "exp", "iat", "nbf")


def build_introspection_response(
    payload: Mapping[str, Any], caller_client_id: Optional[str]
) -> Dict[str, Any]:
    """The introspection response for a token that has already been
    verified, found not to be an ID Token, and found not to be revoked.

    ``client_id`` is the client the TOKEN was issued to, not the caller
    doing the introspection (RFC 7662 §2.2): access tokens carry that claim
    since #188, and the caller is the fallback only for a legacy token
    without it. The fallback is on the key being **absent**: a payload
    carrying ``client_id: None`` reports ``None``, as it always has.
    """
    response: Dict[str, Any] = {
        "active": True,
        "token_type": _TOKEN_TYPE,
        "client_id": payload.get("client_id", caller_client_id),
        "username": payload.get("sub"),
        "sub": payload.get("sub"),
    }
    for claim in _COPIED_CLAIMS:
        response[claim] = payload.get(claim)

    # Presence, not truthiness: a token whose scope is an empty string is
    # reported with an empty scope, not with the default.
    response["scope"] = payload["scope"] if "scope" in payload else _DEFAULT_SCOPE
    return response
