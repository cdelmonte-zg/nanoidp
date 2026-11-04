"""
RFC 6749 §5.2 error responses - the one home (#310 review) for the shape
both the /token shell (routes/oauth.py) and the grant handlers
(routes/oauth_grants.py) answer errors with.

Descriptions are FIXED text: §5.2 restricts error_description to a narrow
ASCII subset, so caller-controlled values (a grant_type of emoji, quotes,
newlines) and library/exception detail never belong here - both go to the
audit events instead (the #200/#307/#310 rule). §5.2 semantics used across
the endpoint: invalid_request = missing/malformed parameter; invalid_grant
= the presented grant (code, refresh token, resource-owner credentials) is
invalid, expired, revoked or issued to another client; invalid_client =
client authentication failed (401).
"""

from typing import Optional, Tuple

from flask import Response, jsonify


def bearer_challenge(
    *, realm: Optional[str] = None, error: Optional[str] = None, description: Optional[str] = None
) -> str:
    """The value of an RFC 6750 section 3 ``WWW-Authenticate`` header: the
    Bearer scheme followed by at least one parameter (the section's MUST):
    ``realm``, which names the protected resource and is each resource's
    own (/userinfo says ``userinfo``, the registration endpoint names
    none), and, for a refused credential, ``error`` and
    ``error_description``. The one builder for the challenges of /userinfo
    (#465) and the registration access token (#190). Values are FIXED
    text, as every description here is, and the builder fails closed on
    anything outside printable ASCII and HTAB (RFC 7230 quoted-string; a
    quote or a backslash is escaped), so that the header and the JSON body
    that carries the same text can never disagree."""
    params = [
        (name, value)
        for name, value in (("realm", realm), ("error", error), ("error_description", description))
        if value is not None
    ]
    if not params:
        raise ValueError("a Bearer challenge needs at least one parameter")

    def quoted(value: str) -> str:
        if any(not (" " <= ch <= "~" or ch == "\t") for ch in value):
            raise ValueError("a Bearer challenge value is printable ASCII")
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'

    return "Bearer " + ", ".join(f"{name}={quoted(value)}" for name, value in params)


def bearer_error(
    status: int, error: str, description: str, *, realm: Optional[str] = None
) -> Response:
    """An RFC 6750 section 3 error answer of a protected resource: the RFC
    6749 section 5.2 JSON body and the Bearer challenge naming the error. The
    one builder for /userinfo (#465) and the registration access token
    (#190)."""
    body = jsonify({"error": error, "error_description": description})
    body.status_code = status
    body.headers["WWW-Authenticate"] = bearer_challenge(
        realm=realm, error=error, description=description
    )
    return body


def oauth_error(error: str, description: str, status: int = 400) -> Tuple[Response, int]:
    """An RFC 6749 §5.2 error JSON body."""
    return (
        jsonify({"error": error, "error_description": description}),
        status,
    )


def invalid_client_error(
    description: str, *, basic_attempted: bool
) -> Tuple[Response, int]:
    """A §5.2 ``invalid_client`` response, status per BOTH specs (#310
    review round 2).

    RFC 6749 §5.2: invalid_client is 400 by default; when the client
    ATTEMPTED authentication via the Authorization header the response
    MUST be 401 and MUST include a WWW-Authenticate challenge for the
    scheme used (Basic here). RFC 9110 §11.6.1 closes the other door: ANY
    401 must carry at least one challenge - so a failure with no
    Authorization header attempted (a missing client_id, a wrong
    client_secret_post body secret) answers 400, never a challenge-less
    401 and never a Basic challenge for a client whose registered method
    is not Basic.
    """
    if basic_attempted:
        body, status = oauth_error("invalid_client", description, 401)
        body.headers["WWW-Authenticate"] = 'Basic realm="nanoidp"'
        return body, status
    return oauth_error("invalid_client", description, 400)
