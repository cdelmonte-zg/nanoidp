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

from typing import Tuple

from flask import Response, jsonify


def oauth_error(error: str, description: str, status: int = 400) -> Tuple[Response, int]:
    """An RFC 6749 §5.2 error JSON body."""
    return (
        jsonify({"error": error, "error_description": description}),
        status,
    )


def invalid_client_error(
    description: str, *, basic_attempted: bool
) -> Tuple[Response, int]:
    """A §5.2 ``invalid_client`` 401.

    When the client ATTEMPTED authentication via the Authorization header,
    §5.2 says the response MUST be 401 and MUST include a WWW-Authenticate
    header matching the scheme the client used (#310 review) - nanoidp
    supports Basic there, so that is the challenge issued. A client that
    never sent the header gets the JSON alone: the MUST is conditional on
    the attempt.
    """
    body, status = oauth_error("invalid_client", description, 401)
    if basic_attempted:
        body.headers["WWW-Authenticate"] = 'Basic realm="nanoidp"'
    return body, status
