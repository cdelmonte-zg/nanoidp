"""Token tool handlers: generate, decode, verify (#286).

Split out of the monolithic mcp_server module; bodies unchanged - including
the #279 simulation-boundary comments and tool semantics.
"""

from typing import Any

import jwt as pyjwt

from ..config import ConfigManager
from ..services import get_crypto_service, get_token_service
from .normalize import _normalize_str_list


# Token Operations
def _tool_generate_token(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    username = arguments["username"]
    user = config.get_user(username)
    if not user:
        return {"success": False, "error": f"User '{username}' not found"}

    # Optional client binding (#73). A given client_id must name a real client:
    # binding to an unknown one would stamp a client_id claim no authenticable
    # client could ever match, i.e. a refresh token that looks bound but is
    # dead - reject it up front instead.
    client_id = arguments.get("client_id")
    if client_id is not None and config.get_client(client_id) is None:
        return {"success": False, "error": f"Client '{client_id}' not found"}

    token_service = get_token_service()
    token_response = token_service.create_token(
        user=user,
        exp_minutes=arguments.get("expires_in_minutes", config.settings.token_expiry_minutes),
        extra_claims=arguments.get("extra_claims"),
        # BOUNDARY (#279): like `resource` below, `scope` is passed through
        # with no scopes_supported vocabulary check and no allowed_scopes
        # ceiling, even when client_id is given - this tool mints a token
        # directly (a testing / simulation affordance, not an OAuth grant),
        # and an out-of-ceiling scope is exactly what testing a resource
        # server's rejection path needs. The ceiling lives on the grant
        # endpoints (resolve_scope at /authorize, /device_authorization and
        # the /token grants), not on this admin tool.
        scope=arguments.get("scope"),
        # Client binding (#73): with client_id the token is bound and a
        # spendable refresh token follows from the binding inside
        # create_token itself (#278); unbound -> no refresh token (a refresh
        # token with no client_id binding is refused since 3.0). The unbound
        # access token is still fine for a one-shot test.
        client_id=client_id,
        # _execute_tool is also reachable directly (see tests), bypassing
        # call_tool's input_schema validation; reject a non-list with a
        # clean error here too instead of minting a token whose malformed
        # claim only misbehaves later at /userinfo (same precedent as
        # additional_audiences, #37).
        id_token_claims=_normalize_str_list(arguments.get("id_token_claims"), "id_token_claims")
        or None,
        userinfo_claims=_normalize_str_list(arguments.get("userinfo_claims"), "userinfo_claims")
        or None,
        # RFC 8707 resource indicators (#187): set the access token aud to the
        # given resource(s). BOUNDARY: unlike /token, /authorize and
        # /device_authorization - which run every requested resource through
        # resolve_resources and reject one outside the client's
        # allowed_resources with invalid_target - this tool never applies that
        # per-client ceiling, even when client_id is given for the refresh
        # binding above: it mints a token directly (a testing / simulation
        # affordance, not an OAuth grant), so the aud is whatever is passed.
        # That is deliberate; a reader expecting parity with /token should know
        # the ceiling lives on the grant endpoints, not on this admin tool.
        resource=_normalize_str_list(arguments.get("resource"), "resource") or None,
    )
    result = {
        "success": True,
        "access_token": token_response["access_token"],
        "token_type": token_response["token_type"],
        "expires_in": token_response["expires_in"],
    }
    # Present only for a bound (client_id) token; create_token omits the key
    # entirely when no refresh token is issued.
    if "refresh_token" in token_response:
        result["refresh_token"] = token_response["refresh_token"]
    if "id_token" in token_response:
        result["id_token"] = token_response["id_token"]
    return result


def _tool_decode_token(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    token = arguments["token"]
    try:
        payload = pyjwt.decode(token, options={"verify_signature": False})
        return {"success": True, "claims": payload}
    except Exception as e:
        return {"success": False, "error": f"Failed to decode token: {str(e)}"}


def _tool_verify_token(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    token = arguments["token"]
    crypto = get_crypto_service(config.settings.keys_dir)
    # audience: optional (#187). Omitted -> verify signature and expiry only
    # and return the claims (the aud is in them), so a resource-bound access
    # token (aud = an RFC 8707 resource, not oauth.audience) is not falsely
    # reported invalid. Provided -> verify the token is valid FOR that
    # audience, which is how a caller simulates a resource server accepting
    # or rejecting a token ("valid for A, not for B").
    audience = arguments.get("audience")
    try:
        payload = crypto.verify_jwt(token, audience)
        return {"valid": True, "claims": payload}
    except Exception as e:
        # A rejected token is verify_token's designed answer, not a tool
        # failure: use "reason" (not "error") so call_tool does not flag
        # the result is_error (see the isError contract in the docstring).
        return {"valid": False, "reason": str(e)}


