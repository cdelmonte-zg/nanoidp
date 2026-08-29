#!/usr/bin/env python3
"""Mock protected MCP server: an e2e fixture for issue #191 (RFC 9728).

This is a FIXTURE, not a product. It exists so the OAuth/MCP interoperability
milestone can be demonstrated end to end: the 401 -> protected-resource
metadata -> /authorize (PKCE, resource=) -> /token -> tools/call round trip,
plus the "wrong audience" and "insufficient scope" rejections a real MCP
resource server performs.

It is an MCP Streamable HTTP server (the `mcp` SDK's resource-server mode)
exposing three tools, each gated on one scope:

    read_document    -> documents:read
    delete_document  -> documents:write
    admin_operation  -> admin

Bearer tokens are validated JWKS-only (self-contained JWT): the server
fetches nanoidp's JWKS once, verifies the RS256 signature, and checks `iss`,
`aud` (which must equal this server's own resource URL), `exp` and the
requested tool's scope. It never calls nanoidp's /introspect. A DELIBERATE
consequence: a token revoked at nanoidp stays valid HERE until it expires,
because a self-contained JWT carries no live revocation state. Revocation is
demonstrated in the e2e through /introspect against nanoidp, not against this
server - that is the difference between self-contained and introspected
tokens, and this fixture only shows the self-contained side.

Run:
    python examples/mock_mcp_server.py \
        --issuer http://localhost:8000 \
        --resource http://localhost:9100/mcp \
        --host 127.0.0.1 --port 9100
"""

import argparse
import os

import jwt
from jwt import PyJWKClient
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer

# One scope per tool (issue #191).
TOOL_SCOPES = {
    "read_document": "documents:read",
    "delete_document": "documents:write",
    "admin_operation": "admin",
}


class InsufficientScope(Exception):
    """Raised by a tool when the bearer token lacks the tool's scope. The MCP
    client sees it as a tool error naming the missing scope - the resource
    server equivalent of a 403 insufficient_scope (RFC 6750 §3.1 / MCP)."""


class MockTokenVerifier(TokenVerifier):
    """Validate a bearer JWT against nanoidp's JWKS (issue #191).

    JWKS-only: signature (RS256), issuer, audience == this resource, and
    expiry. The requested resource's tokens carry ``aud`` = the resource URL
    (RFC 8707, #187), so a token minted for a different resource - or an
    ordinary token with ``aud`` = the global oauth.audience - fails the
    audience check and is rejected here. Scopes come from the space-separated
    ``scope`` claim. Any failure returns None, which the SDK turns into a 401
    carrying the RFC 9728 metadata URL.
    """

    def __init__(self, issuer: str, resource: str) -> None:
        self.issuer = issuer.rstrip("/")
        self.resource = resource
        # PyJWKClient caches keys and refetches on an unknown kid, so a token
        # signed by a rotated key still validates as long as nanoidp keeps the
        # previous keys in its JWKS (it does) - which the e2e asserts.
        self._jwks = PyJWKClient(f"{self.issuer}/.well-known/jwks.json")

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            signing_key = self._jwks.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self.resource,
                issuer=self.issuer,
                options={"require": ["exp", "iss", "aud"]},
            )
        except Exception:
            return None
        scopes = (claims.get("scope") or "").split()
        return AccessToken(
            token=token,
            client_id=claims.get("client_id", claims.get("sub", "")),
            scopes=scopes,
            expires_at=claims.get("exp"),
            resource=self.resource,
            subject=claims.get("sub"),
            claims=claims,
        )


def _require_scope(tool: str) -> AccessToken:
    """The bearer token for the current request, asserting the tool's scope."""
    token = get_access_token()
    if token is None:  # pragma: no cover - the SDK 401s before a tool runs
        raise InsufficientScope("no access token on the request")
    required = TOOL_SCOPES[tool]
    if required not in token.scopes:
        raise InsufficientScope(
            f"insufficient_scope: '{tool}' requires the '{required}' scope; "
            f"the token has [{', '.join(token.scopes) or 'none'}]"
        )
    return token


def build_server(issuer: str, resource: str) -> MCPServer:
    server: MCPServer = MCPServer(
        name="mock-mcp-server",
        token_verifier=MockTokenVerifier(issuer, resource),
        auth=AuthSettings(
            issuer_url=issuer,  # type: ignore[arg-type]
            resource_server_url=resource,  # type: ignore[arg-type]
            required_scopes=[],
        ),
    )

    @server.tool()
    def read_document(document_id: str) -> str:
        """Read a document (requires the documents:read scope)."""
        _require_scope("read_document")
        return f"contents of document {document_id!r}"

    @server.tool()
    def delete_document(document_id: str) -> str:
        """Delete a document (requires the documents:write scope)."""
        _require_scope("delete_document")
        return f"deleted document {document_id!r}"

    @server.tool()
    def admin_operation(action: str) -> str:
        """Perform an admin operation (requires the admin scope)."""
        token = _require_scope("admin_operation")
        return f"admin action {action!r} performed by {token.subject!r}"

    return server


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--issuer",
        default=os.environ.get("MOCK_MCP_ISSUER", "http://localhost:8000"),
        help="nanoidp issuer base URL (default: http://localhost:8000)",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9100)
    parser.add_argument(
        "--resource",
        default=os.environ.get("MOCK_MCP_RESOURCE"),
        help="this server's own resource URL, the token audience it accepts "
        "(default: http://<host>:<port>/mcp)",
    )
    args = parser.parse_args()
    resource = args.resource or f"http://{args.host}:{args.port}/mcp"

    server = build_server(args.issuer, resource)
    print(f"mock MCP server: resource={resource} issuer={args.issuer}")
    import asyncio

    asyncio.run(
        server.run_streamable_http_async(
            host=args.host, port=args.port, stateless_http=True
        )
    )


if __name__ == "__main__":
    main()
