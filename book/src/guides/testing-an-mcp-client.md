# Testing an MCP client against nanoidp

nanoidp is an OAuth 2.1 / OIDC authorization server. To test a real MCP
client's authorization code against it end to end, you need a protected MCP
*resource* server for the client to call. The repository ships a fixture for
exactly this: [`examples/mock_mcp_server.py`](https://github.com/cdelmonte-zg/nanoidp/blob/main/examples/mock_mcp_server.py),
a minimal MCP Streamable HTTP server that validates bearer tokens against
nanoidp and exposes three scope-gated tools.

## The loop

```text
agent host / MCP client
     |  tools/call without a token
     v
mock MCP server  -- 401 + RFC 9728 metadata --> authorization_servers: nanoidp
     |
     |  /authorize (PKCE, resource=mcp-server) -> /token -> access token aud=mcp-server
     v
tools/call with the bearer -> scope check -> result
```

The client discovers the authorization server from the `401`'s
`WWW-Authenticate: Bearer resource_metadata="..."` header, fetches the
RFC 9728 `/.well-known/oauth-protected-resource` document (which names
nanoidp in `authorization_servers`), runs the authorization code flow with
PKCE and `resource=<mcp server URL>` (RFC 8707), and calls the tool with the
resulting audience-bound access token.

## The tools and their scopes

| Tool | Scope required |
| --- | --- |
| `read_document` | `documents:read` |
| `delete_document` | `documents:write` |
| `admin_operation` | `admin` |

Authorization happens in two distinct layers, and the fixture shows both:

- **Resource-level scope floor** (`documents:read`), enforced by the SDK's
  bearer middleware before any tool runs. A token that lacks it gets the
  conformant MCP/RFC 9728 challenge: `403` with `WWW-Authenticate: Bearer
  error="insufficient_scope", ..., resource_metadata="<the RFC 9728 URL>"`.
  This is the transport-level response an MCP client keys off.
- **Application-level per-tool check** for the finer `documents:write` /
  `admin` operations, made inside each tool. A caller past the floor but
  lacking the elevated scope gets an in-band MCP tool error (`isError`), not
  an HTTP challenge - a second, application-defined authorization decision.

A token whose `aud` is a different resource is rejected at the transport with
`401` + `WWW-Authenticate: Bearer` before any tool runs (RFC 8707 audience
binding).

## Running it

nanoidp must advertise the three scopes in its vocabulary, and its issuer
must equal the URL it actually serves (the mock derives the JWKS URL from the
issuer). The delegated leg logs in as a PUBLIC client (PKCE, no secret): the
bundled config registers `mcp-public-client` with
`token_endpoint_auth_method: none` for exactly this, since a real MCP client
holds no client secret.

```yaml
# settings.yaml
oauth:
  issuer: "http://localhost:8003"
  scopes_supported:
    - openid
    - profile
    - email
    - offline_access
    - documents:read
    - documents:write
    - admin
```

```bash
# nanoidp
PORT=8003 python -m nanoidp

# the mock resource server
python examples/mock_mcp_server.py \
  --issuer http://localhost:8003 \
  --resource http://localhost:9100/mcp \
  --port 9100

# drive the whole loop deterministically (no LLM)
python examples/test_agent.py --url http://localhost:8003 \
  --mcp http://localhost:9100/mcp
```

`examples/test_agent.py --mcp` acts as the MCP client itself, through the
`mcp` SDK, so a failure means PKCE, discovery, `resource`, audience, scope or
MCP framing is wrong - never that a model chose not to call a tool.

## Validation is JWKS-only

The mock validates each token against nanoidp's JWKS (signature, `iss`,
`aud`, `exp`, scopes) and never calls `/introspect`. A self-contained JWT
carries no live revocation state, so **a token revoked at nanoidp stays valid
at the resource server until it expires** - the e2e asserts this, showing the
token reported inactive by nanoidp's `/introspect` while the mock still
accepts it. This is the difference between self-contained and introspected
tokens; the fixture demonstrates the self-contained side. A token still
verifies across a nanoidp key rotation, because nanoidp keeps the previous
keys in its JWKS.
