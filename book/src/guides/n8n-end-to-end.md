# n8n end to end

A real MCP host is the honest test of nanoidp's OAuth/MCP surface: it has its
own expectations about discovery, PKCE, `resource` and how a resource server
challenges it, and none of them are written by us. This guide runs n8n's
**MCP Client** node against nanoidp and the mock MCP server from
[Testing an MCP client against nanoidp](testing-an-mcp-client.md), with no
LLM and no browser in the loop.

The stack lives in
[`examples/agentic-stack/`](https://github.com/cdelmonte-zg/nanoidp/tree/main/examples/agentic-stack)
and the script that drives it in
[`e2e/n8n_e2e.py`](https://github.com/cdelmonte-zg/nanoidp/blob/main/e2e/n8n_e2e.py).
It is what `.github/workflows/n8n-e2e.yml` runs, manually and nightly.

## The loop

```
n8n (MCP Client node, mcpOAuth2Api credential)
   |  GET  /.well-known/oauth-protected-resource/mcp     -> mock MCP server (RFC 9728)
   |  GET  /authorize?...code_challenge...&resource=...   -> nanoidp (PKCE, public client)
   |  POST /token (code + code_verifier)                  -> nanoidp: access token, aud = the resource
   |  POST /mcp  tools/call read_document, Bearer token   -> mock MCP server: verifies the JWT against
   |                                                          nanoidp's JWKS (iss, aud, exp, scope)
   v
webhook response: {"structuredContent": {"result": "contents of document 'doc-42'"}}
```

Everything n8n does here is n8n's own code: the credential type, the
authorization URL, the token exchange, the MCP transport. nanoidp is
configured, not adapted (`examples/agentic-stack/config/settings.yaml`): the
issuer is its name on the Compose network, the scope vocabulary carries the
three scopes the mock server gates its tools on, and one public client,
`n8n-public`, has n8n's OAuth callback as its registered `redirect_uri`.

## Running it

```bash
# from the repository root
docker compose -f examples/agentic-stack/docker-compose.yml up --build --wait
python e2e/n8n_e2e.py
```

The script bootstraps n8n (owner, login, API key), imports the two
credentials from `examples/agentic-stack/n8n-import/`, runs n8n's OAuth2
credential flow without a browser, creates three workflows through the public
API and triggers them through their webhooks:

| check | what it shows |
| --- | --- |
| the authorization URL n8n builds carries `code_challenge_method=S256`, `client_id=n8n-public` and `resource=http://mcp:9100/mcp` | n8n's request is what an MCP client is supposed to send |
| `read_document` returns the document and the execution is `success` | the token n8n obtained is accepted by a resource server that only knows nanoidp's JWKS |
| `delete_document` with a token holding only `documents:read` fails with `insufficient_scope ... requires the 'documents:write' scope` | the resource server's scope decision reaches the workflow as the node's error |
| a credential whose `resourceUrl` names another resource gets a token nanoidp binds to that resource, and the mock server rejects it | audience binding works in the direction that matters: a token for one resource is not a token for another |

After the run, n8n is at `http://localhost:5678` (`owner@example.org` /
`E2eOwnerPassw0rd!`): the workflows and credentials the script created are
there, and the same loop can be repeated from the editor. `docker compose
... down -v` removes everything.

## Two n8n facts the script encodes

Both measured on n8n 2.38.7, the version the Compose file pins:

- **`resourceUrl` must be explicit** on the `MCP OAuth2 API` credential. n8n
  does discover the resource from the server's RFC 9728 metadata, but only an
  explicit `resourceUrl` makes it send `resource` on `/authorize`. Without
  it the token's audience is nanoidp's default and the resource server
  rejects it with `invalid_token`.
- **The OAuth callback needs n8n's own session.** `/rest/oauth2-credential/callback`
  answers `Unauthorized` without the logged-in cookie, so the script follows
  nanoidp's redirect with the session it obtained at bootstrap. In a browser
  this is invisible; headless it is the one thing to know.

A third one decides how the credentials get in: n8n's public API refuses an
empty `clientSecret` for this credential type, while a real MCP client holds
no secret. The script imports them with `n8n import:credentials` instead,
which accepts the public client as it is.

## What is deliberately not here

- **Dynamic client registration.** n8n's `MCP OAuth2 API` credential enables
  it by default; with it on, n8n discovers nanoidp from the resource
  metadata, asks for `/.well-known/oauth-authorization-server`, falls back to
  `openid-configuration`, and stops at the missing `registration_endpoint`.
  That is #190. The stack runs with the toggle off.
- **The AI Agent path.** The `MCP Client Tool` node inside an agent adds a
  tool-calling loop on top of the same OAuth; #194 keeps it as a separate
  deliverable with a mock chat model, so that no LLM is needed in CI.
- **OIDC login to n8n itself** through nanoidp is an n8n Enterprise feature
  and is not part of this stack.

The n8n version is pinned on purpose: its MCP OAuth behaviour has changed
across releases, and a failure must be attributable to nanoidp or to a known
n8n version. Bump it deliberately and re-run the script.
