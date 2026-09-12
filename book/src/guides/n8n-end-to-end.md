# n8n end to end

A real MCP host is the honest test of nanoidp's OAuth/MCP surface: it has its
own expectations about discovery, PKCE, `resource` and how a resource server
challenges it, and none of them are written by us. This guide runs n8n
against nanoidp and the mock MCP server from
[Testing an MCP client against nanoidp](testing-an-mcp-client.md) on two
paths, with no LLM and no browser in the loop: the **MCP Client** node on its
own (path 1), and the **AI Agent** with the **MCP Client Tool** node inside
its tool-calling loop, driven by a mock chat model (path 2).

The stack lives in
[`examples/agentic-stack/`](https://github.com/cdelmonte-zg/nanoidp/tree/main/examples/agentic-stack)
and the script that drives it in
[`e2e/n8n_e2e.py`](https://github.com/cdelmonte-zg/nanoidp/blob/main/e2e/n8n_e2e.py).
It is what `.github/workflows/n8n-e2e.yml` runs, manually and nightly.

## Path 1: the MCP Client node

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

The script bootstraps n8n (owner, login, API key), imports the three
credentials from `examples/agentic-stack/n8n-import/`, runs n8n's OAuth2
credential flow without a browser, creates the workflows through the public
API and triggers them through their webhooks. Path 1 first:

| check | what it shows |
| --- | --- |
| the authorization URL n8n builds carries `code_challenge_method=S256`, `client_id=n8n-public` and `resource=http://mcp:9100/mcp` | n8n's request is what an MCP client is supposed to send |
| `read_document` returns the document and the execution is `success` | the token n8n obtained is accepted by a resource server that only knows nanoidp's JWKS |
| `delete_document` with a token holding only `documents:read` fails with `insufficient_scope ... requires the 'documents:write' scope` | the resource server's scope decision reaches the workflow as the node's error |
| a credential whose `resourceUrl` names another resource gets a token nanoidp binds to that resource, and the mock server rejects it | audience binding works in the direction that matters: a token for one resource is not a token for another |

Then path 2, with the same credential (its token is already stored, so the
OAuth is not repeated: path 2 is about what happens after it):

| check | what it shows |
| --- | --- |
| the model is offered `MCP_Client_Tool_read_document`, `..._delete_document` and `..._admin_operation` | n8n propagates the OAuth-protected server's tool list into the agent; listing is not gated on scope, calling is |
| asked to read `doc-42`, the model calls `read_document`, the tool result carries the document, and the agent's answer quotes it | the token n8n obtained does the same job from inside the loop as from the step node |
| asked to delete, the model calls `delete_document`; the tool result is the server's `insufficient_scope ... requires the 'documents:write' scope`, quoted in the answer, and the execution is `success` | the resource server's decision reaches the agent loop as a tool result the model can react to, not as a crash; the tool node's run is marked as an error, the agent goes on |
| with the wrong-audience credential the execution fails on `tools/list` with `invalid_token`, and the model is never called | a token for another resource is refused before the agent even knows what tools exist |

After the run, n8n is at `http://localhost:5678` (`owner@example.org` /
`E2eOwnerPassw0rd!`): the workflows and credentials the script created are
there, and both loops can be repeated from the editor. `docker compose
... down -v` removes everything.

## Path 2: the AI Agent's tool-calling loop

```
n8n (AI Agent; model = mock chat model; tool = MCP Client Tool, mcpOAuth2Api credential)
   |  POST /mcp  tools/list, Bearer token                -> mock MCP server: read/delete/admin
   |  POST /v1/chat/completions {messages, tools}        -> mock chat model: "call MCP_Client_Tool_read_document"
   |  POST /mcp  tools/call read_document, Bearer token  -> mock MCP server: verifies the JWT, returns the document
   |  POST /v1/chat/completions {..., tool result}       -> mock chat model: "The tool answered: ..."
   v
webhook response: {"output": "The tool answered: [...\"contents of document 'doc-42'\"...]"}
```

The model is
[`e2e/mock_chat_model.py`](https://github.com/cdelmonte-zg/nanoidp/blob/main/e2e/mock_chat_model.py),
a fixture and deliberately a stupid one: an OpenAI-compatible
`/v1/chat/completions` that, offered tools, always answers with one tool call
(the tool picked from the user's words, `read_document` unless they say
"delete" or "admin"), and, handed a tool result, answers with a fixed sentence
quoting it. It proves nothing about language models; it makes the agent's
loop deterministic so that what is under test is n8n's plumbing between the
OAuth-protected tool and the model. It is not a general OpenAI emulation and
is meant to stay that way.

n8n's side is all standard nodes, created by the script through the public
API: an **AI Agent** (`enableStreaming` off, since a webhook answers with the
last node's output; `maxIterations` 3), an **OpenAI Chat Model** whose
`OpenAI` credential has the mock's URL as *Base URL* and the *Use Responses
API* toggle off (the mock speaks chat completions), and an **MCP Client
Tool** with the same `MCP OAuth2 API` credential as path 1 and *All* tools.

Three things measured on n8n 2.38.7 that the mock and the script encode:

- **Tool names are prefixed** with the node's name: the model sees
  `MCP_Client_Tool_read_document`, and n8n maps the call back. The mock
  matches on the suffix.
- **The request is minimal**: `model`, `messages`, `tools` (each with
  `strict: false`) and `stream: false`; no `tool_choice`, no
  `response_format`. A tool result comes back to the model as a JSON string
  of the MCP `content` list; a tool that answers `isError` comes back as
  `[{"error": "..."}]` with the server's text, and the run continues.
- **A connection failure is fatal, a tool error is not.** The wrong-audience
  credential fails at `tools/list`, the sub-node's error becomes the
  execution's, and the model is never called; `insufficient_scope` on
  `tools/call` is a result the model gets to see.

## A real model, by hand

The automated run never uses an LLM. To watch path 2 with a model that
actually reads the prompt, the Compose file has an optional `ollama` profile:

```bash
docker compose -f examples/agentic-stack/docker-compose.yml --profile ollama up --build --wait
docker compose -f examples/agentic-stack/docker-compose.yml exec ollama ollama pull qwen2.5:3b
```

In the editor, open one of the `agent` workflows the script created, replace
the `Mock Chat Model` node with an **Ollama Chat Model** (credential base URL
`http://ollama:11434`, model `qwen2.5:3b`) and run it with a prompt of your
own. The model is pulled once into a volume; CPU inference is slow; nothing
in CI depends on it, and no hosted provider is configured anywhere in the
repository.

## Three n8n facts the script encodes

All measured on n8n 2.38.7, the version the Compose file pins:

- **Readiness is JSON, not a 200.** n8n starts in three phases: `/healthz`
  answers 200 from the first seconds while every other path, `/rest/settings`
  included, gets a 200 `text/html` "n8n is starting up" page; then the SPA
  answers 404 HTML while the REST routes are still unmounted; only then the
  JSON. The Compose healthcheck and the script both wait for
  `/rest/settings` to answer the JSON envelope. The nightly once passed on
  the HTML page and ran the whole bootstrap against it.

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
- **OIDC login to n8n itself** through nanoidp is an n8n Enterprise feature
  and is not part of this stack.

The n8n version is pinned on purpose: its MCP OAuth behaviour has changed
across releases, and a failure must be attributable to nanoidp or to a known
n8n version. Bump it deliberately and re-run the script.
