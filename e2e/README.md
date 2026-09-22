# End-to-end test harness

The CI end-to-end suite. Unlike `examples/` (real usage presets), nothing here
is meant to be copied into a project - these scripts drive a running nanoidp
over the network to cover what the unit suite structurally cannot: real HTTP,
the SAML redirect/POST bindings, the MCP Streamable HTTP transport, and the
OAuth/MCP interoperability loop. They run in `.github/workflows/e2e.yml`.

| File | What it does |
| --- | --- |
| `test_agent.py` | The main agent. Drives a real server and asserts protocol behaviour. Suites: default, `--oauth21`, `--saml-signed`, `--mcp`. |
| `mock_mcp_server.py` | A minimal OAuth-protected MCP resource server (fixture) for the `--mcp` interoperability suite. See the guide "Testing an MCP client against nanoidp". |
| `mock_chat_model.py` | A stupid OpenAI-compatible chat model (fixture, standard library only): always asks for the MCP tool, then quotes the tool's answer. The AI Agent's "model" in `n8n_e2e.py`, so that path 2 of #194 needs no LLM. |
| `mcp_smoke_test.py` | Exercises the real MCP stdio server startup + a `tools/call`, the transport a unit test cannot reach. |
| `n8n_e2e.py` | Drives `examples/agentic-stack/` (nanoidp + mock MCP server + mock chat model + a pinned n8n): n8n's own OAuth2 flow against nanoidp, then its MCP Client node calling a tool (path 1) and an AI Agent calling the same tool through the MCP Client Tool node (path 2), each with the scope and audience negatives (#194). Runs in `.github/workflows/n8n-e2e.yml`, manual and nightly. |
| `shared_store_e2e.py` | Two servers over one SQLite runtime store, started from different working directories: a runtime user created at one logs in at the other, a code issued by one is redeemed once at the other, a token revoked at one is refused by the other, a promotion at one is declared for the other, and the audit of both reads as one (#354). |
| `gen_sp_keypair.py` | Generates a test SP keypair for the signed-SAML suite. |

## Running

```bash
# start a server first (see CONTRIBUTING.md), then:
python e2e/test_agent.py                              # default suite
python e2e/test_agent.py --oauth21 --url http://localhost:8001
python e2e/test_agent.py --mcp http://localhost:9100/mcp
python e2e/mcp_smoke_test.py --config ./config

# two servers over one store (see the guide "Two processes, one runtime state")
python e2e/shared_store_e2e.py --a http://localhost:8007 --b http://localhost:8008
```

Adding a feature? Extend the matching suite here in the same PR - an
end-to-end scenario is part of the deliverable, not a follow-up.

## Environment variables

`test_agent.py`'s `test_totp_login` needs a secret it cannot enroll itself
(`totp_secret` is YAML-only, #348): set `NANOIDP_E2E_TOTP_SECRET` to a
Base32 secret already configured as a user's `totp_secret` in `users.yaml`
to exercise its code-screen-and-verify checks - without it, that half of
the test silently no-ops instead of failing. `NANOIDP_E2E_TOTP_USERNAME` /
`NANOIDP_E2E_TOTP_PASSWORD` name the user the secret belongs to (default:
`--user`/`--password`, i.e. `admin`/`admin`).
