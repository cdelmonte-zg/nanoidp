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
| `mcp_smoke_test.py` | Exercises the real MCP stdio server startup + a `tools/call`, the transport a unit test cannot reach. |
| `gen_sp_keypair.py` | Generates a test SP keypair for the signed-SAML suite. |

## Running

```bash
# start a server first (see CONTRIBUTING.md), then:
python e2e/test_agent.py                              # default suite
python e2e/test_agent.py --oauth21 --url http://localhost:8001
python e2e/test_agent.py --mcp http://localhost:9100/mcp
python e2e/mcp_smoke_test.py --config ./config
```

Adding a feature? Extend the matching suite here in the same PR - an
end-to-end scenario is part of the deliverable, not a follow-up.
