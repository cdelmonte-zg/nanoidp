# n8n end-to-end stack

nanoidp, the RFC 9728 mock MCP server from `e2e/` and a pinned n8n on one
Compose network: a real MCP host authenticates against nanoidp with its own
OAuth2 flow and calls a tool. `e2e/n8n_e2e.py` drives the whole loop headless;
the same stack lets you open n8n and watch it by hand.

The guide is [n8n end to end](https://cdelmonte-zg.github.io/nanoidp/guides/n8n-end-to-end.html);
this file is the short version.

```bash
# from the repository root
docker compose -f examples/agentic-stack/docker-compose.yml up --build --wait
python e2e/n8n_e2e.py
docker compose -f examples/agentic-stack/docker-compose.yml down -v
```

After the script has run, n8n is at http://localhost:5678 (owner
`owner@example.org` / `E2eOwnerPassw0rd!`) with the imported credentials and
the workflows the script created; nanoidp is at http://localhost:8000
(`admin` / `admin`), the mock MCP server at http://localhost:9100/mcp.

`config/` is nanoidp's configuration for the stack, `n8n-import/` the two
n8n credentials the script imports. Nothing here is a production setup: fixed
encryption key, plain HTTP, demo passwords.
