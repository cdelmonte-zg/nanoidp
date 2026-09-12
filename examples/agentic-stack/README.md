# n8n end-to-end stack

nanoidp, the RFC 9728 mock MCP server and the mock chat model from `e2e/`,
and a pinned n8n on one Compose network: a real MCP host authenticates
against nanoidp with its own OAuth2 flow and calls a tool, from the MCP
Client node and from inside an AI Agent's tool-calling loop. `e2e/n8n_e2e.py`
drives both loops headless; the same stack lets you open n8n and watch them
by hand.

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
(`admin` / `admin`), the mock MCP server at http://localhost:9100/mcp, the
mock chat model at http://localhost:9200/v1 (its request log at
http://localhost:9200/requests).

`config/` is nanoidp's configuration for the stack, `n8n-import/` the three
n8n credentials the script imports (two `MCP OAuth2 API` ones, good and
wrong-audience, and the `OpenAI` one pointing at the mock chat model).
Nothing here is a production setup: fixed encryption key, plain HTTP, demo
passwords.

## A real model, by hand

The automated run never uses an LLM: the AI Agent's model is
`e2e/mock_chat_model.py`, which always asks for the MCP tool. To watch the
same loop with a model that actually reads the prompt, the Compose file has
an optional `ollama` profile:

```bash
docker compose -f examples/agentic-stack/docker-compose.yml --profile ollama up --build --wait
docker compose -f examples/agentic-stack/docker-compose.yml exec ollama ollama pull qwen2.5:3b
```

The model is pulled once into the `ollama` volume. In the n8n editor, open
one of the `agent` workflows the script created, replace the `Mock Chat
Model` node with an **Ollama Chat Model** node (credential base URL
`http://ollama:11434`, model `qwen2.5:3b`), and run it with a prompt of your
own. `qwen2.5:3b` is small and supports tool calling; any Ollama model that
does will do. CPU inference takes a while; nothing in CI depends on this.
