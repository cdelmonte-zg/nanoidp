# Install

Pick whichever fits your environment.

## PyPI

```bash
pip install nanoidp
```

Ships the server (`python -m nanoidp`) and the MCP server (`nanoidp-mcp`).

## Docker (GHCR)

```bash
docker pull ghcr.io/cdelmonte-zg/nanoidp:latest
```

Run it with your config directory mounted:

```bash
docker run --rm -p 8000:8000 \
  -v $(pwd)/config:/app/config \
  ghcr.io/cdelmonte-zg/nanoidp:latest
```

Container tags are derived from release tags (for example `v2.2.0`);
`latest` points at the newest non-prerelease.

## From source

```bash
git clone https://github.com/cdelmonte-zg/nanoidp.git
cd nanoidp
pip install .
```

For development (tests, lint, type checking):

```bash
pip install -e ".[dev]"
```

The repository also ships a `docker-compose.yml` for running from a
checkout:

```bash
docker-compose up -d
```

Next: the [Quickstart](quickstart.md) gets you from a fresh install to a
first token.
