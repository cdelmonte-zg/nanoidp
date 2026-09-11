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

Container tags are derived from release tags (for example `v2.6.0`);
`latest` points at the newest non-prerelease.

Since 3.1.0 the image runs as uid 1000 (gid 0) rather than root. Anything
you mount for nanoidp to write, a keys volume in particular, must be
writable by that user: a volume first created by an older release is
root-owned and needs a one-time `chown -R 1000:0`. A read-only config
mount needs nothing.

## Helm

```bash
helm install nanoidp oci://ghcr.io/cdelmonte-zg/charts/nanoidp --values values.yaml
```

Without `--version`, Helm resolves the newest final release; pre-releases
need `--devel` or an explicit `--version`. See the
[chart README](https://github.com/cdelmonte-zg/nanoidp/tree/main/charts/nanoidp)
for a complete, working `values.yaml` (config files, a registered OAuth
client, Ingress), the full set of values, and the chart's limitations.

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
