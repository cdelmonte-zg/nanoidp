# Documentation site (mdBook)

The published site: <https://cdelmonte-zg.github.io/nanoidp/>. It is built
from `book/src/` with [mdBook](https://rust-lang.github.io/mdBook/) and
deployed by `.github/workflows/pages.yml` on every push to `main` that
touches the docs.

## Single source of truth

The guides and the project pages are **symlinks** into the canonical files,
so they are never duplicated:

- `src/guides/{MCP_WORKFLOW,SECURITY}.md` -> `docs/` (plus `src/guides/images` -> `docs/images`)
- `src/project/vision.md` -> `VISION.md`, `src/project/changelog.md` -> `CHANGELOG.md`

The introduction and getting-started pages are written for the site.

## Build locally

```bash
cargo install mdbook          # once
cd book && mdbook serve        # live-reload at http://localhost:3000
# or: mdbook build             # renders to book/book/ (gitignored)
```
