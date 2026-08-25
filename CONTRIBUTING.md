# Contributing to NanoIDP

Thank you for your interest in contributing to NanoIDP!

Before writing code, read the
[Architecture page](https://cdelmonte-zg.github.io/nanoidp/project/architecture.html)
(source: `book/src/project/architecture.md`): it maps the packages, the
import contracts CI enforces, where state lives, and the multi-site
flows (like adding a client field) that changes must follow.

## How to Contribute

### Reporting Bugs

1. Check existing issues to avoid duplicates
2. Create a new issue with:
   - Clear title
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (Python version, OS)

### Feature Requests

1. Open an issue describing the feature
2. Explain the use case
3. Wait for discussion before implementing

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Run tests and linting
5. Commit with clear messages
6. Push to your fork
7. Open a Pull Request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/nanoidp.git
cd nanoidp

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows

# Install in development mode with dev dependencies
pip install -e ".[dev]"

# Run locally
nanoidp --debug
```

## Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=nanoidp

# Run specific test
pytest tests/test_basic.py
```

## End-to-End Test Agent

NanoIDP includes a comprehensive test agent that validates all functionality against a running server:

```bash
# Run against local server (default: http://localhost:8000)
python examples/test_agent.py

# Run against custom URL
python examples/test_agent.py --url http://localhost:9000

# Verbose output
python examples/test_agent.py --verbose

# JSON output
python examples/test_agent.py --json
```

The test agent covers:

- **Core**: Health check, OIDC discovery
- **OAuth2/OIDC**: All grant types, token introspection, revocation, logout
- **SAML 2.0**: Metadata, SSO (POST/Redirect bindings), Attribute Query, signing config
- **Key Management**: Key info, rotation, post-rotation token validation
- **REST API**: Users, config, audit log

**Caution:** a run against a live server persists configuration changes back to that server's `config/settings.yaml`. Since #127, unrelated fields (e.g. `${PORT}` placeholders, comments) are left untouched, but any value the run genuinely changes (e.g. `default_acs_url`) is still written for real. If the server runs from a git checkout, restore the file before committing: `git checkout -- config/settings.yaml`.

## Code Quality

```bash
# Format code
black src tests

# Lint code
ruff check src tests

# Fix linting issues automatically
ruff check --fix src tests

# Check architectural import contracts (#149)
lint-imports
```

`lint-imports` enforces the package layering `routes -> services -> config`
and keeps `serialization.py` free of runtime imports from the package (that is
what lets `config.py` import it without a cycle). The contracts live in
`[tool.importlinter]` in `pyproject.toml`; a type-checking-only import does not
count. If a change needs a new edge between layers, adjust the contract in the
same PR and say why.

## Code Style

- Follow PEP 8 (enforced by Black and Ruff)
- Use meaningful variable and function names
- Add docstrings to functions and classes
- Keep functions focused and small
- Type hints are encouraged

## Commit Messages

Use clear, descriptive commit messages:

- `feat: Add OAuth client management UI`
- `fix: Correct token expiry calculation`
- `docs: Update README with Docker instructions`
- `refactor: Simplify user authentication flow`
- `test: Add tests for SAML endpoint`

## Project Structure

```
nanoidp/
├── src/nanoidp/       # Main package
│   ├── routes/        # Flask route handlers
│   ├── services/      # Business logic
│   └── templates/     # Jinja2 templates
├── tests/             # Test files
├── config/            # Default configuration
└── docs/              # Documentation
```

## Releasing (maintainers)

Releases are cut by pushing a `v*` tag; two workflows publish to PyPI and
GHCR and a wheel-smoke job exercises the built artifact before anything is
published. The full process, with the exact commands, the verification
checklist and the recovery procedures, lives in
[docs/RELEASING.md](docs/RELEASING.md). In short: bump `pyproject.toml`
through a PR, tag the merged commit (`v2.7.0-rc5` for a pre-release with a
hyphen, `v2.7.0` for a final), create the GitHub release, then verify that
every workflow job ran and that the published artifacts install and behave
(pre-releases reach PyPI too and need `pip install --pre`; `:latest` on GHCR
moves only on final tags).

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
