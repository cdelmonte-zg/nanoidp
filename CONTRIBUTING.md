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
python e2e/test_agent.py

# Run against custom URL
python e2e/test_agent.py --url http://localhost:9000

# Verbose output
python e2e/test_agent.py --verbose

# JSON output
python e2e/test_agent.py --json
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

### Domain invariants have one home (#285)

OAuth/OIDC/SAML policy belongs in services and domain logic; routes and the
MCP server are adapters and must not independently reinterpret the same rule.
If a PR implements the same policy separately at two surfaces - say, a check
written once in `/token` and again, slightly differently, in an MCP tool -
that is an architectural smell to flag in review: extract the rule to one
place (or delegate to the existing one) instead of keeping the copies in
sync by hand. The bug class this prevents is real and recurring here: a
capability exposed by N entry points with a rule updated at N-1 of them
(#269/#272). `tests/test_token_issuance_parity.py` enforces it mechanically
for token issuance: a new surface that mints tokens fails the suite until it
is registered and declares a stance on every policy.

A related rule for comments: never claim a "circular dependency" (or any
structural constraint) a deferred import does not actually avoid - false
constraint comments teach the next contributor a wrong module graph. The one
real import constraint is the `serialization` contract above; everything
else imports normally at module top.

### Error surfaces (#287)

Each surface class has ONE error shape; a new endpoint or tool uses its
class's shape, never invents a seventh:

- **OAuth/OIDC protocol endpoints**: RFC 6749 §5.2 JSON
  (`error`/`error_description`), except `/authorize` errors after
  `redirect_uri` validation, which redirect with `error`, `state` and `iss`
  (RFC 6749 §4.1.2.1, RFC 9207). Never HTML, never bare text.
- **Browser/UI pages**: `flash(message, "error")` + redirect; conflict and
  hook conditions render their message through the shared helpers.
- **SAML**: protocol-level failures answer IN the protocol - a SAML `Status`
  (e.g. `Requester`/`UnknownPrincipal`) inside a Response; transport-level
  failures on the SOAP endpoint answer with a SOAP 1.1 Fault (HTTP 500,
  `faultcode` Client/Server per SOAP 1.1 §6.2). Browser-facing SSO steps may
  use Werkzeug `abort()` HTML, since the reader is a person mid-redirect.
- **MCP**: two deliberate layers - dispatch refusals
  (`{"error", "code", "tool"}`, `is_error=True`, the `MCP_*` code taxonomy)
  vs domain results (`{"success": False, "error", ...}` plus `kind` for
  typed conditions), because "not found" is an answer, not a failed call.
  The layer contract is documented on `_reject` in `mcp_server.py`.

Typed exceptions are not the error channel: `exceptions.py` deliberately
holds only what is actually raised (`SAMLSignatureError`); a taxonomy
nothing raises is documentation that lies.

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
