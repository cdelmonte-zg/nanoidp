# Contributing to NanoIDP

Thank you for your interest in contributing to NanoIDP!

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

**Caution:** a run against a live server persists configuration changes back to that server's `config/settings.yaml` (resolved `${PORT}` placeholders, cleared `default_acs_url`). If the server runs from a git checkout, restore the file before committing: `git checkout -- config/settings.yaml`.

## Code Quality

```bash
# Format code
black src tests

# Lint code
ruff check src tests

# Fix linting issues automatically
ruff check --fix src tests
```

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

NanoIDP uses GitHub Actions for automated releases to both PyPI and GHCR.

```bash
# 1. Update version in pyproject.toml
# 2. Update CHANGELOG.md
# 3. Commit changes
git add -A && git commit -m "Release v1.0.1"

# 4. Create and push tag
git tag v1.0.1
git push origin main --tags
```

The workflow automatically:

1. Runs all tests
2. Builds the package
3. Publishes to TestPyPI
4. Publishes to PyPI (only for non-prerelease tags)
5. Builds and publishes Docker images to GHCR

Container tags are derived from the git tag (for example `v1.0.1`); the `latest` tag is only published for non-prerelease tags.

### Pre-release Testing

For testing releases before publishing to PyPI:

```bash
# Create a pre-release tag (publishes to TestPyPI and GHCR)
git tag v1.0.1-rc1
git push origin v1.0.1-rc1

# Install from TestPyPI to verify
pip install -i https://test.pypi.org/simple/ nanoidp==1.0.1rc1
```

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
