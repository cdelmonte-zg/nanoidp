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

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
