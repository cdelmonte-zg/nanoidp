"""
NanoIDP - Lightweight Identity Provider
=======================================
A configurable identity provider for testing OAuth2/OIDC and SAML integrations.

Features:
- OAuth2 token endpoint with password and client_credentials grants
- OIDC discovery and JWKS endpoints
- SAML SSO and metadata endpoints
- Configurable users with custom attributes
- Web UI for monitoring and testing
"""
import re
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path


def _read_version_from_pyproject() -> str | None:
    """Best-effort ``version`` read from the repo's ``pyproject.toml``, for a
    source tree used without an installed distribution (e.g. vendored, or
    copied into a container image without ``pip install``) where
    ``importlib.metadata.version()`` has nothing to find.

    No TOML parser: ``tomllib`` is stdlib-only from Python 3.11 and this
    project still supports 3.10, so this scans for the ``[project]`` table's
    ``version = "..."`` line by hand instead of adding a dependency just for
    this fallback.
    """
    pyproject_path = Path(__file__).resolve().parent.parent.parent / "pyproject.toml"
    try:
        text = pyproject_path.read_text()
    except OSError:
        return None

    in_project_table = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_project_table = stripped == "[project]"
            continue
        if in_project_table:
            match = re.match(r'version\s*=\s*"([^"]+)"', stripped)
            if match:
                return match.group(1)
    return None


try:
    __version__ = version("nanoidp")
except PackageNotFoundError:
    __version__ = _read_version_from_pyproject() or "0.0.0+unknown"

__author__ = "NanoIDP Contributors"
