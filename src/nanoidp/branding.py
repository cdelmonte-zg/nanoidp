"""Per-client login page branding utilities."""

import os
import re
from typing import Optional

_LOGO_EXTENSIONS = (".svg", ".png", ".jpg", ".jpeg", ".webp")
_SAFE_CLIENT_ID = re.compile(r"[a-zA-Z0-9_-]+")


def resolve_client_logo(logos_dir: str, client_id: str) -> Optional[str]:
    """Return the filename of client_id's local logo, or None.

    Ensures path-traversal safety by validating client_id against a charset
    whitelist before building a filesystem path.

    Args:
        logos_dir: Absolute or relative path to the logos directory.
        client_id: The OAuth client ID.

    Returns:
        A filename like "client-1.svg", or None if no logo found.
    """
    if not _SAFE_CLIENT_ID.fullmatch(client_id):
        return None
    logos_path = os.path.abspath(logos_dir)
    for ext in _LOGO_EXTENSIONS:
        filename = f"{client_id}{ext}"
        path = os.path.join(logos_path, filename)
        if os.path.isfile(path):
            return filename
    return None


def effective_logos_dir(logos_dir: Optional[str], static_folder: Optional[str]) -> str:
    """Resolve the configured logos directory, falling back to the app's static/logos.

    Shared by the /authorize logo lookup, the logo-serving route, and the
    clients form's help text, so all three always agree (#150 review).
    """
    return logos_dir or os.path.join(static_folder or "static", "logos")
