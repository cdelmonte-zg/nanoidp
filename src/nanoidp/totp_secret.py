"""
Base32 TOTP secret normalization, shared by the ``User`` model validator
and the ``services.totp`` verification service (#348).

Framework-free and stdlib-only, following the same pattern as
``security.py`` (#286): the ``User`` model is a layer below ``services``
in the import-linter contract (``routes -> services -> config``), so
``models.py`` cannot import ``services.totp`` without breaking it - even a
deferred, in-function import is a static edge ``lint-imports`` flags. This
leaf module lets both sides depend on it instead of on each other, so the
accepted alphabet AND the canonical spelling are defined once: the model
stores ``canonical_secret``, and ``normalize_secret`` decodes from it.
"""

import base64


def canonical_secret(raw: str) -> str:
    """The one spelling of a Base32 secret: upper-case, no spaces, no
    padding. Raises ``ValueError`` unless the result decodes as Base32.

    Tolerant of case, of spaces (authenticator apps display secrets in
    groups of four) and of missing padding - the forms an operator is
    likely to copy from a provisioning URI or type by hand. Anything that
    still fails to decode is rejected: this is the one place "Base32 or
    rejected" (the issue's validation rule) is implemented. The message
    never repeats the value: a near-valid secret with one wrong character
    is still a secret, and this message reaches startup logs and the MCP
    reload result.
    """
    cleaned = raw.strip().replace(" ", "").upper().rstrip("=")
    if not cleaned:
        raise ValueError("totp_secret must not be empty")
    try:
        base64.b32decode(cleaned + "=" * ((-len(cleaned)) % 8), casefold=True)
    except Exception as e:
        raise ValueError("totp_secret is not valid Base32") from e
    return cleaned


def normalize_secret(raw: str) -> bytes:
    """Decode a Base32 TOTP secret to raw key bytes, or raise ``ValueError``."""
    cleaned = canonical_secret(raw)
    return base64.b32decode(cleaned + "=" * ((-len(cleaned)) % 8), casefold=True)
