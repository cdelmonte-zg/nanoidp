"""
Typed exceptions for NanoIDP.

This module once declared a 20-class hierarchy (base NanoIDPError, per-domain
subclasses with error codes) of which exactly one class was ever raised or
caught; routes shape their errors per surface instead - RFC 6749 §5.2 JSON on
the OAuth endpoints, flash messages in the UI, SAML Status / SOAP Fault on
the SAML endpoints, the layered result shapes in the MCP server (see
CONTRIBUTING, "Error surfaces"). The dead hierarchy was removed in #287
rather than retrofitted: an exception taxonomy nothing raises is
documentation that lies.
"""


class SAMLSignatureError(Exception):
    """Raised when SAML request signature validation fails
    (services/saml_verification.py); callers render str(e) into their
    surface's own error shape."""

    def __init__(self, message: str = "SAML signature validation failed") -> None:
        self.message = message
        super().__init__(message)
