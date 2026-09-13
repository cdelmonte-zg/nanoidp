"""
TOTP verification for the declarative second factor (#348).

Stdlib only - no new dependency. This is a demo factor, not IdP hardening
(VISION principle 1): there is no enrolment, no challenge store, and no
replay protection. A secret is a plain field of the user entry
(``User.totp_secret``); its presence is the enrolment.

RFC 4226 (HOTP) defines the HMAC-based counter algorithm and the dynamic
truncation this module implements in ``_hotp``. RFC 6238 (TOTP) layers a
30-second time step on top of it as the counter; ``verify_totp`` is that
layer, checked at one step of clock skew either side. Six digits, SHA-1 -
the parameters every authenticator app assumes when a provisioning URI
names none, and the only ones this feature offers (the settings
description says so), which is why nothing here is parameterised beyond
the reference instant.

Deliberately no replay memory (out of scope, #348): the same code verifies
more than once within its 30-second step. A production TOTP implementation
would record the last accepted counter per enrollment and refuse a repeat;
that needs a store, which this declarative feature does not have.
"""

import hmac
import struct
import time
from hashlib import sha1
from typing import Optional

from ..totp_secret import normalize_secret

DIGITS = 6
PERIOD = 30
SKEW_STEPS = 1


def _hotp(key: bytes, counter: int) -> str:
    """RFC 4226 §5.3: HMAC-SHA1 over the counter, then dynamic truncation."""
    digest = hmac.new(key, struct.pack(">Q", counter), sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = (
        (digest[offset] & 0x7F) << 24
        | (digest[offset + 1] & 0xFF) << 16
        | (digest[offset + 2] & 0xFF) << 8
        | (digest[offset + 3] & 0xFF)
    )
    return str(truncated % (10**DIGITS)).zfill(DIGITS)


def generate_totp(secret: str, *, at: Optional[float] = None) -> str:
    """The TOTP code for ``secret`` at ``at`` (default: now). For tests,
    which need to compute the expected code for a known secret."""
    counter = int((at if at is not None else time.time()) // PERIOD)
    return _hotp(normalize_secret(secret), max(counter, 0))


def verify_totp(secret: str, code: str, *, at: Optional[float] = None) -> bool:
    """RFC 6238 §4: accept ``code`` if it matches the time step at ``at``
    (default: now) or one step either side.

    ``code`` must be exactly six ASCII digits before any HMAC is computed -
    a malformed submission is rejected outright rather than compared.
    ``str.isdigit()`` alone is not enough: it is also true for fullwidth
    (e.g. "１２３４５６"), Arabic-Indic and superscript digits, none of
    which are legal ``hmac.compare_digest`` arguments (a non-ASCII ``str``
    raises ``TypeError`` there), so ``isascii()`` is checked first (#348
    review, blocking 1). A secret that does not decode returns False rather
    than raising, so a login can never 500 on it (the model rejects such a
    secret at load, so this is defence in depth). Steps before the epoch
    are skipped rather than packed as a negative counter. No replay memory
    (module docstring).
    """
    if len(code) != DIGITS or not code.isascii() or not code.isdigit():
        return False
    try:
        key = normalize_secret(secret)
    except ValueError:
        return False
    counter = int((at if at is not None else time.time()) // PERIOD)
    for step in range(-SKEW_STEPS, SKEW_STEPS + 1):
        if counter + step < 0:
            continue
        if hmac.compare_digest(_hotp(key, counter + step), code):
            return True
    return False
