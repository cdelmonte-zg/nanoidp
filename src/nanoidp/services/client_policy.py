"""How a client's authentication method and secret go together (#300).

One rule, written four times before this: a public client
(``token_endpoint_auth_method`` ``none``) has no secret, and a confidential
one cannot be without it. The UI create form, the UI edit form, MCP
``create_client`` and MCP ``update_client`` each normalized it themselves,
with the reasoning repeated in a comment at every site.

What is deliberately NOT here is the rest of what ``is_public`` decides -
PKCE at ``/authorize``, the refusal at ``/introspect``, the ownership check
at ``/revoke``, the channel rule at ``/device_authorization``, forced
refresh rotation, and so on. Those are ten different rules that share a
predicate, not one policy written ten times: each belongs next to the
endpoint that applies it, where it is read together with the RFC it comes
from. #300 has the table.

The model keeps its own validator: ``confidential => secret required`` is
enforced on ``OAuthClient`` as the last barrier. This module normalizes the
inputs before a client exists, or before an existing one is mutated, which
is why it is not a method on the model.
"""

from dataclasses import dataclass
from typing import Any, Optional

from ..models import OAuthClient

#: "Not provided", told apart from "provided empty" - the two are different
#: questions and the callers do not answer them alike: an omitted secret
#: keeps the current one, an empty one is an attempt to clear it.
UNSET: Any = object()

PUBLIC_METHOD = "none"
DEFAULT_METHOD = "client_secret_basic"

SECRET_REQUIRED = "client_secret is required unless token_endpoint_auth_method is 'none'"


class ClientSecretRequired(ValueError):
    """A confidential client was asked for without a secret.

    Raised rather than returned so that no caller can build a client from a
    state that was refused. Each surface words it for its own audience: the
    UI flashes its sentence, MCP answers with its own.
    """

    def __init__(self, message: str = SECRET_REQUIRED) -> None:
        super().__init__(message)


@dataclass(frozen=True)
class ClientAuthState:
    """The pair as it will be persisted: the method, and the secret that
    goes with it - always ``None`` for a public client."""

    method: str
    secret: Optional[str]

    @property
    def is_public(self) -> bool:
        return self.method == PUBLIC_METHOD


def resolve_client_auth(
    *,
    method: Any = UNSET,
    secret: Any = UNSET,
    current_method: Optional[str] = None,
    current_secret: Optional[str] = None,
) -> ClientAuthState:
    """The method and secret to persist, from what was provided and what is
    already there.

    An omitted method keeps the current one, or the default for a client
    that does not exist yet. A public target drops the secret, supplied or
    stored: a dead, ignored value must not be persisted (#188, #254 review).
    A confidential target without a secret is refused.

    What a blank field means is the caller's convention, not this
    function's: the UI's edit form treats it as "unchanged" (#131) and
    passes ``UNSET``, while MCP passes the empty value it was given, which
    is an attempt to clear.
    """
    effective_method = method if method is not UNSET and method is not None else current_method
    if effective_method is None:
        effective_method = DEFAULT_METHOD

    if effective_method == PUBLIC_METHOD:
        return ClientAuthState(PUBLIC_METHOD, None)

    effective_secret = secret if secret is not UNSET else current_secret
    if not effective_secret:
        raise ClientSecretRequired()
    return ClientAuthState(effective_method, effective_secret)


def apply_client_auth(client: OAuthClient, auth: ClientAuthState) -> None:
    """Move an existing client to this state without the model refusing a
    half-applied one on the way.

    ``OAuthClient`` validates on assignment (#188), so the order is the
    rule: a public target sets the method first, since clearing the secret
    is only valid once the method allows it; a confidential target sets the
    secret first, since flipping the method first would be refused while
    the old secret is still absent or empty.
    """
    if auth.is_public:
        client.token_endpoint_auth_method = auth.method  # type: ignore[assignment]
        client.client_secret = None
        return
    client.client_secret = auth.secret
    client.token_endpoint_auth_method = auth.method  # type: ignore[assignment]
