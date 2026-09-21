"""The activation step of a load, for everything the configuration governs
in ``services`` (#359, #354).

Handed to ``init_config(activate=...)`` by each process composition (the
Flask app and the MCP server). Given the candidate settings it prepares, in
order, the runtime store and the signing service, before anything is
committed, and touching nothing global: any failure refuses the
configuration and leaves what is in use as it is. What it returns publishes
both, once the load can no longer fail, and before the settings are
assigned, so that a reader that takes the settings first and a service
second never pairs newer settings with an older service.

The runtime store comes first. It is the cheaper of the two to prepare, and
it is where a restart can be required: a configuration asking for another
store is refused before a signing service is built for it.
"""

from typing import Callable

from ..config import Settings
from .crypto import activate_crypto_service
from .runtime_store import activate_runtime_store


def activate_services(settings: Settings) -> Callable[[], None]:
    publish_store = activate_runtime_store(settings)
    publish_signing = activate_crypto_service(settings)

    def publish() -> None:
        publish_store()
        publish_signing()

    return publish
