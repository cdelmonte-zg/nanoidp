"""The activation step of a load, for everything the configuration governs
in ``services`` (#359, #354).

Handed to ``init_config(activate=...)`` by each process composition (the
Flask app and the MCP server). Given the candidate settings it prepares, in
order, the runtime store and the signing service, before anything is
committed, and activates neither: any failure refuses the configuration and
leaves what is in use as it is. (Preparing the first memory store may bring
the provisional store into existence, which activates nothing: see
``runtime_store.prepare_runtime_store``.) What it returns publishes both, once
the load can no longer fail, and before the settings are assigned, so that a
reader that takes the settings first and a service second never pairs newer
settings with an older service.

The runtime store comes first. It is the cheaper of the two to prepare, and
it is where a restart can be required: a configuration asking for another
store is refused before a signing service is built for it.
"""

from pathlib import Path
from typing import Callable, Optional

from ..config import Settings
from .crypto import activate_crypto_service
from .runtime_store import activate_runtime_store


def activate_services(settings: Settings, config_dir: Optional[Path] = None) -> Callable[[], None]:
    # The configuration directory: a SQLite store's file is resolved against
    # it, and must lie outside it (#354, step 4c).
    publish_store = activate_runtime_store(settings, config_dir)
    publish_signing = activate_crypto_service(settings, config_dir)

    def publish() -> None:
        publish_store()
        publish_signing()

    return publish
