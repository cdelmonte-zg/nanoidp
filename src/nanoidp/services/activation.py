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

import logging
from pathlib import Path
from typing import Callable, Optional

from ..config import ConfigManager, Settings
from .crypto import activate_crypto_service
from .dynamic_registration import prune_stale_registrations
from .identities import identities_for, reconcile_runtime_identities
from .runtime_store import activate_runtime_store

logger = logging.getLogger(__name__)


def activate_services(settings: Settings, config_dir: Optional[Path] = None) -> Callable[[], None]:
    # The configuration directory: a SQLite store's file is resolved against
    # it, and must lie outside it (#354, step 4c).
    publish_store = activate_runtime_store(settings, config_dir)
    publish_signing = activate_crypto_service(settings, config_dir)

    def publish() -> None:
        publish_store()
        publish_signing()

    return publish


def after_load_services(config: ConfigManager) -> None:
    """What runs after every successful configuration load, in order.

    Handed to ``init_config(after_load=...)`` by each process composition,
    the Flask app and the MCP server, like ``activate_services``: a load is
    a load whichever process makes it (#432). The MCP server loaded without
    this step until then, so over a store it shares with a server an object
    it promoted was not retired by its own reload, and the server's next
    load removed it as a collision.

    The reconciliation retires runtime identities the file now declares
    (#235/#192); the sweep then drops the registration records whose runtime
    client that just removed (#190). They are composed here, for both
    compositions, rather than by teaching either side about the other:
    ``services.identities`` knows nothing about registration, and the
    registration service knows nothing about when a load happens.

    The order matters. A promotion is exactly the case where a record would
    otherwise outlive its client without anyone noticing: the lazy checks
    only fire when someone asks for that registration, so until then the
    record would still be there to be inherited by the next client to hold
    the name.

    ``after_load`` runs post-commit and must not raise (config.py), so the
    sweep is best effort, like the reconciliation it follows.
    """
    reconcile_runtime_identities(config)
    try:
        # The configuration this load committed: the sweep follows it.
        prune_stale_registrations(identities_for(config, config.snapshot))
    except Exception:  # pragma: no cover - defensive, same contract as above
        logger.exception(
            "Could not sweep dynamic registration records after a config load"
        )
