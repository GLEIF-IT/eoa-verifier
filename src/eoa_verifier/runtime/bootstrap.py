"""Record startup settings and prepare packaged schemas and identity."""

import json
import logging
from pathlib import Path

from ..persistence.records import VerificationScope
from ..verification.schema_cache import pin_accepted_schemas

logger = logging.getLogger(__name__)


def bootstrap_service(config, hby, scope_store):
    """Note changed settings, install schemas and return the service habitat.

    The caller owns all stores and has not started workers. Inception options
    affect only a newly created identity; KERIpy startup failures propagate to
    the outer resource contexts, which close previously acquired stores.
    """
    note_config(
        scope_store,
        trusted_geda_aid=config.trusted_geda_aid,
        chain_id=config.chain_id,
    )
    inits = {
        "transferable": True,
        "icount": 1,
        "isith": "1",
        "ncount": 1,
        "nsith": "1",
        "wits": [],
        "toad": 0,
    }
    if config.incept_file:
        extra = json.loads(Path(config.incept_file).read_text())
        if not isinstance(extra, dict):
            raise ValueError("incept file must contain a JSON object")
        inits.update(extra)

    pin_accepted_schemas(hby)
    hab = hby.habByName(config.alias) or hby.makeHab(name=config.alias, **inits)
    return hab


def note_config(scope_store, *, trusted_geda_aid, chain_id):
    """Warn on changed trust/network settings and save the latest startup baseline.

    The operator owns the decision to reuse stored state. This does not inspect,
    revalidate or reset verification results, associations, nonces or delivery work.
    """
    scope = VerificationScope(trusted_geda_aid, chain_id)
    previous = scope_store.get()
    if previous is not None and previous != scope:
        logger.warning(
            "Verifier startup settings changed: previous=%s current=%s. "
            "Continuing with retained state; store compatibility is the operator's responsibility.",
            previous,
            scope,
        )
    scope_store.save(scope)
