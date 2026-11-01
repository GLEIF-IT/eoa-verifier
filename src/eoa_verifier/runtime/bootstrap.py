"""Prepare trust scope, packaged schemas and identity before task composition."""

import json
from pathlib import Path

from ..associations.integrity import AssociationIntegrity
from ..verification.schema_cache import pin_accepted_schemas


def bootstrap_service(config, hby, reader, writer):
    """Validate persisted scope/history, install schemas and return the service habitat.

    The caller owns all stores and has not started workers. Inception options
    affect only a newly created identity; KERIpy startup failures propagate to
    the outer resource contexts, which close previously acquired stores.
    """
    AssociationIntegrity(reader, writer).bind_verification_scope(
        trusted_geda_aid=config.trusted_geda_aid, chain_id=config.chain_id
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
