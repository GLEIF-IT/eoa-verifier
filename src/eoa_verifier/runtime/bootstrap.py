"""Prepare trust scope, packaged schemas and identity before task composition."""

import json
from pathlib import Path

from ..persistence.records import VerificationScope
from ..verification.schema_cache import pin_accepted_schemas


def bootstrap_service(config, hby, scope_store):
    """Validate persisted scope, install schemas and return the service habitat.

    The caller owns all stores and has not started workers. Inception options
    affect only a newly created identity; KERIpy startup failures propagate to
    the outer resource contexts, which close previously acquired stores.
    """
    bind_verification_scope(
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


def bind_verification_scope(scope_store, *, trusted_geda_aid, chain_id):
    """Bind one store to its trust/network policy using a single scope record.

    Existing stores require an exact scope match. A new scope is initialized only
    in an empty store; startup never audits nonce or association history.
    """
    scope = VerificationScope(trusted_geda_aid, chain_id, "nonce-key-v1")
    existing = scope_store.scope()
    if existing is not None:
        if existing != scope:
            raise ValueError(
                "verifier store belongs to another GEDA root, chain or acceptance policy"
            )
        return
    if scope_store.has_history():
        raise ValueError("verifier store has unscoped results; use separate stores")
    scope_store.bind_scope(scope)
