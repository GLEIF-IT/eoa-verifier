"""Revocation rejects a missing original delivery obligation."""

import pytest

from tests.support.acceptance import (
    accept_verified_result,
    revocation_service,
)


def test_missing_original_delivery_cannot_silently_revoke_locally(verified_store):
    """Local-only acceptance is explicit; a lost delivery obligation is corruption."""
    baser = verified_store
    associationStatus = accept_verified_result(baser)
    baser.outbox.rem(keys=(associationStatus.eventId,))
    with pytest.raises(ValueError, match="delivery event is absent"):
        revocation_service(baser).apply_revocation("association")
    assert baser.associations.get(keys=("association",)) == associationStatus
    assert baser.accepted_nonces.cntAll() == 1
