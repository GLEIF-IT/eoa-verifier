"""Qualification receiver policy is independent of HTTP and post-commit faults."""

import pytest
from keri.db import dbing

from scripts.integration.receiver import ReceiptConflict, ReceiptService, ReceiptStore


def test_receipts_are_immutable_and_diagnostics_are_detached():
    """Duplicate attempts count once each; conflicting bytes cannot replace a receipt."""
    with dbing.openLMDB() as db:
        receipts = ReceiptService(ReceiptStore(db))
        body = b'{"eventId":"credential:1","status":"accepted"}'
        assert receipts.receive(body) == "credential:1"
        assert receipts.receive(body) == "credential:1"
        with pytest.raises(ReceiptConflict):
            receipts.receive(b'{"eventId":"credential:1","status":"revoked"}')
        rows = receipts.receipts()
        assert "(no active readers)" in db.env.readers()
    assert rows == [{"eventId": "credential:1", "body": body.decode(), "attempts": 2}]
