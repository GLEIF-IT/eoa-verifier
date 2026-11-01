"""persistence/test_basing.py."""

import json
from dataclasses import asdict
from unittest.mock import patch

import pytest
from keri.db import dbing

from eoa_verifier.persistence.basing import VerifierBaser
from eoa_verifier.persistence.records import (
    DestinationSchedule,
    PendingVerification,
    VerificationResult,
)
from tests.support.acceptance import accept_verified_result


def test_duplicates_completion_and_restart(tmp_path):
    """Retain first Grants, results and waiting information across reopen."""
    baser = VerifierBaser(name="work", headDirPath=str(tmp_path), temp=False)
    try:
        work = PendingVerification("a", "first")
        assert baser.enqueue(work)
        work = baser.next_verification(now=0)
        baser.defer_verification(work, reason="missing source", next_attempt_at=5)
        assert not baser.enqueue(PendingVerification("a", "duplicate"))
        baser.enqueue(PendingVerification("b", "first"))
        result = VerificationResult(
            "b",
            "verified",
            eoaResult={"wallet": "wallet", "accountObservation": {"chainId": 31337}},
        )
        baser.next_verification(now=0)
        baser.finish(result)
        baser.finish(result)
        with pytest.raises(ValueError, match="conflicting"):
            baser.finish(VerificationResult("b", "rejected", "wrong"))
        assert not baser.enqueue(PendingVerification("b", "duplicate"))
        baser.close()
        baser.reopen()
        assert baser.waiting.get(keys=("a",)) == PendingVerification(
            "a", "first", "missing source", 1, 5
        )
        assert baser.pending.get(keys=("b",)) is None
        assert baser.results.get(keys=("b",)) == result
        assert baser.next_acceptance() == result
    finally:
        baser.close()


def test_completion_rollback_after_result_write():
    """A failure deleting pending work rolls back the result written in the same transaction."""
    with dbing.openLMDB(cls=VerifierBaser) as baser:
        work = PendingVerification("a", "first")
        baser.enqueue(work)
        work = baser.next_verification(now=0)
        real_env = baser.env

        class FailingTransaction:
            """Delegate commit/abort to LMDB, injecting failure only at pending deletion."""

            def __enter__(self):
                self.txn = real_env.begin(write=True)
                self.txn.__enter__()
                return self

            def __exit__(self, *args):
                return self.txn.__exit__(*args)

            def get(self, *args, **kwa):
                return self.txn.get(*args, **kwa)

            def put(self, *args, **kwa):
                return self.txn.put(*args, **kwa)

            def delete(self, *args, **kwa):
                raise RuntimeError("between writes")

        class FailingEnvironment:
            """Supply the transaction fault without changing LMDB commit semantics."""

            def begin(self, **kwa):
                return FailingTransaction()

        with (
            patch.object(baser, "env", FailingEnvironment()),
            pytest.raises(RuntimeError, match="between writes"),
        ):
            baser.finish(VerificationResult("a", "verified"))
        assert baser.verifying.get(keys=("a",)) == work
        assert baser.results.get(keys=("a",)) is None
        assert baser.accepting.cntAll() == 0
        baser.finish(VerificationResult("a", "rejected", "invalid proof"))
        assert baser.pending.get(keys=("a",)) is None
        assert baser.results.get(keys=("a",)).reason == "invalid proof"


def test_acceptance_and_delivery_progress_survive_reopen(verified_store):
    """Reopen a completed result, accept once, and retain event/cooldown state on replay."""
    baser = verified_store
    baser.close()
    baser.reopen()
    accepted = accept_verified_result(baser)
    assert baser.next_acceptance() is None
    assert baser.delivery_ready.get(keys=(accepted.eventId,)) is not None
    baser.record_attempt(accepted.eventId)
    baser.delivery_result(accepted.eventId, error="connection failed")
    event = baser.outbox.get(keys=(accepted.eventId,))
    # The durable bytes are the public status event, not the internal result row.
    assert json.loads(event.body) == {
        "version": "1",
        "eventId": "association:1",
        "associationSaid": "association",
        "statusRevision": 1,
        "status": "accepted",
        "association": accepted.association,
        "accountObservation": accepted.accountObservation,
    }
    schedule = DestinationSchedule(failures=3, nextAttemptAt=4000000000)
    baser.destinations.pin(keys=(event.destination,), val=schedule)
    baser.close()
    baser.reopen()
    assert asdict(accept_verified_result(baser)) == asdict(accepted)
    assert baser.outbox.get(keys=(accepted.eventId,)) == event
    assert baser.destinations.get(keys=(event.destination,)) == schedule

    # The delivery component calls completion only after validating an ACK.
    baser.delivery_result(accepted.eventId)
    assert baser.outbox.get(keys=(accepted.eventId,)).acknowledged
    assert baser.destinations.get(keys=(event.destination,)).failures == 0


def test_failed_acceptance_rolls_back_status_and_event(verified_store):
    """A failure after the status write leaves only the completed verification result."""
    baser = verified_store
    with (
        patch.object(
            baser.outbox, "serializer", side_effect=RuntimeError("write failed")
        ),
        pytest.raises(RuntimeError),
    ):
        accept_verified_result(baser)
    assert baser.associations.get(keys=("association",)) is None
    assert baser.accepted_nonces.cntAll() == 0
    assert list(baser.outbox.getItemIter()) == []
    assert baser.results.get(keys=("association",)).status == "verified"
    assert accept_verified_result(baser).status == "accepted"


def test_rejected_result_cannot_create_acceptance_or_event(verified_store):
    """Rejected verification remains inspectable and never produces a success event."""
    baser = verified_store
    baser.enqueue(PendingVerification("rejected", "grant"))
    baser.next_verification(now=0)
    baser.finish(VerificationResult("rejected", "rejected", "wrong schema"))
    with pytest.raises(ValueError, match="verified result"):
        baser.accept(
            "rejected",
            association={"issuerAid": "issuer"},
            nonce="other",
            destination="https://receiver.example/hook",
            peer_aid="peer",
        )
    assert baser.associations.get(keys=("rejected",)) is None
    assert list(baser.outbox.getItemIter()) == []


def test_missing_original_delivery_cannot_silently_retire_locally(verified_store):
    """Local-only acceptance is explicit; a lost delivery obligation is corruption."""
    baser = verified_store
    accepted = accept_verified_result(baser)
    baser.outbox.rem(keys=(accepted.eventId,))
    with pytest.raises(ValueError, match="delivery event is absent"):
        baser.retire("association")
    assert baser.associations.get(keys=("association",)) == accepted
    assert baser.accepted_nonces.cntAll() == 1
