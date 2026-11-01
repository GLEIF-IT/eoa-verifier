"""Acceptance policy and its persistent delivery obligation."""

import json
from dataclasses import asdict

import pytest

from eoa_verifier.persistence.associations import AssociationReader
from eoa_verifier.persistence.records import (
    DestinationSchedule,
    VerificationRecord,
    VerificationResult,
)
from tests.support.acceptance import (
    accept_verified_result,
    acceptance_service,
)
from tests.support.persistence import enqueue_verification
from tests.support.services import delivery_service, verification_service


def test_acceptance_and_delivery_progress_survive_reopen(verified_store):
    """Reopen a completed result, accept once, and retain event/cooldown state on replay."""
    baser = verified_store
    baser.close()
    baser.reopen()
    associationStatus = accept_verified_result(baser)
    assert AssociationReader(baser).acceptance() is None
    assert baser.delivery_ready.get(keys=(associationStatus.eventId,)) is not None
    delivery_service(baser).record_attempt(associationStatus.eventId)
    delivery_service(baser).defer(associationStatus.eventId, error="connection failed")
    delivery = baser.outbox.get(keys=(associationStatus.eventId,))
    # The durable bytes are the public status event, not the internal result row.
    assert json.loads(delivery.body) == {
        "version": "1",
        "eventId": "association:1",
        "associationSaid": "association",
        "statusRevision": 1,
        "status": "accepted",
        "association": associationStatus.association,
        "accountObservation": associationStatus.accountObservation,
    }
    schedule = DestinationSchedule(failures=3, nextAttemptAt=4000000000)
    baser.destinations.pin(keys=(delivery.destination,), val=schedule)
    baser.close()
    baser.reopen()
    assert asdict(accept_verified_result(baser)) == asdict(associationStatus)
    assert baser.outbox.get(keys=(associationStatus.eventId,)) == delivery
    assert baser.destinations.get(keys=(delivery.destination,)) == schedule

    # The delivery component calls completion only after validating an ACK.
    delivery_service(baser).complete(associationStatus.eventId)
    assert baser.outbox.get(keys=(associationStatus.eventId,)).delivered
    assert baser.destinations.get(keys=(delivery.destination,)).failures == 0


def test_rejected_result_cannot_create_acceptance_or_event(verified_store):
    """Rejected verification remains inspectable and never produces a success event."""
    baser = verified_store
    enqueue_verification(baser, VerificationRecord("rejected", "grant"))
    verificationService = verification_service(baser)
    verificationService.start_pending(verificationService.next_pending())
    verification_service(baser).finish(
        VerificationResult("rejected", "rejected", "wrong schema")
    )
    with pytest.raises(ValueError, match="verified result"):
        acceptance_service(baser).accept(
            "rejected",
            associationFacts={"issuerAid": "issuer"},
            nonce="other",
            destination="https://receiver.example/hook",
        )
    assert baser.associations.get(keys=("rejected",)) is None
    assert list(baser.outbox.getItemIter()) == []
