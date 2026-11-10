"""Acceptance policy and its persistent delivery obligation."""

import json
from dataclasses import asdict

import pytest

from eoa_verifier.associations.accepting import AcceptanceService
from eoa_verifier.associations.evidence import AssociationEvidence
from eoa_verifier.persistence.associations import AssociationReader, AssociationWriter
from eoa_verifier.persistence.records import (
    DestinationSchedule,
    VerificationRecord,
    VerificationResult,
)
from eoa_verifier.persistence.verification import VerificationReader
from tests.support.acceptance import (
    accept_verified_result,
    acceptance_service,
    chain_registry,
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
            sources={"le": "le", "qvi": "qvi"},
            destination="https://receiver.example/hook",
        )
    assert baser.associations.get(keys=("rejected",)) is None
    assert list(baser.outbox.getItemIter()) == []


def scheduled_acceptance(baser, rgy):
    """Compose the scheduled acceptance path over seeded KERIpy facts."""
    return AcceptanceService(
        AssociationReader(baser),
        AssociationWriter(baser),
        AssociationEvidence(rgy),
        verification_reader=VerificationReader(baser),
        destination="https://receiver.example/hook",
    )


CHAIN = {
    "association": {"le": {"n": "le"}},
    "le": {"qvi": {"n": "qvi"}},
    "qvi": {},
}
ISSUED = {"association": "iss", "le": "iss", "qvi": "iss"}


def test_scheduled_acceptance_records_verified_chain(verified_store):
    """Issued association, LE and QVI evidence accept and write both source links."""
    baser = verified_store
    scheduled_acceptance(baser, chain_registry(CHAIN, ISSUED)).process_one()
    assert baser.associations.get(keys=("association",)).status == "accepted"
    assert baser.source_links.get(keys=("le", "association")) == "le"
    assert baser.source_links.get(keys=("qvi", "association")) == "qvi"


@pytest.mark.parametrize(
    "credential,label",
    [("association", "association"), ("le", "LE"), ("qvi", "QVI")],
)
def test_revoked_chain_credential_rejects_acceptance_terminally(
    verified_store, credential, label
):
    """A revocation seen after verification rejects; no nonce, event, link or dead letter."""
    baser = verified_store
    states = dict(ISSUED, **{credential: "rev"})
    scheduled_acceptance(baser, chain_registry(CHAIN, states)).process_one()
    status = baser.associations.get(keys=("association",))
    assert status.status == "rejected" and status.eventId == ""
    assert status.reason == f"{label} credential {credential} is revoked"
    assert status.accountObservation["wallet"] == "0x" + "12" * 20
    assert AssociationReader(baser).acceptance() is None
    assert baser.acceptance_dead.cntAll() == 0
    assert baser.accepted_nonces.cntAll() == 0
    assert baser.source_links.cntAll() == 0
    assert baser.outbox.cntAll() == 0
    assert baser.results.get(keys=("association",)).status == "verified"


@pytest.mark.parametrize("source", ["association", "le", "qvi"])
@pytest.mark.parametrize("change", ["state-missing", "body-missing"])
def test_missing_chain_evidence_stops_in_acceptance_dead_letter(
    verified_store, source, change
):
    """Absent evidence stays recoverable: no terminal status, nonce, link or event."""
    baser = verified_store
    credentials = dict(CHAIN)
    states = dict(ISSUED)
    if change == "state-missing":
        del states[source]
    else:
        del credentials[source]
    scheduled_acceptance(baser, chain_registry(credentials, states)).process_one()
    dead = baser.acceptance_dead.get(keys=("association",))
    assert dead.reason == "issuance evidence missing before acceptance"
    assert baser.associations.get(keys=("association",)) is None
    assert baser.accepted_nonces.cntAll() == 0
    assert baser.source_links.cntAll() == 0
    assert baser.outbox.cntAll() == 0
