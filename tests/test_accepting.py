"""Acceptance/outbox transactions and public stored status; verified association facts are tested end to end."""

import json

from dataclasses import asdict
from unittest.mock import patch

import falcon
import pytest
from falcon.testing import TestClient
from keri.db import dbing

from eoa_verifier.persistence.basing import VerifierBaser
from eoa_verifier.persistence.records import (
    DestinationSchedule,
    PendingVerification,
    VerificationResult,
)
from eoa_verifier.associations.statusing import StatusEnd


@pytest.fixture
def verified_store(tmp_path):
    """Yield durable initial results; these fixture facts are not cryptographic evidence."""
    with dbing.openLMDB(
        cls=VerifierBaser, name="acceptance", headDirPath=str(tmp_path), temp=False
    ) as baser:
        baser.enqueue(PendingVerification("association", "grant"))
        baser.finish(
            VerificationResult(
                "association",
                "verified",
                eoaResult={
                    "wallet": "0x" + "12" * 20,
                    "accountObservation": {
                        "chainId": 31337,
                        "blockNumber": 42,
                        "blockHash": "0x" + "34" * 32,
                        "code": "0x",
                        "observedAt": "2000-01-01T00:00:00Z",
                    },
                },
            )
        )
        yield baser


def accept_verified_result(baser):
    """Commit one known initial result with minimal association facts and target."""
    return baser.accept(
        "association",
        association={
            "issuerAid": "issuer",
            "leSaid": "le",
            "extId": "eip155:31337:0x" + "12" * 20,
            "issuanceAnchor": {"sequenceNumber": 3, "said": "anchor"},
        },
        destination="https://receiver.example/hook",
        peer_aid="peer",
    )


def test_acceptance_and_delivery_progress_survive_reopen(verified_store):
    """Reopen a completed result, accept once, and retain event/cooldown state on replay."""
    baser = verified_store
    baser.close()
    baser.reopen()
    accepted = accept_verified_result(baser)
    baser.record_attempt(accepted.eventId)
    baser.delivery_result(accepted.eventId, error="connection failed")
    event = baser.outbox.get(keys=(accepted.eventId,))
    # The durable bytes are the public status event, not the internal result row.
    assert json.loads(event.body) == {
        "version": "1", "eventId": "association:1",
        "associationSaid": "association", "statusRevision": 1,
        "status": "accepted", "association": accepted.association,
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
    assert list(baser.outbox.getItemIter()) == []
    assert baser.results.get(keys=("association",)).status == "verified"
    assert accept_verified_result(baser).status == "accepted"


def test_rejected_result_cannot_create_acceptance_or_event(verified_store):
    """Rejected verification remains inspectable and never produces a success event."""
    baser = verified_store
    baser.enqueue(PendingVerification("rejected", "grant"))
    baser.finish(VerificationResult("rejected", "rejected", "wrong schema"))
    with pytest.raises(ValueError, match="verified result"):
        baser.accept(
            "rejected",
            association={},
            destination="https://receiver.example/hook",
            peer_aid="peer",
        )
    assert baser.associations.get(keys=("rejected",)) is None
    assert list(baser.outbox.getItemIter()) == []


def test_public_get_returns_stored_status_and_old_observation(verified_store):
    """Unauthenticated GET distinguishes known states; old observations remain accepted."""
    baser = verified_store
    app = falcon.App()
    app.add_route("/v1/associations/{said}/status", StatusEnd(baser))
    client = TestClient(app)
    baser.enqueue(PendingVerification("pending", "grant", "missing source"))
    baser.enqueue(PendingVerification("rejected", "grant"))
    baser.finish(VerificationResult("rejected", "rejected", "wrong schema"))
    for said, status in (
        ("pending", "pending"),
        ("rejected", "rejected"),
        ("association", "verified"),
    ):
        response = client.simulate_get(f"/v1/associations/{said}/status")
        assert response.status_code == 200
        assert response.json["status"] == status
    accept_verified_result(baser)
    response = client.simulate_get("/v1/associations/association/status")
    assert response.json["status"] == "accepted"
    assert response.json["accountObservation"]["observedAt"] == "2000-01-01T00:00:00Z"
    assert response.json["delivery"]["acknowledged"] is False
    assert client.simulate_get("/v1/associations/unknown/status").status_code == 404


def test_retirement_commits_its_own_event_once_and_preserves_facts(verified_store):
    """A failed retirement rolls back; a committed one survives replay with its own pending ACK."""

    baser = verified_store
    accepted = accept_verified_result(baser)
    baser.delivery_result(accepted.eventId)  # Initial-success ACK is already durable.
    initial = baser.outbox.get(keys=(accepted.eventId,))
    schedule = DestinationSchedule(failures=3, nextAttemptAt=4000000000)
    baser.destinations.pin(keys=(initial.destination,), val=schedule)

    with (
        patch.object(
            baser.outbox, "serializer", side_effect=RuntimeError("write failed")
        ),
        pytest.raises(RuntimeError, match="write failed"),
    ):
        baser.retire("association")
    assert baser.associations.get(keys=("association",)) == accepted
    assert baser.outbox.get(keys=("association:2",)) is None

    retired = baser.retire("association")
    baser.close()
    baser.reopen()
    assert baser.retire("association") == retired
    assert accept_verified_result(baser) == retired  # No reacceptance after revocation.
    assert baser.outbox.get(keys=(initial.eventId,)) == initial
    event = baser.outbox.get(keys=(retired.eventId,))
    assert not event.acknowledged and event.attempts == 0
    assert (event.destination, event.peerAid) == (initial.destination, initial.peerAid)
    assert baser.destinations.get(keys=(event.destination,)) == schedule
    payload = json.loads(event.body)
    assert (payload["statusRevision"], payload["status"], payload["reasonCode"]) == (
        2,
        "revoked",
        "REVOKED",
    )
    assert payload["association"] == accepted.association
    assert payload["accountObservation"] == accepted.accountObservation

    app = falcon.App()
    app.add_route("/v1/associations/{said}/status", StatusEnd(baser))
    response = TestClient(app).simulate_get("/v1/associations/association/status")
    assert response.json["status"] == "revoked"
    assert response.json["reason"] == "REVOKED"
    assert response.json["accountObservation"] == accepted.accountObservation
    assert response.json["delivery"]["eventId"] == event.eventId
    assert not response.json["delivery"]["acknowledged"]


def test_public_status_does_not_disclose_other_delivery_activity(verified_store):
    """Another event's shared cooldown cannot change an acknowledged association's public view."""
    baser = verified_store
    accepted = accept_verified_result(baser)
    baser.record_attempt(accepted.eventId)
    baser.delivery_result(accepted.eventId)
    event = baser.outbox.get(keys=(accepted.eventId,))
    app = falcon.App()
    app.add_route("/v1/associations/{said}/status", StatusEnd(baser))
    client = TestClient(app)
    path = "/v1/associations/association/status"
    before = client.simulate_get(path).json

    # A different association's event shares this destination.
    result = baser.results.get(keys=("association",))
    baser.enqueue(PendingVerification("other", "grant"))
    baser.finish(VerificationResult("other", "verified", eoaResult=result.eoaResult))
    other = baser.accept(
        "other", association={}, destination=event.destination, peer_aid=event.peerAid
    )
    baser.record_attempt(other.eventId, next_attempt_at=3000000000)
    schedule = DestinationSchedule(failures=3, nextAttemptAt=4000000000)
    baser.delivery_result(other.eventId, error="target unavailable", schedule=schedule)

    assert client.simulate_get(path).json == before
    assert "nextAttemptAt" not in before["delivery"]
    # Operators still have the complete durable schedule through local storage.
    assert baser.destinations.get(keys=(event.destination,)) == schedule
