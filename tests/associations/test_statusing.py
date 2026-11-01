"""associations/test_statusing.py."""

import falcon
from falcon.testing import TestClient

from eoa_verifier.associations.statusing import StatusEnd, StatusQuery
from eoa_verifier.persistence.reading import ApplicationReader
from eoa_verifier.persistence.records import (
    DestinationSchedule,
    VerificationRecord,
    VerificationResult,
)
from eoa_verifier.persistence.writing import ApplicationWriter
from tests.support.acceptance import accept_verified_result, acceptance_service
from tests.support.services import delivery_service, verification_service


def test_public_get_returns_stored_status_and_old_observation(verified_store):
    """Unauthenticated GET distinguishes known states; old observations remain accepted."""
    baser = verified_store
    app = falcon.App()
    app.add_route(
        "/v1/associations/{said}/status",
        StatusEnd(StatusQuery(ApplicationReader(baser))),
    )
    client = TestClient(app)
    ApplicationWriter(baser).enqueue_verification(
        VerificationRecord("rejected", "grant")
    )
    verification_service(baser).next_verification(now=0)
    verification_service(baser).finish(
        VerificationResult("rejected", "rejected", "wrong schema")
    )
    ApplicationWriter(baser).enqueue_verification(
        VerificationRecord("pending", "grant", "missing source")
    )
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


def test_public_status_does_not_disclose_other_delivery_activity(verified_store):
    """Another event's shared cooldown cannot change an acknowledged association's public view."""
    baser = verified_store
    associationStatus = accept_verified_result(baser)
    delivery_service(baser).record_attempt(associationStatus.eventId)
    delivery_service(baser).acknowledge(associationStatus.eventId)
    delivery = baser.outbox.get(keys=(associationStatus.eventId,))
    app = falcon.App()
    app.add_route(
        "/v1/associations/{said}/status",
        StatusEnd(StatusQuery(ApplicationReader(baser))),
    )
    client = TestClient(app)
    path = "/v1/associations/association/status"
    before = client.simulate_get(path).json

    # A different association's event shares this destination.
    result = baser.results.get(keys=("association",))
    ApplicationWriter(baser).enqueue_verification(VerificationRecord("other", "grant"))
    verification_service(baser).next_verification(now=0)
    verification_service(baser).finish(
        VerificationResult("other", "verified", eoaResult=result.eoaResult)
    )
    other = acceptance_service(baser).accept(
        "other",
        associationFacts={"issuerAid": "issuer"},
        nonce="other",
        destination=delivery.destination,
        peer_aid=delivery.peerAid,
    )
    delivery_service(baser).record_attempt(other.eventId, next_attempt_at=3000000000)
    schedule = DestinationSchedule(failures=3, nextAttemptAt=4000000000)
    delivery_service(baser).defer(
        other.eventId, error="target unavailable", schedule=schedule
    )

    assert client.simulate_get(path).json == before
    assert "nextAttemptAt" not in before["delivery"]
    # Operators still have the complete durable schedule through local storage.
    assert baser.destinations.get(keys=(delivery.destination,)) == schedule


def test_waiting_and_dead_letter_are_passive_statuses(verified_store):
    """Public reads expose operational failures without asserting an invalid credential."""
    import falcon.testing

    from eoa_verifier.associations.statusing import StatusEnd

    baser = verified_store
    app = falcon.App()
    app.add_route(
        "/v1/associations/{said}/status",
        StatusEnd(StatusQuery(ApplicationReader(baser))),
    )
    client = falcon.testing.TestClient(app)
    ApplicationWriter(baser).enqueue_verification(
        VerificationRecord("waiting", "grant")
    )
    verification = verification_service(baser).next_verification(now=100)
    verification_service(baser).defer_verification(
        verification, reason="missing evidence", next_attempt_at=105
    )
    status = client.simulate_get("/v1/associations/waiting/status").json
    assert status["status"] == "waiting" and status["nextAttemptAt"] == 105
    verification = verification_service(baser).next_verification(now=105)
    verification_service(baser).defer_verification(
        verification, reason="missing evidence", next_attempt_at=110, max_attempts=2
    )
    assert (
        client.simulate_get("/v1/associations/waiting/status").json["status"]
        == "dead-letter"
    )
    acceptance_service(baser).stop("association", "revoked before acceptance")
    stopped = client.simulate_get("/v1/associations/association/status").json
    assert stopped["phase"] == "acceptance" and stopped["status"] == "dead-letter"
    assert baser.accepted_nonces.cntAll() == 0
