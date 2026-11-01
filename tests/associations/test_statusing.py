"""associations/test_statusing.py."""

import falcon
from falcon.testing import TestClient

from eoa_verifier.associations.statusing import StatusEnd
from eoa_verifier.persistence.records import (
    DestinationSchedule,
    PendingVerification,
    VerificationResult,
)
from tests.support.acceptance import accept_verified_result


def test_public_get_returns_stored_status_and_old_observation(verified_store):
    """Unauthenticated GET distinguishes known states; old observations remain accepted."""
    baser = verified_store
    app = falcon.App()
    app.add_route("/v1/associations/{said}/status", StatusEnd(baser))
    client = TestClient(app)
    baser.enqueue(PendingVerification("rejected", "grant"))
    baser.next_verification(now=0)
    baser.finish(VerificationResult("rejected", "rejected", "wrong schema"))
    baser.enqueue(PendingVerification("pending", "grant", "missing source"))
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
    baser.next_verification(now=0)
    baser.finish(VerificationResult("other", "verified", eoaResult=result.eoaResult))
    other = baser.accept(
        "other",
        association={"issuerAid": "issuer"},
        nonce="other",
        destination=event.destination,
        peer_aid=event.peerAid,
    )
    baser.record_attempt(other.eventId, next_attempt_at=3000000000)
    schedule = DestinationSchedule(failures=3, nextAttemptAt=4000000000)
    baser.delivery_result(other.eventId, error="target unavailable", schedule=schedule)

    assert client.simulate_get(path).json == before
    assert "nextAttemptAt" not in before["delivery"]
    # Operators still have the complete durable schedule through local storage.
    assert baser.destinations.get(keys=(event.destination,)) == schedule


def test_waiting_and_dead_letter_are_passive_statuses(verified_store):
    """Public reads expose operational failures without asserting an invalid credential."""
    import falcon.testing
    from eoa_verifier.associations.statusing import StatusEnd

    baser = verified_store
    app = falcon.App()
    app.add_route("/v1/associations/{said}/status", StatusEnd(baser))
    client = falcon.testing.TestClient(app)
    baser.enqueue(PendingVerification("waiting", "grant"))
    work = baser.next_verification(now=100)
    baser.defer_verification(work, reason="missing evidence", next_attempt_at=105)
    status = client.simulate_get("/v1/associations/waiting/status").json
    assert status["status"] == "waiting" and status["nextAttemptAt"] == 105
    work = baser.next_verification(now=105)
    baser.defer_verification(
        work, reason="missing evidence", next_attempt_at=110, max_attempts=2
    )
    assert (
        client.simulate_get("/v1/associations/waiting/status").json["status"]
        == "dead-letter"
    )
    baser.stop_acceptance("association", "revoked before acceptance")
    stopped = client.simulate_get("/v1/associations/association/status").json
    assert stopped["phase"] == "acceptance" and stopped["status"] == "dead-letter"
    assert baser.accepted_nonces.cntAll() == 0
