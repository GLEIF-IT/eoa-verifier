"""integration/test_acceptance_status.py."""

import json
from unittest.mock import patch

import falcon
import pytest
from falcon.testing import TestClient

from eoa_verifier.associations.statusing import StatusEnd
from eoa_verifier.persistence.records import DestinationSchedule
from tests.support.acceptance import accept_verified_result


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
