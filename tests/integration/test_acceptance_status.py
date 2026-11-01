"""integration/test_acceptance_status.py."""

import json
from unittest.mock import patch

import falcon
import pytest
from falcon.testing import TestClient

from eoa_verifier.associations.statusing import StatusEnd, StatusQuery
from eoa_verifier.persistence.associations import AssociationReader
from eoa_verifier.persistence.delivery import DeliveryReader
from eoa_verifier.persistence.records import DestinationSchedule
from eoa_verifier.persistence.verification import VerificationReader
from tests.support.acceptance import accept_verified_result, revocation_service
from tests.support.services import delivery_service


def test_revocation_commits_its_own_event_once_and_preserves_facts(verified_store):
    """A failed revocation rolls back; a committed one survives replay with its own pending ACK."""

    baser = verified_store
    associationStatus = accept_verified_result(baser)
    delivery_service(baser).complete(
        associationStatus.eventId
    )  # Initial-success ACK is already durable.
    initial = baser.outbox.get(keys=(associationStatus.eventId,))
    schedule = DestinationSchedule(failures=3, nextAttemptAt=4000000000)
    baser.destinations.pin(keys=(initial.destination,), val=schedule)

    with (
        patch.object(
            baser.outbox, "serializer", side_effect=RuntimeError("write failed")
        ),
        pytest.raises(RuntimeError, match="write failed"),
    ):
        revocation_service(baser).apply_revocation("association")
    assert baser.associations.get(keys=("association",)) == associationStatus
    assert baser.outbox.get(keys=("association:2",)) is None

    revokedStatus = revocation_service(baser).apply_revocation("association")
    baser.close()
    baser.reopen()
    assert revocation_service(baser).apply_revocation("association") == revokedStatus
    assert (
        accept_verified_result(baser) == revokedStatus
    )  # No reacceptance after revocation.
    assert baser.outbox.get(keys=(initial.eventId,)) == initial
    delivery = baser.outbox.get(keys=(revokedStatus.eventId,))
    assert not delivery.delivered and delivery.attempts == 0
    assert delivery.destination == initial.destination
    assert baser.destinations.get(keys=(delivery.destination,)) == schedule
    payload = json.loads(delivery.body)
    assert (payload["statusRevision"], payload["status"], payload["reasonCode"]) == (
        2,
        "revoked",
        "REVOKED",
    )
    assert payload["association"] == associationStatus.association
    assert payload["accountObservation"] == associationStatus.accountObservation

    app = falcon.App()
    app.add_route(
        "/v1/associations/{said}/status",
        StatusEnd(
            StatusQuery(
                AssociationReader(baser),
                VerificationReader(baser),
                DeliveryReader(baser),
            )
        ),
    )
    response = TestClient(app).simulate_get("/v1/associations/association/status")
    assert response.json["status"] == "revoked"
    assert response.json["reason"] == "REVOKED"
    assert response.json["accountObservation"] == associationStatus.accountObservation
    assert response.json["delivery"]["eventId"] == delivery.eventId
    assert not response.json["delivery"]["delivered"]
