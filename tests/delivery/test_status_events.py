"""Qualification receiver policy is independent of HTTP and post-commit faults."""

import pytest
from keri.db import dbing

from scripts.integration.receiver import (
    StatusEventConflict,
    StatusEventService,
    StatusEventStore,
)


def test_status_events_are_immutable_and_diagnostics_are_detached():
    """Duplicate attempts count once each; conflicting bytes cannot replace a stored status event."""
    with dbing.openLMDB() as db:
        status_event_service = StatusEventService(StatusEventStore(db))
        statusEventBytes = b'{"eventId":"credential:1","status":"accepted"}'
        assert status_event_service.receive(statusEventBytes) == "credential:1"
        assert status_event_service.receive(statusEventBytes) == "credential:1"
        with pytest.raises(StatusEventConflict):
            status_event_service.receive(
                b'{"eventId":"credential:1","status":"revoked"}'
            )
        storedEvents = status_event_service.stored_events()
        assert "(no active readers)" in db.env.readers()
    assert storedEvents == [
        {"eventId": "credential:1", "body": statusEventBytes.decode(), "attempts": 2}
    ]
