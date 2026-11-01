"""Build immutable public status-event bytes before application persistence."""

import json

from eoa_verifier.persistence.records import Delivery


def status_delivery(associationStatus, *, status_revision, destination):
    """Serialize one immutable v1 event for URL-only webhook delivery."""
    statusEvent = {
        "version": "1",
        "eventId": associationStatus.eventId,
        "associationSaid": associationStatus.associationSaid,
        "statusRevision": status_revision,
        "status": associationStatus.status,
        "association": associationStatus.association,
        "accountObservation": associationStatus.accountObservation,
    }
    if associationStatus.reason:
        statusEvent["reasonCode"] = associationStatus.reason
    statusEventJson = json.dumps(statusEvent, separators=(",", ":"), sort_keys=True)
    return Delivery(
        associationStatus.eventId,
        associationStatus.associationSaid,
        destination,
        statusEventJson,
    )
