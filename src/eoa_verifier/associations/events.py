"""Build immutable public status-event bytes before application persistence."""

import json

from eoa_verifier.persistence.records import Delivery


def status_delivery(associationStatus, *, status_revision, destination):
    """Build a Delivery record from prepared association status, revision and target URL.

    Serialize deterministic compact/sorted v1 JSON, including reasonCode only when
    present. Return an unsent record; this function performs no signing, storage or
    HTTP I/O. Once committed, callers resend these exact body bytes.
    """
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
