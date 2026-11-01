"""Apply already-validated credential TEL revocation to local association status.

The issuer issues the TEL revocation. KERIpy validates it; this module records
the resulting association status and delivery obligation without issuing a TEL event.
"""

from dataclasses import replace

from hio.base import doing

from eoa_verifier.persistence.records import DeliveryReference

from .events import status_delivery


class RevocationService:
    """Commit application revocation before acknowledging its separate KERIpy record."""

    def __init__(self, reader, writer, evidence=None, *, delivery_reader):
        """Borrow association persistence, delivery reads and optional TEL evidence."""
        self.reader, self.writer, self.evidence = reader, writer, evidence
        self.delivery_reader = delivery_reader

    def process_one(self):
        """Apply at most one credential revocation without scanning association history."""
        revocationIds = self.evidence.next_revocation()
        if revocationIds is None:
            return
        credSaid, _telEvtSaid = revocationIds
        status = self.reader.association(credSaid)
        if status is not None and status.status == "accepted":
            self.apply_revocation(credSaid)
        self.evidence.remove_revocation(credSaid)

    def apply_revocation(self, credSaid):
        """Prepare revoked status and its second immutable event from accepted facts."""
        previous = self.reader.association(credSaid)
        if previous is None or previous.status not in ("accepted", "revoked"):
            raise ValueError("revocation requires an accepted association")
        if previous.status == "revoked":
            return previous
        original = (
            self.delivery_reader.delivery(previous.eventId)
            if previous.eventId
            else None
        )
        if previous.eventId and original is None:
            raise ValueError("accepted delivery event is absent")
        status = replace(
            previous,
            status="revoked",
            eventId=f"{credSaid}:2" if original else "",
            reason="REVOKED",
        )
        delivery = (
            status_delivery(
                status,
                status_revision=2,
                destination=original.destination,
            )
            if original
            else None
        )
        if delivery is None:
            self.writer.rev(previous, status)
        else:
            self.writer.rev_and_queue(
                previous, status, delivery, DeliveryReference(delivery.eventId)
            )
        return status


class RevocationDoer(doing.Doer):
    """Schedule one KERIpy-to-application revocation operation per turn."""

    def __init__(self, service, tock=0.25, **kwa):
        """Borrow the revocation operation and configure its scheduler interval."""
        self.service = service
        super().__init__(tock=tock, **kwa)

    def recur(self, tyme):
        """Advance one revocation record and remain scheduled."""
        self.service.process_one()
        return False
