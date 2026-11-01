"""Idempotent application retirement after accepted native TEL revocation."""

from dataclasses import replace

from hio.base import doing

from eoa_verifier.persistence.records import DeliveryReference

from .events import status_delivery


class RetirementService:
    """Commit application retirement before acknowledging its separate native record."""

    def __init__(self, reader, writer, evidence=None):
        self.reader, self.writer, self.evidence = reader, writer, evidence

    def process_one(self):
        """Apply at most one credential revocation without scanning association history."""
        revocationIds = self.evidence.next_revocation()
        if revocationIds is None:
            return
        credSaid, _telEvtSaid = revocationIds
        status = self.reader.association(credSaid)
        if status is not None and status.status == "accepted":
            self.retire(credSaid)
        self.evidence.remove_revocation(credSaid)

    def retire(self, credSaid):
        """Prepare revoked status and its second immutable event from accepted facts."""
        previous = self.reader.association(credSaid)
        if previous is None or previous.status not in ("accepted", "revoked"):
            raise ValueError("retirement requires an accepted association")
        if previous.status == "revoked":
            return previous
        original = self.reader.delivery(previous.eventId) if previous.eventId else None
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
                peer_aid=original.peerAid,
            )
            if original
            else None
        )
        self.writer.save_retirement(
            previous,
            status,
            delivery,
            DeliveryReference(delivery.eventId) if delivery else None,
        )
        return status


class RetirementDoer(doing.Doer):
    """Schedule one native-to-application retirement operation per turn."""

    def __init__(self, service, tock=0.25, **kwa):
        self.service = service
        super().__init__(tock=tock, **kwa)

    def recur(self, tyme):
        self.service.process_one()
        return False
