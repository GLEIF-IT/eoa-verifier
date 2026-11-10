"""Apply already-validated credential TEL revocation to local association status.

The issuer issues the TEL revocation. KERIpy validates it; this module records
the resulting association status and delivery obligation without issuing a TEL event.
An association's own revocation applies directly. Revocation of an LE or QVI
credential in its verified chain fans out through two idempotent stages: one registry
record becomes durable work records, then one work record is applied per turn.
"""

from dataclasses import replace

from hio.base import doing

from eoa_verifier.persistence.records import DeliveryReference, UpstreamRevocation

from .events import status_delivery


class RevocationService:
    """Commit application revocation before acknowledging its separate KERIpy record."""

    def __init__(self, reader, writer, evidence=None, *, delivery_reader):
        """Borrow association persistence, delivery reads and optional TEL evidence."""
        self.reader, self.writer, self.evidence = reader, writer, evidence
        self.delivery_reader = delivery_reader

    def process_one(self):
        """Classify at most one credential revocation without scanning association history.

        An association applies directly; if that fails it becomes a work record, so
        the worker dead-letters it and this shared queue keeps moving. An LE or QVI
        credential with source links becomes one durable work record per association.
        Any other credential has no effect. The registry record is acknowledged only
        after the application commit.
        """
        revocationIds = self.evidence.next_revocation()
        if revocationIds is None:
            return
        credSaid, telEvtSaid = revocationIds
        status = self.reader.association(credSaid)
        if status is not None:
            if status.status == "accepted":
                try:
                    self.apply_revocation(credSaid)
                except ValueError:
                    self.writer.queue_upstream(
                        [
                            UpstreamRevocation(
                                credSaid, credSaid, "association", telEvtSaid
                            )
                        ]
                    )
        else:
            links = self.reader.source_links(credSaid)
            if links:
                self.writer.queue_upstream(
                    [
                        UpstreamRevocation(said, credSaid, role, telEvtSaid)
                        for said, role in links
                    ]
                )
        self.evidence.remove_revocation(credSaid)

    def process_work(self):
        """Apply at most one upstream revocation work record.

        Status with its cause, optional event and work removal commit together. Work for an
        association that is no longer accepted is dropped, covering replay and an
        issuer revocation that arrived first. ValueError (a missing original event
        or changed status) dead-letters this association so others still progress;
        storage errors propagate and retain the work.
        """
        work = self.reader.revocation_work()
        if work is None:
            return
        previous = self.reader.association(work.associationSaid)
        if previous is None or previous.status != "accepted":
            self.writer.drop_work(work)
            return
        try:
            status, delivery = self._revoked(previous)
            if work.sourceRole != "association":
                status = replace(
                    status,
                    revocationSource={
                        "credentialSaid": work.sourceSaid,
                        "role": work.sourceRole,
                        "telEventSaid": work.telEvtSaid,
                    },
                )
            reference = DeliveryReference(delivery.eventId) if delivery else None
            self.writer.rev_upstream(previous, status, delivery, reference)
        except ValueError as error:
            self.writer.work_to_dead(work, replace(work, reason=str(error)))

    def retry(self, said):
        """Requeue a corrected upstream revocation dead letter with the service stopped."""
        previous = self.reader.dead_revocation(said)
        if previous is None:
            raise ValueError("unknown revocation dead letter")
        self.writer.dead_to_work(previous, replace(previous, reason=""))

    def apply_revocation(self, credSaid):
        """Return revoked local status, preserving the original facts and delivery target.

        credSaid must already be accepted or revoked; otherwise raise ValueError.
        The scheduled caller supplies KERIpy-validated TEL revocation, never an issuer
        instruction to create one. Repeated application returns stored revoked status.
        Commit status and, if initial acceptance had delivery, its immutable revision-2
        event together. A missing original outbox event fails before any mutation.
        The separate TEL queue is acknowledged by process_one only after this commit.
        """
        previous = self.reader.association(credSaid)
        if previous is None or previous.status not in ("accepted", "revoked"):
            raise ValueError("revocation requires an accepted association")
        if previous.status == "revoked":
            return previous
        status, delivery = self._revoked(previous)
        if delivery is None:
            self.writer.rev(previous, status)
        else:
            self.writer.rev_and_queue(
                previous, status, delivery, DeliveryReference(delivery.eventId)
            )
        return status

    def _revoked(self, previous):
        """Prepare revoked status and its optional revision-2 event without I/O.

        A missing original outbox event raises ValueError before any mutation.
        """
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
            eventId=f"{previous.associationSaid}:2" if original else "",
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
        return status, delivery


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


class RevocationWorkDoer(doing.Doer):
    """Schedule one upstream revocation work record per turn."""

    def __init__(self, service, tock=0.25, **kwa):
        """Borrow the revocation operation and configure its scheduler interval."""
        self.service = service
        super().__init__(tock=tock, **kwa)

    def recur(self, tyme):
        """Advance one work record and remain scheduled."""
        self.service.process_work()
        return False
