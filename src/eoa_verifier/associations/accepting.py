"""Initial association acceptance and nonce conflict policy."""

from dataclasses import replace

from hio.base import doing

from eoa_verifier.persistence.records import (
    AcceptedNonce,
    AssociationStatus,
    DeliveryReference,
    DestinationSchedule,
)
from eoa_verifier.persistence.writing import NonceConflict

from .events import status_delivery
from .integrity import AssociationIntegrity


class AcceptanceService:
    """Prepare initial status/event records; persistence only enforces atomic uniqueness."""

    def __init__(
        self, reader, writer, evidence=None, *, destination=None, peer_aid=None
    ):
        """Borrow adapters; native evidence is required only for scheduled acceptance."""
        self.reader, self.writer, self.evidence = reader, writer, evidence
        self.destination, self.peer_aid = destination, peer_aid

    def process_one(self):
        """Guard one verified candidate against locally missing or revoked issuance."""
        result = self.reader.acceptance()
        if result is None:
            return
        facts = self.evidence.issuance_facts(result.associationSaid)
        if facts is None:
            self.stop(
                result.associationSaid,
                "issuance evidence missing or revoked before acceptance",
            )
        else:
            associationFacts, nonce = facts
            self.accept(
                result.associationSaid,
                associationFacts=associationFacts,
                nonce=nonce,
                destination=self.destination,
                peer_aid=self.peer_aid,
            )

    def accept(
        self, credSaid, *, associationFacts, nonce, destination=None, peer_aid=None
    ):
        """Accept once or reject nonce reuse; same-SAID races return their committed status."""
        previous = self.reader.association(credSaid)
        if previous is not None:
            return previous
        result = self.reader.verification_result(credSaid)
        if result is None or result.status != "verified":
            raise ValueError("acceptance requires a completed verified result")
        if bool(destination) != bool(peer_aid):
            raise ValueError("delivery requires both destination and peer AID")
        claim = AcceptedNonce(associationFacts["issuerAid"], nonce, credSaid)
        observation = dict(
            result.eoaResult["accountObservation"], wallet=result.eoaResult["wallet"]
        )
        status = AssociationStatus(
            credSaid,
            "accepted",
            f"{credSaid}:1" if destination else "",
            associationFacts,
            observation,
        )
        delivery = (
            status_delivery(
                status, status_revision=1, destination=destination, peer_aid=peer_aid
            )
            if destination
            else None
        )
        reference = DeliveryReference(delivery.eventId) if delivery else None
        schedule = DestinationSchedule() if delivery else None
        try:
            saved = self.writer.save_acceptance(
                status, claim, delivery, reference, schedule
            )
        except NonceConflict:
            # The entire attempted acceptance aborted. Inspect committed ownership
            # without a writer, then prepare a separate terminal rejection.
            previous = self.reader.association(credSaid)
            if previous is not None:
                return previous
            AssociationIntegrity(self.reader, self.writer).claimed_nonce(
                claim.issuerAid, nonce
            )
            status = replace(
                status, status="rejected", eventId="", reason="NONCE_REUSED"
            )
            saved = self.writer.save_acceptance(status, None)
        return status if saved else self.reader.association(credSaid)

    def stop(self, cred_said, reason):
        """Prepare one acceptance dead letter, retaining the completed verification."""
        previous = self.reader.acceptance(cred_said)
        if previous is None:
            raise ValueError("acceptance work is absent")
        self.writer.move_acceptance(
            previous, replace(previous, reason=reason), to_dead=True
        )

    def retry(self, cred_said):
        """Recheck a corrected acceptance with the service stopped."""
        previous = self.reader.acceptance(cred_said, dead=True)
        if previous is None:
            raise ValueError("unknown acceptance dead letter")
        self.writer.move_acceptance(
            previous, replace(previous, reason=""), to_dead=False
        )


class AcceptanceDoer(doing.Doer):
    """Schedule one initial acceptance operation per turn."""

    def __init__(self, service, **kwa):
        self.service = service
        super().__init__(**kwa)

    def recur(self, tyme):
        self.service.process_one()
        return False
