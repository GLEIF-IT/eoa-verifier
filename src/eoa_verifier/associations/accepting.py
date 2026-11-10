"""Initial association acceptance and nonce conflict policy."""

from dataclasses import replace

from hio.base import doing

from eoa_verifier.associations.evidence import RevokedCredential
from eoa_verifier.persistence.associations import NonceConflict
from eoa_verifier.persistence.records import (
    AssociationStatus,
    DeliveryReference,
    DestinationSchedule,
)

from .events import status_delivery


class AcceptanceService:
    """Prepare initial status/event records; persistence only enforces atomic uniqueness."""

    def __init__(
        self,
        reader,
        writer,
        evidence=None,
        *,
        verification_reader,
        destination=None,
    ):
        """Borrow association persistence and verification-result reads.

        KERIpy evidence is required only for scheduled acceptance."""
        self.reader, self.writer, self.evidence = reader, writer, evidence
        self.verification_reader = verification_reader
        self.destination = destination

    def process_one(self):
        """Guard one verified candidate against locally missing or revoked issuance.

        Revocation of the association, LE or QVI credential is a terminal rejection
        that consumes no nonce and creates no event, matching verification. Missing
        evidence stops in the acceptance dead letter for correction and retry.
        """
        result = self.reader.acceptance()
        if result is None:
            return
        try:
            facts = self.evidence.issuance_facts(result.associationSaid)
        except RevokedCredential as revoked:
            self.writer.reject(
                AssociationStatus(
                    result.associationSaid,
                    "rejected",
                    "",
                    {},
                    self._observation(result),
                    str(revoked),
                )
            )
            return
        if facts is None:
            self.stop(
                result.associationSaid,
                "issuance evidence missing before acceptance",
            )
        else:
            associationFacts, nonce, sources = facts
            self.accept(
                result.associationSaid,
                associationFacts=associationFacts,
                nonce=nonce,
                sources=sources,
                destination=self.destination,
            )

    def accept(self, credSaid, *, associationFacts, nonce, sources, destination=None):
        """Accept a verified credential once, or record a global nonce-reuse rejection.

        credSaid identifies a completed verified result. associationFacts is copied
        from accepted evidence by the scheduled caller; nonce is its exact profile
        string. sources is {"le": leSaid, "qvi": qviSaid} from the verified chain and
        becomes the upstream-revocation index. destination optionally creates a
        signed-delivery obligation. Prepare all records before the atomic writer
        claims the nonce and saves status/event/index.

        Return the committed AssociationStatus, including an existing same-SAID result
        without rewriting it. A different credential reusing any consumed nonce becomes
        rejected/NONCE_REUSED with no event. Missing verification or malformed nonce
        raises ValueError; a failed transaction publishes no partial acceptance.
        """
        previous = self.reader.association(credSaid)
        if previous is not None:
            return previous
        result = self.verification_reader.result(credSaid)
        if result is None or result.status != "verified":
            raise ValueError("acceptance requires a completed verified result")
        status = AssociationStatus(
            credSaid,
            "accepted",
            f"{credSaid}:1" if destination else "",
            associationFacts,
            self._observation(result),
        )
        delivery = (
            status_delivery(status, status_revision=1, destination=destination)
            if destination
            else None
        )
        reference = DeliveryReference(delivery.eventId) if delivery else None
        schedule = DestinationSchedule() if delivery else None
        links = [(sources["le"], "le"), (sources["qvi"], "qvi")]
        try:
            if delivery is None:
                saved = self.writer.accept(status, nonce, links)
            else:
                saved = self.writer.accept_and_queue(
                    status, nonce, delivery, reference, schedule, links
                )
        except NonceConflict:
            # The failed no-overwrite insert aborted the entire acceptance. A
            # same-credential race returns its stored result; every new use rejects.
            previous = self.reader.association(credSaid)
            if previous is not None:
                return previous
            status = replace(
                status, status="rejected", eventId="", reason="NONCE_REUSED"
            )
            saved = self.writer.reject(status)
        return status if saved else self.reader.association(credSaid)

    @staticmethod
    def _observation(result):
        """Copy the verified account observation with its wallet."""
        return dict(
            result.eoaResult["accountObservation"], wallet=result.eoaResult["wallet"]
        )

    def stop(self, cred_said, reason):
        """Prepare one acceptance dead letter, retaining the completed verification."""
        previous = self.reader.acceptance(cred_said)
        if previous is None:
            raise ValueError("acceptance work is absent")
        self.writer.acceptance_to_dead(previous, replace(previous, reason=reason))

    def retry(self, cred_said):
        """Recheck a corrected acceptance with the service stopped."""
        previous = self.reader.dead_acceptance(cred_said)
        if previous is None:
            raise ValueError("unknown acceptance dead letter")
        self.writer.dead_to_acceptance(previous, replace(previous, reason=""))


class AcceptanceDoer(doing.Doer):
    """Schedule one initial acceptance operation per turn."""

    def __init__(self, service, **kwa):
        """Borrow the application operation; the runtime owns its resources."""
        self.service = service
        super().__init__(**kwa)

    def recur(self, tyme):
        """Advance one acceptance and remain scheduled."""
        self.service.process_one()
        return False
