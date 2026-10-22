"""Coordinate durable verification work and revalidate asynchronous results."""

from __future__ import annotations

from hio.base import doing
from keri import kering

from eoa_verifier.basing import (
    STATE_AWAITING_ARTIFACTS,
    STATE_VERIFYING,
    VerificationWork,
    VerifierBaser,
)
from eoa_verifier.verification.credentials import grant_candidate, verify_association
from eoa_verifier.verification.errors import (
    MissingCredentialArtifactsError,
    VerificationError,
)


class PresentationVerifierDoer(doing.DoDoer):
    """Verify received credentials against accepted KERI state and wallet proof.

    Grants carry the proof in the ACDC. Missing artifacts remain pending;
    invalid proofs fail. Owns the EOA worker lifecycle and commits its result cues.
    One association is dispatched at a time, bounding in-memory work. RPC errors
    remain retryable; restart rediscovers unfinished operations from the store.
    Verification-only runs terminate at ``verified``.
    """

    def __init__(
        self,
        *,
        baser: VerifierBaser,
        rgy,
        trusted_geda_aid: str,
        association_schema: str = "",
        eoa_verifier=None,
        retry_delay: float = 5.0,
        **kwa,
    ):
        self.baser = baser
        self.rgy = rgy
        self.trusted_geda_aid = trusted_geda_aid
        self.association_schema = association_schema
        self.eoa_verifier = eoa_verifier
        self.retry_delay = retry_delay
        # These are scheduling hints only; operation state remains in VerifierBaser.
        # Restart may retry sooner, but cannot lose or falsely complete the work.
        self.retry_at = {}
        self.pending = None
        if eoa_verifier is None:
            raise ValueError("association verification requires an EOA worker")
        super().__init__(doers=[eoa_verifier, doing.doify(self.verify_do)], **kwa)

    def verify_do(self, tymth, tock=0.0, **opts):
        """Coordinate persisted work and worker cues on the shared HIO clock."""
        yield tock
        while True:
            self.process_results()
            self.process_ready()
            yield self.tock

    def process_results(self) -> None:
        """Apply a matching cue; recheck KERI/TEL state after asynchronous work."""
        while self.eoa_verifier.cues:
            cue = self.eoa_verifier.cues.popleft()
            said = cue["said"]
            if said != self.pending:
                continue
            self.pending = None
            op = self.baser.get_verification(said)
            if op is None or op.state != STATE_VERIFYING:
                continue
            if cue["kin"] == "retry":
                op.failureReason = cue["error"]
                self.baser.pin_verification(op)
                self.retry_at[said] = self.tyme + self.retry_delay
            elif cue["kin"] == "failed":
                self.baser.mark_failed(op, cue["error"])
            elif cue["kin"] == "verified":
                try:
                    # A revocation can arrive while the RPC client is waiting.
                    verify_association(
                        rgy=self.rgy,
                        said=said,
                        schema_said=self.association_schema,
                        trusted_geda_aid=self.trusted_geda_aid,
                    )
                except MissingCredentialArtifactsError as exc:
                    self.baser.mark_awaiting_artifacts(op, str(exc))
                except (VerificationError, kering.ValidationError) as exc:
                    self.baser.mark_failed(op, str(exc))
                else:
                    self.baser.complete_verification(op)

    def process_ready(self) -> None:
        """Retry operations ready for verification or waiting for KERI artifacts."""

        for op in list(
            self.baser.verification_by_state(STATE_VERIFYING, STATE_AWAITING_ARTIFACTS)
        ):
            if self.pending is not None:
                break
            if self.retry_at.get(op.associationSaid, 0) > self.tyme:
                continue
            self.verify_operation(op)

    def verify_operation(self, op: VerificationWork) -> VerificationWork:
        """Verify the selected credential profile before completing initial verification."""

        try:
            # KERIpy may discard an invalid child before logging its bytes.
            # The accepted Grant already owns the immutable candidate; use
            # it for rejection, never as a substitute for KERI acceptance.
            candidate = grant_candidate(self.rgy, op.grantSaid)
            association = verify_association(
                rgy=self.rgy,
                said=op.associationSaid,
                schema_said=self.association_schema,
                candidate=candidate,
                trusted_geda_aid=self.trusted_geda_aid,
            )
            # The database remains the work list. The queue contains only the
            # current dispatch, so restart recovers work without queue persistence.
            self.retry_at.pop(op.associationSaid, None)
            op.state = STATE_VERIFYING
            self.baser.pin_verification(op)
            self.pending = op.associationSaid
            self.eoa_verifier.msgs.append(association.sad)
            return op
        except MissingCredentialArtifactsError as exc:
            return self.baser.mark_awaiting_artifacts(op, str(exc))
        except (VerificationError, kering.ValidationError) as exc:
            return self.baser.mark_failed(op, str(exc))
