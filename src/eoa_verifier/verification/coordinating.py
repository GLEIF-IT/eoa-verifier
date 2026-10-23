"""Coordinate durable verification work and revalidate asynchronous results."""

from __future__ import annotations

from hio.base import doing
from keri import kering

from eoa_verifier.basing import PendingVerification, VerificationResult, VerifierBaser
from eoa_verifier.verification.credentials import grant_candidate, verify_association
from eoa_verifier.verification.errors import (
    MissingCredentialArtifactsError,
    VerificationError,
)


class PresentationVerifierDoer(doing.DoDoer):
    """Own initial-verification scheduling, the EOA worker, and durable work updates.

    Native credential checks precede dispatch and run once more after the initial
    RPC wait to catch evidence received during that wait. These are local native
    state reads, not periodic verification or network refresh. One association is
    in flight; missing material and RPC failures leave unfinished work retryable.
    A verified result is initial progress, not application acceptance.
    """

    def __init__(
        self,
        *,
        baser: VerifierBaser,
        rgy,
        trusted_geda_aid: str,
        association_schema: str,
        eoa_verifier,
        retry_delay: float = 5.0,
        **kwa,
    ):
        """Borrow the work store and native Regery; own the supplied EOA child Doer.

        trusted_geda_aid and association_schema define the trust/profile policy.
        eoa_verifier is required and exposes msgs/cues decks. retry_delay is HIO-clock
        seconds between failed initial attempts. retry_at maps SAIDs to eligible times;
        inflight is the dispatched SAID or None; scan_after is the last examined key.
        These hints are in memory only: restart rediscovers durable unfinished work
        and may retry sooner. kwa supplies native DoDoer scheduling options.
        """
        self.baser = baser
        self.rgy = rgy
        self.trusted_geda_aid = trusted_geda_aid
        self.association_schema = association_schema
        self.eoa_verifier = eoa_verifier
        self.retry_delay = retry_delay
        # These are scheduling hints only; operation state remains in VerifierBaser.
        # Restart may retry sooner, but cannot lose or falsely complete the work.
        self.retry_at = {}
        self.inflight = None
        self.scan_after = ""
        super().__init__(doers=[eoa_verifier, doing.doify(self.verify_do)], **kwa)

    def verify_do(self, tymth, tock=0.0, **opts):
        """Apply worker results and examine a bounded work page, then yield self.tock.

        HIO supplies the shared clock. This generator runs until unscheduled and has
        no completion value; the parent owns the worker's shutdown.
        """
        yield tock
        while True:
            self.process_results()
            self.process_ready()
            yield self.tock

    def process_results(self) -> None:
        """Consume cues matching pending work and persist their status; return None.

        Ignore unmatched cues or work no longer pending. RPC failures set a retry
        hint; local invalidity fails the row. Success rechecks locally accepted native
        state before completing the row. Store successful account observations with the
        result. Unexpected storage or programming errors propagate.
        """
        while self.eoa_verifier.cues:
            cue = self.eoa_verifier.cues.popleft()
            said = cue["said"]
            if said != self.inflight:
                continue
            self.inflight = None
            op = self.baser.pending.get(keys=(said,))
            if op is None:
                continue
            if cue["kin"] == "retry":
                self._retry(op, cue["error"])
            elif cue["kin"] == "failed":
                self._finish(op, "rejected", reason=cue["error"])
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
                    self._retry(op, str(exc))
                except (VerificationError, kering.ValidationError) as exc:
                    self._finish(op, "rejected", reason=str(exc))
                else:
                    self._finish(op, "verified", verified=cue["verified"])

    def process_ready(self) -> None:
        """Skip scanning while busy; otherwise inspect at most one 32-record page.

        Advance past cooling-down rows and attempt at most one association.
        An empty page resets the scan for a later turn. No database cursor survives
        this method; mutations and network waits occur outside its read transaction.
        """

        if self.inflight is not None:
            return
        batch = self.baser.pending_batch(after=self.scan_after)
        if not batch:
            self.scan_after = ""
            return
        for op in batch:
            self.scan_after = op.associationSaid
            if self.retry_at.get(op.associationSaid, 0) > self.tyme:
                continue
            self.verify_operation(op)
            break  # At most one native verification attempt per scheduler turn.

    def verify_operation(self, op: PendingVerification) -> None:
        """Check one pending row’s native evidence and dispatch it or record a decision.

        Missing artifacts retain pending work and a retry hint; invalid evidence
        produces a rejected result. Success queues the ACDC dictionary
        and tracks it as in flight. Candidate Grant bytes may justify rejection but never
        substitute for native acceptance. Persistence/programming errors propagate.
        """

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
        except MissingCredentialArtifactsError as exc:
            self._retry(op, str(exc))
            return
        except (VerificationError, kering.ValidationError) as exc:
            self._finish(op, "rejected", reason=str(exc))
            return

        # The database remains the work list. The queue contains only the
        # current dispatch, so restart recovers work without queue persistence.
        self.retry_at.pop(op.associationSaid, None)
        self.inflight = op.associationSaid
        self.eoa_verifier.msgs.append(association.sad)

    def _retry(self, op, reason):
        """Keep unfinished work durable and pace another attempt on the HIO clock."""
        self.baser.note_pending(op.associationSaid, reason)
        self.retry_at[op.associationSaid] = self.tyme + self.retry_delay

    def _finish(self, op, outcome, *, reason="", verified=None):
        """Persist the workflow decision and release its transient retry hint."""
        self.baser.finish(
            VerificationResult(op.associationSaid, outcome, reason, verified or {})
        )
        self.retry_at.pop(op.associationSaid, None)
