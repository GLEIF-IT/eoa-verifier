"""Advance one durable verification attempt through local proof and EOA checks."""

import time

from hio.base import doing
from keri import kering

from eoa_verifier.persistence.records import VerificationResult
from eoa_verifier.verification.credentials import grant_candidate, verify_association
from eoa_verifier.verification.errors import (
    MissingCredentialArtifactsError,
    VerificationError,
)


class VerificationCoordinator(doing.DoDoer):
    """Own one asynchronous EOA check; the database owns progress and retry timing.

    Local evidence is checked before RPC and again after its response. Completed
    results never schedule work. Missing evidence and transient RPC failures move
    to waiting, then to dead letter when the finite attempt budget is exhausted.
    """

    def __init__(
        self,
        *,
        baser,
        rgy,
        trusted_geda_aid,
        association_schema,
        eoa_verifier,
        retry_delay=5.0,
        max_attempts=3,
        clock=time.time,
        **kwa,
    ):
        """Borrow stores; own the EOA Doer. clock returns UTC Unix seconds."""
        self.baser, self.rgy = baser, rgy
        self.trusted_geda_aid, self.association_schema = (
            trusted_geda_aid,
            association_schema,
        )
        self.eoa_verifier = eoa_verifier
        self.retry_delay, self.max_attempts, self.clock = (
            retry_delay,
            max_attempts,
            clock,
        )
        # Only dispatch correlation is transient. A new worker resumes durable active work.
        self.inflight = None
        super().__init__(doers=[eoa_verifier, doing.doify(self.verify_do)], **kwa)

    def verify_do(self, tymth, tock=0.0, **opts):
        """Apply one response or begin one attempt per scheduler turn."""
        yield tock
        while True:
            if not self.process_results():
                self.process_ready()
            yield self.tock

    def process_results(self):
        """Correlate one EOA cue and commit its next durable phase."""
        if not self.eoa_verifier.cues:
            return
        cue = self.eoa_verifier.cues.popleft()
        if cue["said"] != self.inflight:
            return
        op = self.baser.verifying.get(keys=(self.inflight,))
        if op is None:
            raise ValueError("dispatched verification has no active work")
        if cue["kin"] == "retry":
            self._retry(op, cue["error"])
        elif cue["kin"] == "failed":
            self._finish(op, "rejected", reason=cue["error"])
        elif cue["kin"] == "verified":
            try:
                self._verify(op)
            except MissingCredentialArtifactsError as exc:
                self._retry(op, str(exc))
            except (VerificationError, kering.ValidationError) as exc:
                self._finish(op, "rejected", reason=str(exc))
            else:
                self._finish(op, "verified", eoaResult=cue["eoaResult"])
        else:
            raise ValueError("unknown EOA result")
        self.inflight = None
        return True

    def process_ready(self):
        """Claim one attempt before local validation or external RPC dispatch."""
        if self.inflight is not None:
            return
        op = self.baser.next_verification(
            now=self.clock(), max_attempts=self.max_attempts
        )
        if op is None:
            return
        try:
            association = self._verify(op)
        except MissingCredentialArtifactsError as exc:
            self._retry(op, str(exc))
        except (VerificationError, kering.ValidationError) as exc:
            self._finish(op, "rejected", reason=str(exc))
        else:
            self.inflight = op.associationSaid
            self.eoa_verifier.msgs.append(association.sad)

    def _verify(self, op):
        """Require native acceptance; Grant bytes can justify rejection, never acceptance."""
        return verify_association(
            rgy=self.rgy,
            said=op.associationSaid,
            schema_said=self.association_schema,
            candidate=grant_candidate(self.rgy, op.grantSaid),
            trusted_geda_aid=self.trusted_geda_aid,
        )

    def _retry(self, op, reason):
        """Persist both cooldown and budget; restarting never renews either."""
        self.baser.defer_verification(
            op,
            reason=reason,
            next_attempt_at=self.clock() + self.retry_delay,
            max_attempts=self.max_attempts,
        )

    def _finish(self, op, status, *, reason="", eoaResult=None):
        """Commit the result and, for success, its separate acceptance obligation."""
        self.baser.finish(
            VerificationResult(op.associationSaid, status, reason, eoaResult or {})
        )
