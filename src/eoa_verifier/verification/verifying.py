"""Verification phase policy over detached evidence and prepared atomic saves."""

import time
from dataclasses import replace

from keri import kering

from eoa_verifier.persistence.records import VerificationResult

from .credentials import verify_association
from .errors import MissingCredentialArtifactsError, VerificationError


class VerificationService:
    """Own one candidate's local checks, finite retries and result completion."""

    def __init__(
        self,
        reader,
        writer,
        evidence=None,
        *,
        trusted_geda_aid="",
        association_schema="",
        retry_delay=5.0,
        max_attempts=3,
        clock=time.time,
    ):
        """Borrow adapters; KERIpy evidence is unnecessary for offline phase operations."""
        self.reader, self.writer, self.evidence = reader, writer, evidence
        self.trusted_geda_aid, self.association_schema = (
            trusted_geda_aid,
            association_schema,
        )
        self.retry_delay, self.max_attempts, self.clock = (
            retry_delay,
            max_attempts,
            clock,
        )

    def next_verification(self, *, now, max_attempts=3):
        """Choose one active/due/new candidate and durably charge its attempt."""
        record = self.reader.active_verification()
        if record is not None:
            if record.attempts >= max_attempts:
                dead = replace(
                    record,
                    reason=record.reason
                    or "verification interrupted; attempt budget exhausted",
                )
                self.writer.dead_letter_verification(record, dead)
                return None
            active = replace(
                record,
                attempts=record.attempts + 1,
                reason="verification attempt started; result not committed",
            )
            self.writer.resume_verification(record, active)
            return active
        record = self.reader.waiting_verification()
        if record is not None and record.nextAttemptAt <= now:
            if record.attempts >= max_attempts:
                dead = replace(
                    record,
                    reason=record.reason
                    or "verification interrupted; attempt budget exhausted",
                )
                self.writer.dead_letter_waiting_verification(record, dead)
                return None
            active = replace(
                record,
                attempts=record.attempts + 1,
                reason="verification attempt started; result not committed",
            )
            self.writer.activate_waiting_verification(record, active)
            return active
        record = self.reader.pending_verification()
        if record is not None:
            if record.attempts >= max_attempts:
                dead = replace(
                    record,
                    reason=record.reason
                    or "verification interrupted; attempt budget exhausted",
                )
                self.writer.dead_letter_pending_verification(record, dead)
                return None
            active = replace(
                record,
                attempts=record.attempts + 1,
                reason="verification attempt started; result not committed",
            )
            self.writer.start_verification(record, active)
            return active
        return None

    def defer_verification(self, record, *, reason, next_attempt_at, max_attempts=3):
        """Choose waiting or dead letter without holding a transaction during policy."""
        updated = replace(record, reason=reason, nextAttemptAt=next_attempt_at)
        if record.attempts >= max_attempts:
            self.writer.dead_letter_verification(record, updated)
        else:
            self.writer.defer_verification(record, updated)

    def retry(self, cred_said):
        """Reset one corrected dead letter with the service stopped."""
        record = self.reader.dead_verification(cred_said)
        if record is None:
            raise ValueError("unknown verification dead letter")
        updated = replace(record, attempts=0, nextAttemptAt=0, reason="")
        self.writer.retry_dead_verification(record, updated)

    def finish(self, result):
        """Prepare an acceptance obligation only for a verified result."""
        if result.status == "verified":
            self.writer.complete_verified_candidate(result)
        else:
            self.writer.complete_rejected_candidate(result)

    def prepare(self):
        """Claim and validate one candidate; return its detached ACDC for RPC dispatch."""
        record = self.next_verification(
            now=self.clock(), max_attempts=self.max_attempts
        )
        if record is None:
            return None
        try:
            return self._verify(record)
        except MissingCredentialArtifactsError as exc:
            self._retry(record, str(exc))
        except (VerificationError, kering.ValidationError) as exc:
            self._finish(record, "rejected", reason=str(exc))
        return None

    def apply_cue(self, cue):
        """Recheck local evidence after RPC and commit one correlated outcome."""
        verification = self.reader.active_verification(cue["said"])
        if verification is None:
            raise ValueError("dispatched verification has no active work")
        if cue["kin"] == "retry":
            self._retry(verification, cue["error"])
        elif cue["kin"] == "failed":
            self._finish(verification, "rejected", reason=cue["error"])
        elif cue["kin"] == "verified":
            try:
                self._verify(verification)
            except MissingCredentialArtifactsError as exc:
                self._retry(verification, str(exc))
            except (VerificationError, kering.ValidationError) as exc:
                self._finish(verification, "rejected", reason=str(exc))
            else:
                self._finish(verification, "verified", eoaResult=cue["eoaResult"])
        else:
            raise ValueError("unknown EOA result")

    def _verify(self, verification):
        """Require KERIpy acceptance; Grant bytes can justify rejection, never acceptance."""
        return verify_association(
            evidence=self.evidence,
            said=verification.associationSaid,
            schema_said=self.association_schema,
            candidate=self.evidence.grant_candidate(verification.grantSaid),
            trusted_geda_aid=self.trusted_geda_aid,
        )

    def _retry(self, verification, reason):
        """Persist both cooldown and budget; restarting never renews either."""
        self.defer_verification(
            verification,
            reason=reason,
            next_attempt_at=self.clock() + self.retry_delay,
            max_attempts=self.max_attempts,
        )

    def _finish(self, verification, status, *, reason="", eoaResult=None):
        """Commit the result and, for success, its separate acceptance obligation."""
        self.finish(
            VerificationResult(
                verification.associationSaid, status, reason, eoaResult or {}
            )
        )
