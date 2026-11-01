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

    def next_verifying(self):
        """Read one interrupted verifying record without changing its attempt count."""
        return self.reader.verifying()

    def next_waiting(self):
        """Read one due waiting record; leave future deadlines untouched."""
        record = self.reader.waiting()
        return (
            record
            if record is not None and record.nextAttemptAt <= self.clock()
            else None
        )

    def next_pending(self):
        """Read one pending record without claiming it or inspecting other phases."""
        return self.reader.pending()

    def resume_verifying(self, record):
        """Charge one interrupted attempt, or dead-letter exhausted verifying work."""
        if record.attempts >= self.max_attempts:
            dead = replace(
                record,
                reason=record.reason
                or "verification interrupted; attempt budget exhausted",
            )
            self.writer.verifying_to_dead(record, dead)
            return None
        active = replace(
            record,
            attempts=record.attempts + 1,
            reason="verification attempt started; result not committed",
        )
        self.writer.resume_verifying(record, active)
        return active

    def retry_waiting(self, record):
        """Charge one due retry, or dead-letter exhausted waiting work."""
        if record.nextAttemptAt > self.clock():
            raise ValueError("verification retry is not due")
        if record.attempts >= self.max_attempts:
            dead = replace(
                record,
                reason=record.reason
                or "verification interrupted; attempt budget exhausted",
            )
            self.writer.waiting_to_dead(record, dead)
            return None
        active = replace(
            record,
            attempts=record.attempts + 1,
            reason="verification attempt started; result not committed",
        )
        self.writer.waiting_to_verifying(record, active)
        return active

    def start_pending(self, record):
        """Charge the first attempt of valid fresh pending work."""
        if record.attempts != 0 or record.nextAttemptAt != 0 or self.max_attempts < 1:
            raise ValueError(
                "pending verification requires a fresh attempt and positive budget"
            )
        active = replace(
            record,
            attempts=record.attempts + 1,
            reason="verification attempt started; result not committed",
        )
        self.writer.pending_to_verifying(record, active)
        return active

    def defer_verification(self, record, *, reason, next_attempt_at, max_attempts=3):
        """Choose waiting or dead letter without holding a transaction during policy."""
        updated = replace(record, reason=reason, nextAttemptAt=next_attempt_at)
        if record.attempts >= max_attempts:
            self.writer.verifying_to_dead(record, updated)
        else:
            self.writer.verifying_to_waiting(record, updated)

    def retry(self, cred_said):
        """Reset one corrected dead letter with the service stopped."""
        record = self.reader.dead(cred_said)
        if record is None:
            raise ValueError("unknown verification dead letter")
        updated = replace(record, attempts=0, nextAttemptAt=0, reason="")
        self.writer.dead_to_pending(record, updated)

    def finish(self, result):
        """Prepare an acceptance obligation only for a verified result."""
        if result.status == "verified":
            self.writer.complete_verified(result)
        else:
            self.writer.complete_rejected(result)

    def prepare(self, record):
        """Validate a charged attempt; return its detached ACDC for RPC dispatch."""
        try:
            return self._verify(record)
        except MissingCredentialArtifactsError as exc:
            self._retry(record, str(exc))
        except (VerificationError, kering.ValidationError) as exc:
            self._finish(record, "rejected", reason=str(exc))
        return None

    def apply_cue(self, cue):
        """Recheck local evidence after RPC and commit one correlated outcome."""
        verification = self.reader.verifying(cue["said"])
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
