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
        """Borrow adapters; native evidence is unnecessary for offline phase operations."""
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
        for source in ("verifying", "waiting", "pending"):
            record = self.reader.verification(source)
            if record is None or (source == "waiting" and record.nextAttemptAt > now):
                continue
            if record.attempts >= max_attempts:
                dead = replace(
                    record,
                    reason=record.reason
                    or "verification interrupted; attempt budget exhausted",
                )
                self.writer.move_verification(record, source, dead, "dead-letter")
                return None
            active = replace(
                record,
                attempts=record.attempts + 1,
                reason="verification attempt started; result not committed",
            )
            self.writer.move_verification(record, source, active, "verifying")
            return active
        return None

    def defer_verification(self, record, *, reason, next_attempt_at, max_attempts=3):
        """Choose waiting or dead letter without holding a transaction during policy."""
        target = "dead-letter" if record.attempts >= max_attempts else "waiting"
        updated = replace(record, reason=reason, nextAttemptAt=next_attempt_at)
        self.writer.move_verification(record, "verifying", updated, target)

    def retry(self, cred_said):
        """Reset one corrected dead letter with the service stopped."""
        record = self.reader.verification("dead-letter", cred_said)
        if record is None:
            raise ValueError("unknown verification dead letter")
        updated = replace(record, attempts=0, nextAttemptAt=0, reason="")
        self.writer.move_verification(record, "dead-letter", updated, "pending")

    def finish(self, result):
        """Prepare an acceptance obligation only for a verified result."""
        self.writer.complete_verification(
            result, result if result.status == "verified" else None
        )

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
        verification = self.reader.verification("verifying", cue["said"])
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
        """Require native acceptance; Grant bytes can justify rejection, never acceptance."""
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
