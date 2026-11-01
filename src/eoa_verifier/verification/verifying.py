"""Verify received external-association ACDCs against local vLEI trust evidence before acceptance.

VerificationService checks the association's schema, LE/QVI source relationships,
GEDA issuance/delegation root, nested SAIDs, accepted TEL status and witnessed
issuance using evidence already validated by KERIpy. The coordinator then obtains
a wallet proof/account result from WalletCheckDoer and returns it to this service;
success rechecks local credential evidence before saving an initial verified result.

This module owns bounded durable attempts and initial-check outcomes. Association
acceptance, permanent nonce consumption, revocation application and webhook delivery
are separate operations. It neither publishes endorsements nor continually checks
Ethereum or fetches missing KERI evidence itself.
"""

import time
from dataclasses import replace

from keri import kering

from eoa_verifier.persistence.records import VerificationResult

from .credentials import verify_association
from .errors import MissingCredentialArtifactsError, VerificationError


class VerificationService:
    """Check an external-association credential's local trust chain and complete its initial result.

    prepare() requires the configured association schema, an untargeted I2I edge to
    an accepted LE credential, an accepted QVI source, issuer/holder continuity, QVI
    issuance and delegation rooted at the configured GEDA, valid nested block SAIDs,
    and locally accepted, witnessed association issuance. CredentialEvidence reads
    KERIpy-validated credentials, TEL status and KEL/witness evidence; this service
    does not replace KERIpy signature or event validation. Missing local evidence is
    retryable; known invalid relationships or revocation reject the candidate.

    The coordinator sends the prepared ACDC to WalletCheckDoer. Its WalletVerifier
    checks the EIP-712 wallet proof, configured Ethereum chain and initial account
    code policy via EthAccountReader. apply_cue() correlates the result with active
    work and repeats local credential checks before committing a successful result,
    so revocation learned locally while RPC was pending causes rejection instead.

    Attempts and retry deadlines are durable and bounded, including interrupted
    attempts. Services decide outcomes using detached reads; writers commit explicit
    phase/result changes. A verified result queues separate application acceptance:
    it neither consumes the association nonce nor proves acceptance, webhook delivery
    or on-chain endorsement. No ongoing account monitoring or remote evidence
    freshness guarantee is provided.
    """

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
        """Borrow credential-evidence and application persistence adapters; own no store or worker.

        reader/writer are verification feature adapters. Scheduled checks also require
        CredentialEvidence, the trusted GEDA AID and the association schema SAID. Offline
        retry/phase operations need only persistence. retry_delay is seconds; clock
        returns UTC Unix seconds for persisted deadlines. max_attempts includes attempts
        interrupted by restart. The coordinator separately owns wallet-check scheduling.
        """
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
        """Persist a prepared initial VerificationResult and settle its verifying phase.

        The caller supplies the completed check outcome; this storage-facing operation
        does not repeat cryptographic checks. Only status verified queues the separate
        application-acceptance phase. Rejected results create no acceptance obligation.
        """
        if result.status == "verified":
            self.writer.complete_verified(result)
        else:
            self.writer.complete_rejected(result)

    def prepare(self, record):
        """Check the association ACDC and accepted LE/QVI source chain before wallet/RPC dispatch.

        record identifies a charged verifying attempt. Return its detached accepted ACDC
        when credential trust, nested SAIDs and witnessed issuance pass. Missing evidence
        persists a bounded retry; invalid/revoked evidence persists a rejected result.
        Those handled failures return None, so no wallet request is dispatched.
        """
        try:
            return self._verify(record)
        except MissingCredentialArtifactsError as exc:
            self._retry(record, str(exc))
        except (VerificationError, kering.ValidationError) as exc:
            self._finish(record, "rejected", reason=str(exc))
        return None

    def apply_cue(self, cue):
        """Apply one correlated wallet-check cue to its active association-credential attempt.

        A retry cue records bounded deferral; a failed proof/account cue records rejection.
        For a verified cue, recheck locally accepted credential/source evidence before
        saving wallet/account facts and queuing acceptance. Missing active work or an
        unknown cue kind raises ValueError. This does not consume nonces or send HTTP.
        """
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
        """Require accepted association/LE/QVI evidence, GEDA trust and witnessed issuance.

        Grant candidate bytes can expose a definite rejection while KERIpy escrows are
        incomplete, but cannot establish acceptance. Delegate concrete credential/edge/
        nested-SAID checks to verify_association and return its accepted ACDC.
        """
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
