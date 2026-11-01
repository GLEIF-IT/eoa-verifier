"""Persist verification, acceptance and delivery independently of KERI evidence."""

from keri.db import dbing, koming, subing

from .records import (
    AcceptedNonce,
    AssociationStatus,
    Delivery,
    DeliveryReference,
    DestinationSchedule,
    GrantReplayRecord,
    VerificationRecord,
    VerificationResult,
    VerificationScope,
)


class VerifierBaser(dbing.LMDBer):
    """Own the application LMDB environment and its non-duplicate table bindings.

    Use KERIpy name/base/headDirPath/temp/reopen lifecycle options (normally through
    openLMDB). Persistent close retains results, consumed nonces and queued work;
    temporary context closure follows LMDBer's cleanup. This store is separate from
    Habery KEL state and VerifierReger TEL/credential evidence. Komer values are JSON
    records; Suber retry indexes hold UTF-8 identifiers. Services own all decisions.
    """

    # Persistent application-store directory below LMDBer's head/base/name roots.
    TailDirPath = "eoa-verifier/db"
    # LMDBer alternate relative directory when the default root is unavailable.
    AltTailDirPath = ".eoa-verifier/db"
    # Prefix for LMDBer-owned disposable test-store directories.
    TempPrefix = "eoa_verifier_db_"

    def reopen(self, **kwa):
        """Open the environment and bind the application schema; return the LMDB environment.

        kwa passes through to LMDBer.reopen. Comments below describe each table's raw
        key and decoded value; unless stated otherwise keys are UTF-8 identifiers and
        Komer stores non-duplicate JSON records. Opening binds tables, not work policy.
        """
        super().reopen(**kwa)
        # "verification" -> VerificationScope: last startup settings, for warnings only.
        self.scope = koming.Komer(db=self, subkey="startup.", schema=VerificationScope)
        # Credential SAID -> VerificationRecord: fresh initial-verification work.
        self.pending = koming.Komer(
            db=self, subkey="pending.", schema=VerificationRecord
        )
        # Credential SAID -> VerificationRecord: charged/in-flight or interrupted check.
        self.verifying = koming.Komer(
            db=self, subkey="verifying.", schema=VerificationRecord
        )
        # Credential SAID -> VerificationRecord: deferred checks indexed by due time.
        self.waiting = koming.Komer(
            db=self, subkey="waiting.", schema=VerificationRecord
        )
        # 16-hex UTC Unix microseconds + "." + credential SAID -> credential SAID.
        # Ordered retry index into waiting; the service decides when the head is due.
        self.verification_due = subing.Suber(db=self, subkey="verification-due.")
        # 16-hex UTC Unix microseconds + "." + notice ID -> notice ID.
        # Ordered retry index into grant_waiting, not a history-discovery scan.
        self.grant_due = subing.Suber(db=self, subkey="grant-due.")
        # Credential SAID -> VerificationRecord: stopped checks awaiting manual retry.
        self.verification_dead = koming.Komer(
            db=self, subkey="verification-dead.", schema=VerificationRecord
        )
        # "receiver" -> GrantReplayRecord: sole current/interrupted IPEX Grant replay.
        self.grant_active = koming.Komer(
            db=self, subkey="grant-active.", schema=GrantReplayRecord
        )
        # Notice ID -> GrantReplayRecord: deferred replay with a grant_due entry.
        self.grant_waiting = koming.Komer(
            db=self, subkey="grant-waiting.", schema=GrantReplayRecord
        )
        # Notice ID -> GrantReplayRecord: stopped replay awaiting operator recovery.
        self.grant_dead = koming.Komer(
            db=self, subkey="grant-dead.", schema=GrantReplayRecord
        )
        # Credential SAID -> VerificationResult: stopped application acceptance.
        # The completed initial check remains independently in results.
        self.acceptance_dead = koming.Komer(
            db=self, subkey="acceptance-dead.", schema=VerificationResult
        )
        # Credential SAID -> VerificationResult: retained completed initial outcome.
        self.results = koming.Komer(
            db=self, subkey="results.", schema=VerificationResult
        )
        # Credential SAID -> AssociationStatus: accepted/rejected/revoked local status.
        self.associations = koming.Komer(
            db=self, subkey="associations.", schema=AssociationStatus
        )
        # Exact 1-128 ASCII nonce bytes -> AcceptedNonce (diagnostic credential owner).
        # Any existing key means globally consumed; never release it on revocation.
        self.accepted_nonces = koming.Komer(
            db=self, subkey="accepted_nonces.", schema=AcceptedNonce
        )
        # "<credential SAID>:<revision>" -> Delivery: exact JSON/URL and attempt progress.
        # Revision 1 is acceptance, 2 is revocation; phases reference this event ID.
        self.outbox = koming.Komer(db=self, subkey="outbox.", schema=Delivery)
        # Credential SAID -> VerificationResult: verified, awaiting local acceptance.
        self.accepting = koming.Komer(
            db=self, subkey="accepting.", schema=VerificationResult
        )
        # Event ID -> DeliveryReference: ready unsent work, separate from history.
        self.delivery_ready = koming.Komer(
            db=self, subkey="delivery-ready.", schema=DeliveryReference
        )
        # "sender" -> DeliveryReference: sole current/interrupted HTTP delivery.
        self.delivery_active = koming.Komer(
            db=self, subkey="delivery-active.", schema=DeliveryReference
        )
        # Event ID -> DeliveryReference: stopped delivery; outbox bytes stay retained.
        self.delivery_dead = koming.Komer(
            db=self, subkey="delivery-dead.", schema=DeliveryReference
        )
        # Exact destination URL bytes -> DestinationSchedule: shared pacing/backoff.
        # nextAttemptAt is UTC Unix seconds, never an association expiry.
        self.destinations = koming.Komer(
            db=self, subkey="destinations.", schema=DestinationSchedule
        )
        return self.env
