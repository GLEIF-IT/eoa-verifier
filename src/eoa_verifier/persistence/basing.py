"""Persist verification, acceptance and delivery independently of KERI evidence."""

from keri.db import dbing, koming, subing

from .records import (
    AcceptedNonce,
    AssociationStatus,
    Delivery,
    DeliveryReference,
    DestinationSchedule,
    GrantReplayRecord,
    ReplayClaim,
    VerificationRecord,
    VerificationResult,
    VerificationScope,
)


class VerifierBaser(dbing.LMDBer):
    """Own atomic application records and replay claims; make no verification decisions."""

    TailDirPath = "eoa-verifier/db"
    AltTailDirPath = ".eoa-verifier/db"
    TempPrefix = "eoa_verifier_db_"

    def reopen(self, **kwa):
        """Open verification, acceptance/outbox and transport replay tables in one environment."""
        super().reopen(**kwa)
        self.scope = koming.Komer(db=self, subkey="startup.", schema=VerificationScope)
        self.pending = koming.Komer(
            db=self, subkey="pending.", schema=VerificationRecord
        )
        self.verifying = koming.Komer(
            db=self, subkey="verifying.", schema=VerificationRecord
        )
        self.waiting = koming.Komer(
            db=self, subkey="waiting.", schema=VerificationRecord
        )
        self.verification_due = subing.Suber(db=self, subkey="verification-due.")
        self.grant_due = subing.Suber(db=self, subkey="grant-due.")
        self.verification_dead = koming.Komer(
            db=self, subkey="verification-dead.", schema=VerificationRecord
        )
        self.grant_active = koming.Komer(
            db=self, subkey="grant-active.", schema=GrantReplayRecord
        )
        self.grant_waiting = koming.Komer(
            db=self, subkey="grant-waiting.", schema=GrantReplayRecord
        )
        self.grant_dead = koming.Komer(
            db=self, subkey="grant-dead.", schema=GrantReplayRecord
        )
        self.acceptance_dead = koming.Komer(
            db=self, subkey="acceptance-dead.", schema=VerificationResult
        )
        self.results = koming.Komer(
            db=self, subkey="results.", schema=VerificationResult
        )
        self.replay_claims = koming.Komer(
            db=self, subkey="replay_claims.", schema=ReplayClaim
        )
        self.associations = koming.Komer(
            db=self, subkey="associations.", schema=AssociationStatus
        )
        self.accepted_nonces = koming.Komer(
            db=self, subkey="accepted_nonces.", schema=AcceptedNonce
        )
        self.outbox = koming.Komer(db=self, subkey="outbox.", schema=Delivery)
        self.accepting = koming.Komer(
            db=self, subkey="accepting.", schema=VerificationResult
        )
        self.delivery_ready = koming.Komer(
            db=self, subkey="delivery-ready.", schema=DeliveryReference
        )
        self.delivery_active = koming.Komer(
            db=self, subkey="delivery-active.", schema=DeliveryReference
        )
        self.delivery_dead = koming.Komer(
            db=self, subkey="delivery-dead.", schema=DeliveryReference
        )
        self.destinations = koming.Komer(
            db=self, subkey="destinations.", schema=DestinationSchedule
        )
        return self.env
