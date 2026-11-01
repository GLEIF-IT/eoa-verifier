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
        self.scope = koming.Komer(db=self, subkey="scope.", schema=VerificationScope)
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

    def claim_nonce(self, peer, nonce, expires_at):
        """Insert a peer/nonce claim after authentication; return False on replay.

        expires_at is the authenticated Unix expiry time in seconds, retained as
        metadata. This method does not prune expired claims or deduplicate
        application events. Claims survive reopening persistent stores.
        """
        return self.replay_claims.put(keys=(peer, nonce), val=ReplayClaim(expires_at))

    def next_delivery(self):
        """Claim one ready event, or resume the single interrupted delivery."""
        with self.env.begin(write=True) as txn:
            deliveryRef = self.delivery_active.deserializer(
                txn.get(b"sender", db=self.delivery_active.sdb)
            )
            if deliveryRef is None:
                with txn.cursor(db=self.delivery_ready.sdb) as cursor:
                    if not cursor.first():
                        return None
                    key, raw = cursor.item()
                    deliveryRef = self.delivery_ready.deserializer(raw)
                    txn.put(
                        b"sender",
                        self.delivery_active.serializer(deliveryRef),
                        db=self.delivery_active.sdb,
                    )
                    txn.delete(key, db=self.delivery_ready.sdb)
            return self.outbox.deserializer(
                txn.get(deliveryRef.eventId.encode(), db=self.outbox.sdb)
            )

    def retry_delivery(self, event_id):
        """Explicitly resume a corrected dead letter with a fresh bounded attempt budget."""
        key = event_id.encode()
        with self.env.begin(write=True) as txn:
            deliveryRef = self.delivery_dead.deserializer(
                txn.get(key, db=self.delivery_dead.sdb)
            )
            if deliveryRef is None:
                raise ValueError("unknown dead-letter event")
            delivery = self.outbox.deserializer(txn.get(key, db=self.outbox.sdb))
            delivery.blocked, delivery.error, delivery.attempts = False, "", 0
            txn.put(key, self.outbox.serializer(delivery), db=self.outbox.sdb)
            txn.put(
                key,
                self.delivery_ready.serializer(deliveryRef),
                db=self.delivery_ready.sdb,
            )
            txn.delete(key, db=self.delivery_dead.sdb)

    def record_attempt(self, event_id, *, next_attempt_at=None):
        """Atomically record the attempt and request-start pacing before network work.

        An interrupted attempt stays pending. The sender supplies scheduling policy;
        resuming an event clears its permanent-error block, not destination cooldown.
        """
        with self.env.begin(write=True) as txn:
            delivery = self.outbox.deserializer(
                txn.get(event_id.encode(), db=self.outbox.sdb)
            )
            if delivery is None:
                raise ValueError("unknown delivery event")
            if delivery.acknowledged:
                return delivery
            delivery.attempts += 1
            delivery.blocked = False
            delivery.error = "attempt started; authenticated ACK not recorded"
            txn.put(
                event_id.encode(), self.outbox.serializer(delivery), db=self.outbox.sdb
            )
            if next_attempt_at is not None:
                schedule = self.destinations.deserializer(
                    txn.get(delivery.destination.encode(), db=self.destinations.sdb)
                )
                schedule.nextAttemptAt = max(schedule.nextAttemptAt, next_attempt_at)
                txn.put(
                    delivery.destination.encode(),
                    self.destinations.serializer(schedule),
                    db=self.destinations.sdb,
                )
            return delivery

    def delivery_result(self, event_id, *, error="", blocked=False, schedule=None):
        """Record failure or authenticated completion; never discard an undelivered event.

        An empty error means the delivery component validated the full ACK contract.
        Failure progress and a supplied destination schedule commit together.
        This method enforces persistence, not authentication or delivery policy.
        """
        with self.env.begin(write=True) as txn:
            raw = txn.get(event_id.encode(), db=self.outbox.sdb)
            if raw is None:
                raise ValueError("unknown delivery event")
            delivery = self.outbox.deserializer(raw)
            if delivery.acknowledged:
                return
            delivery.error = error
            delivery.blocked = blocked
            delivery.acknowledged = not error
            txn.put(
                event_id.encode(), self.outbox.serializer(delivery), db=self.outbox.sdb
            )
            if delivery.acknowledged or delivery.blocked:
                txn.delete(event_id.encode(), db=self.delivery_ready.sdb)
                activeDeliveryRef = self.delivery_active.deserializer(
                    txn.get(b"sender", db=self.delivery_active.sdb)
                )
                if activeDeliveryRef and activeDeliveryRef.eventId == event_id:
                    txn.delete(b"sender", db=self.delivery_active.sdb)
                if delivery.blocked:
                    txn.put(
                        event_id.encode(),
                        self.delivery_dead.serializer(DeliveryReference(event_id)),
                        db=self.delivery_dead.sdb,
                    )
            if delivery.acknowledged:
                raw = txn.get(delivery.destination.encode(), db=self.destinations.sdb)
                schedule = self.destinations.deserializer(raw)
                schedule.failures = 0
            if schedule is not None:
                txn.put(
                    delivery.destination.encode(),
                    self.destinations.serializer(schedule),
                    db=self.destinations.sdb,
                )
