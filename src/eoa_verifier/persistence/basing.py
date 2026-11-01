"""Persist verification, acceptance and delivery independently of KERI evidence."""

import json
import re
from dataclasses import replace
from itertools import islice

from keri.db import dbing, koming

from .records import (
    AcceptedNonce,
    AssociationStatus,
    Delivery,
    DeliveryReference,
    DestinationSchedule,
    PendingVerification,
    ReplayClaim,
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
            db=self, subkey="pending.", schema=PendingVerification
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

    def bind_verification_scope(self, *, trusted_geda_aid, chain_id):
        """Refuse another policy or previously completed results with unknown provenance."""
        scope = VerificationScope(trusted_geda_aid, chain_id, "issuer-nonce-ascii-v1")
        try:
            existing = self.scope.get(keys=("verification",))
        except (TypeError, ValueError) as exc:
            raise ValueError("unsupported verifier policy; use a fresh store") from exc
        if existing is not None and existing != scope:
            raise ValueError(
                "verifier store belongs to another GEDA root, chain or acceptance policy"
            )
        if existing is None and (
            self.results.cntAll() or self.associations.cntAll() or self.outbox.cntAll()
        ):
            raise ValueError("verifier store has unscoped results; use separate stores")
        self.validate_nonce_history()
        self.scope.put(keys=("verification",), val=scope)

    def enqueue(self, work):
        """Insert new unfinished work once; completed or pending duplicates return False."""
        key = work.associationSaid.encode()
        with self.env.begin(write=True) as txn:
            if txn.get(key, db=self.results.sdb) is not None:
                return False
            return txn.put(
                key, self.pending.serializer(work), db=self.pending.sdb, overwrite=False
            )

    def note_pending(self, said, reason):
        """Update only waiting information, preserving identity and the first Grant reference."""
        key = said.encode()
        with self.env.begin(write=True) as txn:
            raw = txn.get(key, db=self.pending.sdb)
            if raw is None:
                raise ValueError("pending work is absent")
            work = self.pending.deserializer(raw)
            if work.reason != reason:
                work.reason = reason
                txn.put(key, self.pending.serializer(work), db=self.pending.sdb)

    def finish(self, result):
        """Atomically insert a result and remove pending work; reject conflicting completion.

        The workflow chooses the outcome. Identical repeat completion is harmless;
        a missing pending record cannot be completed for the first time. Serialization
        or storage failure aborts the whole transaction, leaving pending recoverable.
        """
        key = result.associationSaid.encode()
        with self.env.begin(write=True) as txn:
            existing = txn.get(key, db=self.results.sdb)
            if existing is not None:
                if self.results.deserializer(existing) != result:
                    raise ValueError("conflicting verification result")
                return
            if txn.get(key, db=self.pending.sdb) is None:
                raise ValueError("pending work is absent")
            txn.put(key, self.results.serializer(result), db=self.results.sdb)
            if result.status == "verified":
                txn.put(key, self.accepting.serializer(result), db=self.accepting.sdb)
            txn.delete(key, db=self.pending.sdb)

    def pending_batch(self, *, after="", limit=32):
        """Copy a bounded page strictly after the SAID; close its cursor before returning."""
        return self._batch(self.pending, after=after, limit=limit)

    def claim_nonce(self, peer, nonce, expires_at):
        """Insert a peer/nonce claim after authentication; return False on replay.

        expires_at is the authenticated Unix expiry time in seconds, retained as
        metadata. This method does not prune expired claims or deduplicate
        application events. Claims survive reopening persistent stores.
        """
        return self.replay_claims.put(keys=(peer, nonce), val=ReplayClaim(expires_at))

    def acceptance_batch(self, *, after="", limit=1):
        """Copy unfinished acceptance only; completed results never schedule work."""
        return self._batch(self.accepting, after=after, limit=limit)

    def association_batch(self, *, after="", limit=32):
        """Copy a bounded status page for local TEL revocation reconciliation."""
        return self._batch(self.associations, after=after, limit=limit)

    def next_delivery(self):
        """Claim one ready event, or resume the single interrupted delivery."""
        with self.env.begin(write=True) as txn:
            reference = self.delivery_active.deserializer(
                txn.get(b"sender", db=self.delivery_active.sdb)
            )
            if reference is None:
                with txn.cursor(db=self.delivery_ready.sdb) as cursor:
                    if not cursor.first():
                        return None
                    key, raw = cursor.item()
                    reference = self.delivery_ready.deserializer(raw)
                    txn.put(
                        b"sender",
                        self.delivery_active.serializer(reference),
                        db=self.delivery_active.sdb,
                    )
                    txn.delete(key, db=self.delivery_ready.sdb)
            return self.outbox.deserializer(
                txn.get(reference.eventId.encode(), db=self.outbox.sdb)
            )

    def retry_delivery(self, event_id):
        """Explicitly resume a corrected dead letter with a fresh bounded attempt budget."""
        key = event_id.encode()
        with self.env.begin(write=True) as txn:
            reference = self.delivery_dead.deserializer(
                txn.get(key, db=self.delivery_dead.sdb)
            )
            if reference is None:
                raise ValueError("unknown dead-letter event")
            event = self.outbox.deserializer(txn.get(key, db=self.outbox.sdb))
            event.blocked, event.error, event.attempts = False, "", 0
            txn.put(key, self.outbox.serializer(event), db=self.outbox.sdb)
            txn.put(
                key,
                self.delivery_ready.serializer(reference),
                db=self.delivery_ready.sdb,
            )
            txn.delete(key, db=self.delivery_dead.sdb)

    def _batch(self, table, *, after, limit):
        """Seek strictly after a key and release the LMDB cursor before returning."""
        with self.env.begin(db=table.sdb) as txn, txn.cursor() as cursor:
            if not cursor.set_range(after.encode()):
                return []
            if after and cursor.key() == after.encode() and not cursor.next():
                return []
            return [
                table.deserializer(raw) for _, raw in islice(cursor.iternext(), limit)
            ]

    def nonce_key(self, issuer, nonce):
        """Use Komer's ordinary issuer.nonce key; neither component contains dots."""
        if not isinstance(issuer, str) or not issuer or "." in issuer:
            raise ValueError("issuer AID is required and cannot contain a dot")
        if (
            not isinstance(nonce, str)
            or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", nonce) is None
        ):
            raise ValueError(
                "nonce must contain 1 to 128 ASCII letters, digits, underscores or hyphens"
            )
        return self.accepted_nonces._tokey((issuer, nonce))

    def _read_claim(self, txn, key, raw):
        """Fail closed on corrupt claims, mismatched keys or orphaned ownership."""
        try:
            claim = self.accepted_nonces.deserializer(raw)
            if not isinstance(claim.associationSaid, str) or not claim.associationSaid:
                raise ValueError("missing accepted SAID")
            if self.nonce_key(claim.issuerAid, claim.nonce) != key:
                raise ValueError("claim key mismatch")
            owner = self.associations.deserializer(
                txn.get(claim.associationSaid.encode(), db=self.associations.sdb)
            )
            if (
                owner is None
                or owner.status not in ("accepted", "revoked")
                or owner.associationSaid != claim.associationSaid
                or owner.association["issuerAid"] != claim.issuerAid
            ):
                raise ValueError("claim has no accepted owner")
            return claim
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            raise ValueError("inconsistent accepted nonce claim") from exc

    def validate_nonce_history(self):
        """Require complete acceptance history at startup; never backfill old stores."""
        with self.env.begin() as txn:
            owners = set()
            with txn.cursor(db=self.accepted_nonces.sdb) as cursor:
                for key, raw in cursor:
                    claim = self._read_claim(txn, key, raw)
                    if claim.associationSaid in owners:
                        raise ValueError(
                            "multiple nonce claims for one accepted association"
                        )
                    owners.add(claim.associationSaid)
            with txn.cursor(db=self.associations.sdb) as cursor:
                for key, raw in cursor:
                    status = self.associations.deserializer(raw)
                    if status.associationSaid.encode() != key:
                        raise ValueError("inconsistent association key")
                    if (
                        status.status in ("accepted", "revoked")
                        and status.associationSaid not in owners
                    ):
                        raise ValueError(
                            "accepted associations lack nonce history; use a fresh store"
                        )

    def accept(self, said, *, association, nonce, destination=None, peer_aid=None):
        """Commit nonce ownership, local acceptance and optional delivery together.

        Facts and the exact nonce come from already verified native evidence.
        Another SAID owning this issuer/nonce produces terminal NONCE_REUSED
        application rejection; initial cryptographic verification stays unchanged.
        Same-SAID replay returns its original outcome, including after revocation.
        Native LMDB transactions supply all writer coordination and durability.
        """
        key = said.encode()
        with self.env.begin(write=True) as txn:
            previous = txn.get(key, db=self.associations.sdb)
            if previous is not None:
                return self.associations.deserializer(previous)
            raw = txn.get(key, db=self.results.sdb)
            result = self.results.deserializer(raw) if raw is not None else None
            if result is None or result.status != "verified":
                raise ValueError("acceptance requires a completed verified result")
            if bool(destination) != bool(peer_aid):
                raise ValueError("delivery requires both destination and peer AID")
            claim = AcceptedNonce(association["issuerAid"], nonce, said)
            nonce_key = self.nonce_key(claim.issuerAid, nonce)
            inserted = txn.put(
                nonce_key,
                self.accepted_nonces.serializer(claim),
                db=self.accepted_nonces.sdb,
                overwrite=False,
            )
            observation = dict(
                result.eoaResult["accountObservation"],
                wallet=result.eoaResult["wallet"],
            )
            if not inserted:
                self._read_claim(
                    txn, nonce_key, txn.get(nonce_key, db=self.accepted_nonces.sdb)
                )
                rejected = AssociationStatus(
                    said, "rejected", "", association, observation, "NONCE_REUSED"
                )
                txn.put(
                    key,
                    self.associations.serializer(rejected),
                    db=self.associations.sdb,
                )
                txn.delete(key, db=self.accepting.sdb)
                return rejected
            accepted = AssociationStatus(
                said,
                "accepted",
                f"{said}:1" if destination else "",
                association,
                observation,
            )
            txn.put(
                key, self.associations.serializer(accepted), db=self.associations.sdb
            )
            if destination:
                event = _status_delivery(
                    accepted,
                    status_revision=1,
                    destination=destination,
                    peer_aid=peer_aid,
                )
                txn.put(
                    event.eventId.encode(),
                    self.outbox.serializer(event),
                    db=self.outbox.sdb,
                )
                txn.put(
                    event.eventId.encode(),
                    self.delivery_ready.serializer(DeliveryReference(event.eventId)),
                    db=self.delivery_ready.sdb,
                )
                txn.put(
                    destination.encode(),
                    self.destinations.serializer(DestinationSchedule()),
                    db=self.destinations.sdb,
                    overwrite=False,
                )
            txn.delete(key, db=self.accepting.sdb)
            return accepted

    def retire(self, said):
        """Atomically retire an accepted SAID and create its separate delivery obligation.

        The caller establishes verified revocation. Preserve original issuance facts,
        observation and delivery destination/peer; never change another association.
        Repeated retirement returns the same status/event, including across restart.
        KERIpy TEL persistence is separate and recovered by the retirement worker.
        """
        key = said.encode()
        with self.env.begin(write=True) as txn:
            current = self.associations.deserializer(
                txn.get(key, db=self.associations.sdb)
            )
            if current is None:
                raise ValueError("retirement requires an accepted association")
            if current.status == "revoked":
                return current
            if current.status != "accepted":
                raise ValueError("retirement requires an accepted association")
            original = None
            if current.eventId:
                original = self.outbox.deserializer(
                    txn.get(current.eventId.encode(), db=self.outbox.sdb)
                )
                if original is None:
                    raise ValueError("accepted delivery event is absent")
            retired = replace(
                current,
                status="revoked",
                eventId=f"{said}:2" if original else "",
                reason="REVOKED",
            )
            txn.put(
                key, self.associations.serializer(retired), db=self.associations.sdb
            )
            if original is not None:
                event = _status_delivery(
                    retired,
                    status_revision=2,
                    destination=original.destination,
                    peer_aid=original.peerAid,
                )
                txn.put(
                    event.eventId.encode(),
                    self.outbox.serializer(event),
                    db=self.outbox.sdb,
                )
                txn.put(
                    event.eventId.encode(),
                    self.delivery_ready.serializer(DeliveryReference(event.eventId)),
                    db=self.delivery_ready.sdb,
                )
            return retired

    def record_attempt(self, event_id, *, next_attempt_at=None):
        """Atomically record the attempt and request-start pacing before network work.

        An interrupted attempt stays pending. The sender supplies scheduling policy;
        resuming an event clears its permanent-error block, not destination cooldown.
        """
        with self.env.begin(write=True) as txn:
            event = self.outbox.deserializer(
                txn.get(event_id.encode(), db=self.outbox.sdb)
            )
            if event is None:
                raise ValueError("unknown delivery event")
            if event.acknowledged:
                return event
            event.attempts += 1
            event.blocked = False
            event.error = "attempt started; authenticated ACK not recorded"
            txn.put(
                event_id.encode(), self.outbox.serializer(event), db=self.outbox.sdb
            )
            if next_attempt_at is not None:
                schedule = self.destinations.deserializer(
                    txn.get(event.destination.encode(), db=self.destinations.sdb)
                )
                schedule.nextAttemptAt = max(schedule.nextAttemptAt, next_attempt_at)
                txn.put(
                    event.destination.encode(),
                    self.destinations.serializer(schedule),
                    db=self.destinations.sdb,
                )
            return event

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
            event = self.outbox.deserializer(raw)
            if event.acknowledged:
                return
            event.error = error
            event.blocked = blocked
            event.acknowledged = not error
            txn.put(
                event_id.encode(), self.outbox.serializer(event), db=self.outbox.sdb
            )
            if event.acknowledged or event.blocked:
                txn.delete(event_id.encode(), db=self.delivery_ready.sdb)
                active = self.delivery_active.deserializer(
                    txn.get(b"sender", db=self.delivery_active.sdb)
                )
                if active and active.eventId == event_id:
                    txn.delete(b"sender", db=self.delivery_active.sdb)
                if event.blocked:
                    txn.put(
                        event_id.encode(),
                        self.delivery_dead.serializer(DeliveryReference(event_id)),
                        db=self.delivery_dead.sdb,
                    )
            if event.acknowledged:
                raw = txn.get(event.destination.encode(), db=self.destinations.sdb)
                schedule = self.destinations.deserializer(raw)
                schedule.failures = 0
            if schedule is not None:
                txn.put(
                    event.destination.encode(),
                    self.destinations.serializer(schedule),
                    db=self.destinations.sdb,
                )


def _status_delivery(status, *, status_revision, destination, peer_aid):
    """Serialize one immutable v1 event for the existing outbox/ACK protocol."""
    payload = {
        "version": "1",
        "eventId": status.eventId,
        "associationSaid": status.associationSaid,
        "statusRevision": status_revision,
        "status": status.status,
        "association": status.association,
        "accountObservation": status.accountObservation,
    }
    if status.reason:
        payload["reasonCode"] = status.reason
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    return Delivery(status.eventId, status.associationSaid, destination, peer_aid, body)
