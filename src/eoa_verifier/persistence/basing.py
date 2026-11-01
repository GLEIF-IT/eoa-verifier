"""Persist verification, acceptance and delivery independently of KERI evidence."""

import json
import re
from dataclasses import replace

from keri.db import dbing, koming, subing

from .records import (
    AcceptedNonce,
    AssociationStatus,
    Delivery,
    DeliveryReference,
    DestinationSchedule,
    GrantWork,
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
        self.verifying = koming.Komer(
            db=self, subkey="verifying.", schema=PendingVerification
        )
        self.waiting = koming.Komer(
            db=self, subkey="waiting.", schema=PendingVerification
        )
        self.verification_due = subing.Suber(db=self, subkey="verification-due.")
        self.grant_due = subing.Suber(db=self, subkey="grant-due.")
        self.verification_dead = koming.Komer(
            db=self, subkey="verification-dead.", schema=PendingVerification
        )
        self.grant_active = koming.Komer(
            db=self, subkey="grant-active.", schema=GrantWork
        )
        self.grant_waiting = koming.Komer(
            db=self, subkey="grant-waiting.", schema=GrantWork
        )
        self.grant_dead = koming.Komer(db=self, subkey="grant-dead.", schema=GrantWork)
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

    def bind_verification_scope(self, *, trusted_geda_aid, chain_id):
        """Refuse another policy or previously completed results with unknown provenance."""
        scope = VerificationScope(trusted_geda_aid, chain_id, "durable-phases-v1")
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
            if any(
                txn.get(key, db=table.sdb) is not None
                for table in (
                    self.results,
                    self.verifying,
                    self.waiting,
                    self.verification_dead,
                )
            ):
                return False
            return txn.put(
                key, self.pending.serializer(work), db=self.pending.sdb, overwrite=False
            )

    def begin_grant(self, notice=None, *, now, max_attempts=3):
        """Claim one native notice or resume an interrupted/local waiting replay.

        The caller removes the native notice only after this durable handoff. Its
        ID remains in active work, so restart can finish that acknowledgement.
        """
        with self.env.begin(write=True) as txn:
            work = self.grant_active.deserializer(
                txn.get(b"receiver", db=self.grant_active.sdb)
            )
            if work is None:
                work = due_record(txn, self.grant_due, self.grant_waiting, now)
                if work is not None:
                    txn.delete(work.noticeId.encode(), db=self.grant_waiting.sdb)
                elif notice is not None:
                    work = GrantWork(notice.rid, notice.attrs)
                else:
                    return None
            if work.attempts >= max_attempts:
                work.reason = (
                    work.reason or "Grant replay interrupted; attempt budget exhausted"
                )
                txn.put(
                    work.noticeId.encode(),
                    self.grant_dead.serializer(work),
                    db=self.grant_dead.sdb,
                )
                txn.delete(b"receiver", db=self.grant_active.sdb)
                return None
            work.attempts += 1
            txn.put(
                b"receiver",
                self.grant_active.serializer(work),
                db=self.grant_active.sdb,
            )
            return work

    def settle_grant(
        self, work, *, reason="", next_attempt_at=0, invalid=False, max_attempts=3
    ):
        """Acknowledge replay or atomically retain failed material for waiting/manual recovery."""
        with self.env.begin(write=True) as txn:
            if reason or invalid:
                target = (
                    self.grant_dead
                    if invalid or work.attempts >= max_attempts
                    else self.grant_waiting
                )
                work = replace(work, reason=reason, nextAttemptAt=next_attempt_at)
                txn.put(work.noticeId.encode(), target.serializer(work), db=target.sdb)
                if target is self.grant_waiting:
                    txn.put(
                        due_key(work.nextAttemptAt, work.noticeId),
                        work.noticeId.encode(),
                        db=self.grant_due.sdb,
                    )
            txn.delete(b"receiver", db=self.grant_active.sdb)

    def retry_grant(self, notice_id):
        """Resume a corrected Grant dead letter without requiring another IPEX delivery."""
        key = notice_id.encode()
        with self.env.begin(write=True) as txn:
            work = self.grant_dead.deserializer(txn.get(key, db=self.grant_dead.sdb))
            if work is None:
                raise ValueError("unknown Grant dead letter")
            work = replace(work, attempts=0, nextAttemptAt=0, reason="")
            txn.put(key, self.grant_waiting.serializer(work), db=self.grant_waiting.sdb)
            txn.put(due_key(0, work.noticeId), key, db=self.grant_due.sdb)
            txn.delete(key, db=self.grant_dead.sdb)

    def retry_acceptance(self, said):
        """Recheck a stopped acceptance after restoring its local evidence."""
        key = said.encode()
        with self.env.begin(write=True) as txn:
            result = self.acceptance_dead.deserializer(
                txn.get(key, db=self.acceptance_dead.sdb)
            )
            if result is None:
                raise ValueError("unknown acceptance dead letter")
            result = replace(result, reason="")
            txn.put(key, self.accepting.serializer(result), db=self.accepting.sdb)
            txn.delete(key, db=self.acceptance_dead.sdb)

    def next_verification(self, *, now, max_attempts=3):
        """Durably begin one attempt, resuming interrupted work before new work.

        Due retries take precedence over new work. A time-ordered index
        selects eligible waiting work without walking the waiting records.
        Interrupted attempts count against the same finite budget after restart.
        """
        with self.env.begin(write=True) as txn:
            for table in (self.verifying, self.waiting, self.pending):
                if table is self.waiting:
                    work = due_record(txn, self.verification_due, self.waiting, now)
                    if work is None:
                        continue
                    key = work.associationSaid.encode()
                else:
                    with txn.cursor(db=table.sdb) as cursor:
                        if not cursor.first():
                            continue
                        key, raw = cursor.item()
                        work = table.deserializer(raw)
                txn.delete(key, db=table.sdb)
                if work.attempts >= max_attempts:
                    work.reason = (
                        work.reason
                        or "verification interrupted; attempt budget exhausted"
                    )
                    txn.put(
                        key,
                        self.verification_dead.serializer(work),
                        db=self.verification_dead.sdb,
                    )
                    return None
                work.attempts += 1
                work.reason = "verification attempt started; result not committed"
                txn.put(key, self.verifying.serializer(work), db=self.verifying.sdb)
                return work
        return None

    def defer_verification(self, work, *, reason, next_attempt_at, max_attempts=3):
        """Move the active attempt to durable waiting or dead letter in one commit."""
        key = work.associationSaid.encode()
        work = replace(work, reason=reason, nextAttemptAt=next_attempt_at)
        target = (
            self.verification_dead if work.attempts >= max_attempts else self.waiting
        )
        with self.env.begin(write=True) as txn:
            if txn.get(key, db=self.verifying.sdb) is None:
                raise ValueError("active verification is absent")
            txn.put(key, target.serializer(work), db=target.sdb)
            if target is self.waiting:
                txn.put(
                    due_key(work.nextAttemptAt, work.associationSaid),
                    key,
                    db=self.verification_due.sdb,
                )
            txn.delete(key, db=self.verifying.sdb)

    def verification_progress(self, said):
        """Read one candidate's phase without discovering work from result history."""
        for phase, table in (
            ("pending", self.pending),
            ("verifying", self.verifying),
            ("waiting", self.waiting),
            ("dead-letter", self.verification_dead),
        ):
            work = table.get(keys=(said,))
            if work is not None:
                return phase, work
        return None, None

    def retry_verification(self, said):
        """Explicitly give a dead-letter candidate a new bounded attempt budget."""
        key = said.encode()
        with self.env.begin(write=True) as txn:
            work = self.verification_dead.deserializer(
                txn.get(key, db=self.verification_dead.sdb)
            )
            if work is None:
                raise ValueError("unknown verification dead letter")
            work = replace(work, attempts=0, nextAttemptAt=0, reason="")
            txn.put(key, self.pending.serializer(work), db=self.pending.sdb)
            txn.delete(key, db=self.verification_dead.sdb)

    def finish(self, result):
        """Atomically complete active verification and enqueue successful acceptance.

        The workflow chooses the outcome. Identical repeat completion is harmless;
        a missing active record cannot be completed for the first time. Serialization
        or storage failure aborts the whole transaction, leaving active work recoverable.
        """
        key = result.associationSaid.encode()
        with self.env.begin(write=True) as txn:
            existing = txn.get(key, db=self.results.sdb)
            if existing is not None:
                if self.results.deserializer(existing) != result:
                    raise ValueError("conflicting verification result")
                return
            if txn.get(key, db=self.verifying.sdb) is None:
                raise ValueError("active verification is absent")
            txn.put(key, self.results.serializer(result), db=self.results.sdb)
            if result.status == "verified":
                txn.put(key, self.accepting.serializer(result), db=self.accepting.sdb)
            txn.delete(key, db=self.verifying.sdb)

    def claim_nonce(self, peer, nonce, expires_at):
        """Insert a peer/nonce claim after authentication; return False on replay.

        expires_at is the authenticated Unix expiry time in seconds, retained as
        metadata. This method does not prune expired claims or deduplicate
        application events. Claims survive reopening persistent stores.
        """
        return self.replay_claims.put(keys=(peer, nonce), val=ReplayClaim(expires_at))

    def next_acceptance(self):
        """Read one local acceptance obligation; its transaction consumes it on success."""
        return first_record(self.accepting)

    def stop_acceptance(self, said, reason):
        """Dead-letter missing or revoked evidence instead of repeatedly rediscovering it."""
        key = said.encode()
        with self.env.begin(write=True) as txn:
            result = self.accepting.deserializer(txn.get(key, db=self.accepting.sdb))
            if result is None:
                raise ValueError("acceptance work is absent")
            result = replace(result, reason=reason)
            txn.put(
                key,
                self.acceptance_dead.serializer(result),
                db=self.acceptance_dead.sdb,
            )
            txn.delete(key, db=self.accepting.sdb)

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


def first_record(table):
    """Detach the head of a phase and close its reader before any caller can mutate."""
    with table.db.env.begin(db=table.sdb) as txn, txn.cursor() as cursor:
        return table.deserializer(cursor.value()) if cursor.first() else None


def due_key(when, identifier):
    """Sort an unfinished retry deadline by nonnegative UTC microseconds, then ID."""
    return f"{int(when * 1_000_000):016x}.{identifier}".encode()


def due_record(txn, schedule, waiting, now):
    """Consume one eligible deadline index inside its phase-transition transaction."""
    with txn.cursor(db=schedule.sdb) as cursor:
        if not cursor.first():
            return None
        deadline, key = cursor.item()
        work = waiting.deserializer(txn.get(key, db=waiting.sdb))
    if work is None:
        raise ValueError("retry schedule has no waiting work")
    if work.nextAttemptAt > now:
        return None
    txn.delete(deadline, db=schedule.sdb)
    return work
