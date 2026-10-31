"""Persist verification, acceptance and delivery independently of KERI evidence."""

import json
from dataclasses import dataclass, field, replace
from itertools import islice

from keri.db import dbing, koming


@dataclass
class PendingVerification:
    """Unfinished initial verification; membership in pending is the only workflow state."""

    associationSaid: str
    grantSaid: str
    reason: str = ""


@dataclass
class VerificationResult:
    """Completed initial check, not application acceptance, ownership or endorsement."""

    associationSaid: str
    status: str  # Workflow-selected verified or rejected outcome.
    reason: str = ""
    eoaResult: dict = field(
        default_factory=dict
    )  # Wallet and initial account observation.


@dataclass
class VerificationScope:
    """Initial-verification policy shared by every result in one persistent store."""

    trustedGedaAid: str
    chainId: int


@dataclass
class ReplayClaim:
    """Durable transport nonce claim, independent of application-event deduplication."""

    expiresAt: int


@dataclass
class AssociationStatus:
    """Stored application acceptance and immutable initially verified association.

    Acceptance is not oracle ownership selection or an Ethereum endorsement.
    There is no expiry; verified association revocation changes status explicitly.
    """

    associationSaid: str
    status: str
    eventId: str
    association: dict
    accountObservation: dict
    reason: str = ""


@dataclass
class Delivery:
    """One immutable event body/target with separately mutable attempt progress."""

    eventId: str
    associationSaid: str
    destination: str
    peerAid: str
    body: str
    acknowledged: bool = False
    attempts: int = 0
    error: str = ""
    # Permanent failure; requires correction and explicit resumption.
    blocked: bool = False


@dataclass
class DestinationSchedule:
    """Persisted destination-wide cooldown and consecutive transient-failure count.

    nextAttemptAt is UTC Unix seconds, not an association-validity deadline.
    """

    failures: int = 0
    nextAttemptAt: float = 0.0


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
        self.replay_claims = koming.Komer(db=self, subkey="replay_claims.", schema=ReplayClaim)
        self.associations = koming.Komer(
            db=self, subkey="associations.", schema=AssociationStatus
        )
        self.outbox = koming.Komer(db=self, subkey="outbox.", schema=Delivery)
        self.destinations = koming.Komer(
            db=self, subkey="destinations.", schema=DestinationSchedule
        )
        return self.env

    def bind_verification_scope(self, *, trusted_geda_aid, chain_id):
        """Refuse another policy or previously completed results with unknown provenance."""
        scope = VerificationScope(trusted_geda_aid, chain_id)
        existing = self.scope.get(keys=("verification",))
        if existing is not None and existing != scope:
            raise ValueError("verifier store belongs to another GEDA root or chain")
        if existing is None and (
            self.results.cntAll() or self.associations.cntAll() or self.outbox.cntAll()
        ):
            raise ValueError("verifier store has unscoped results; use separate stores")
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

    def result_batch(self, *, after="", limit=32):
        """Copy a bounded result page; close the read transaction before acceptance."""
        return self._batch(self.results, after=after, limit=limit)

    def association_batch(self, *, after="", limit=32):
        """Copy a bounded status page for local TEL revocation reconciliation."""
        return self._batch(self.associations, after=after, limit=limit)

    def delivery_batch(self, *, after="", limit=32):
        """Copy a bounded outbox page for pending-delivery discovery, including after restart."""
        return self._batch(self.outbox, after=after, limit=limit)

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

    def accept(self, said, *, association, destination, peer_aid):
        """Atomically persist acceptance and one outbox obligation for a verified result.

        The caller supplies verified issuance facts; storage does not verify credentials.
        Repeated acceptance returns the original status without changing its event,
        body or destination. A failure rolls back all new application records.
        KERIpy stores are outside this LMDB transaction.
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
            event_id = f"{said}:1"
            observation = dict(
                result.eoaResult["accountObservation"], wallet=result.eoaResult["wallet"]
            )
            accepted = AssociationStatus(said, "accepted", event_id, association, observation)
            event = _status_delivery(
                accepted,
                status_revision=1,
                destination=destination,
                peer_aid=peer_aid,
            )
            txn.put(
                key, self.associations.serializer(accepted), db=self.associations.sdb
            )
            txn.put(
                event_id.encode(), self.outbox.serializer(event), db=self.outbox.sdb
            )
            txn.put(
                destination.encode(),
                self.destinations.serializer(DestinationSchedule()),
                db=self.destinations.sdb,
                overwrite=False,
            )
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
            original = self.outbox.deserializer(
                txn.get(current.eventId.encode(), db=self.outbox.sdb)
            )
            retired = replace(
                current, status="revoked", eventId=f"{said}:2", reason="REVOKED"
            )
            event = _status_delivery(
                retired,
                status_revision=2,
                destination=original.destination,
                peer_aid=original.peerAid,
            )
            txn.put(
                key, self.associations.serializer(retired), db=self.associations.sdb
            )
            txn.put(
                event.eventId.encode(),
                self.outbox.serializer(event),
                db=self.outbox.sdb,
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
