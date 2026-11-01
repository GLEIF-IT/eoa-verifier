"""Short atomic saves of prepared application records.

Services choose outcomes, budgets and deadlines. Serialization precedes each
transaction; transactions contain only storage guards and their atomic write set.
"""


def due_key(when, identifier):
    """Encode a nonnegative UTC microsecond deadline followed by its item ID."""
    return f"{int(when * 1_000_000):016x}.{identifier}".encode()


class NonceConflict(Exception):
    """Another acceptance owns the nonce; the attempted write set was aborted."""


class ApplicationWriter:
    """Persist concrete application transitions without running workflow policy."""

    def __init__(self, baser):
        """Borrow the application's already-open store."""
        self._db = baser

    def start_grant(self, record):
        """Persist a KERIpy notice in grant_active before KERIpy acknowledgement."""
        db = self._db
        raw = db.grant_active.serializer(record)
        with db.env.begin(write=True) as txn:
            if not txn.put(b"receiver", raw, db=db.grant_active.sdb, overwrite=False):
                raise ValueError("receiver already has an active Grant")

    def resume_grant(self, previous, record):
        """Replace the expected grant_active record with its prepared next attempt."""
        db = self._db
        expected = db.grant_active.serializer(previous)
        raw = db.grant_active.serializer(record)
        with db.env.begin(write=True) as txn:
            if txn.get(b"receiver", db=db.grant_active.sdb) != expected:
                raise ValueError("grant source is absent or changed")
            txn.put(b"receiver", raw, db=db.grant_active.sdb)

    def activate_waiting_grant(self, previous, record):
        """Move grant_waiting to grant_active and remove its due index."""
        db = self._db
        key = record.noticeId.encode()
        expected = db.grant_waiting.serializer(previous)
        raw = db.grant_active.serializer(record)
        old_due = due_key(previous.nextAttemptAt, previous.noticeId)
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.grant_waiting.sdb) != expected:
                raise ValueError("grant source is absent or changed")
            txn.delete(key, db=db.grant_waiting.sdb)
            txn.delete(old_due, db=db.grant_due.sdb)
            txn.put(b"receiver", raw, db=db.grant_active.sdb)

    def defer_grant(self, previous, record):
        """Move grant_active to grant_waiting and insert its prepared deadline."""
        db = self._db
        key = record.noticeId.encode()
        expected = db.grant_active.serializer(previous)
        raw = db.grant_waiting.serializer(record)
        new_due = due_key(record.nextAttemptAt, record.noticeId)
        with db.env.begin(write=True) as txn:
            if txn.get(b"receiver", db=db.grant_active.sdb) != expected:
                raise ValueError("grant source is absent or changed")
            txn.delete(b"receiver", db=db.grant_active.sdb)
            txn.put(key, raw, db=db.grant_waiting.sdb)
            txn.put(new_due, key, db=db.grant_due.sdb)

    def dead_letter_grant(self, previous, record):
        """Move grant_active to grant_dead after replay failure or interruption."""
        db = self._db
        key = record.noticeId.encode()
        expected = db.grant_active.serializer(previous)
        raw = db.grant_dead.serializer(record)
        with db.env.begin(write=True) as txn:
            if txn.get(b"receiver", db=db.grant_active.sdb) != expected:
                raise ValueError("grant source is absent or changed")
            txn.delete(b"receiver", db=db.grant_active.sdb)
            txn.put(key, raw, db=db.grant_dead.sdb)

    def dead_letter_waiting_grant(self, previous, record):
        """Move exhausted grant_waiting to grant_dead and remove its deadline."""
        db = self._db
        key = record.noticeId.encode()
        expected = db.grant_waiting.serializer(previous)
        raw = db.grant_dead.serializer(record)
        old_due = due_key(previous.nextAttemptAt, previous.noticeId)
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.grant_waiting.sdb) != expected:
                raise ValueError("grant source is absent or changed")
            txn.delete(key, db=db.grant_waiting.sdb)
            txn.delete(old_due, db=db.grant_due.sdb)
            txn.put(key, raw, db=db.grant_dead.sdb)

    def retry_dead_grant(self, previous, record):
        """Move corrected grant_dead to grant_waiting with its reset deadline."""
        db = self._db
        key = record.noticeId.encode()
        expected = db.grant_dead.serializer(previous)
        raw = db.grant_waiting.serializer(record)
        new_due = due_key(record.nextAttemptAt, record.noticeId)
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.grant_dead.sdb) != expected:
                raise ValueError("grant source is absent or changed")
            txn.delete(key, db=db.grant_dead.sdb)
            txn.put(key, raw, db=db.grant_waiting.sdb)
            txn.put(new_due, key, db=db.grant_due.sdb)

    def complete_grant(self, record, verification):
        """Atomically settle the expected active Grant and enqueue verification work.

        Existing verification work/results retain duplicate semantics. A failed
        insert or source removal aborts both changes, leaving replay recoverable.
        """
        db = self._db
        expected = db.grant_active.serializer(record)
        key = verification.associationSaid.encode()
        raw = db.pending.serializer(verification)
        with db.env.begin(write=True) as txn:
            if txn.get(b"receiver", db=db.grant_active.sdb) != expected:
                raise ValueError("Grant source changed")
            if not any(
                txn.get(key, db=table.sdb) is not None
                for table in (
                    db.results,
                    db.verifying,
                    db.waiting,
                    db.verification_dead,
                )
            ):
                txn.put(key, raw, db=db.pending.sdb, overwrite=False)
            txn.delete(b"receiver", db=db.grant_active.sdb)

    def discard_unrelated_notice(self, record):
        """Remove an active KERIpy notice whose route is outside IPEX Grant handling."""
        db = self._db
        expected = db.grant_active.serializer(record)
        with db.env.begin(write=True) as txn:
            if txn.get(b"receiver", db=db.grant_active.sdb) != expected:
                raise ValueError("Grant source changed")
            txn.delete(b"receiver", db=db.grant_active.sdb)

    def enqueue_verification(self, verification):
        """Insert unfinished work once, preserving existing work and immutable results."""
        db = self._db
        key, raw = (
            verification.associationSaid.encode(),
            db.pending.serializer(verification),
        )
        with db.env.begin(write=True) as txn:
            if any(
                txn.get(key, db=table.sdb) is not None
                for table in (
                    db.results,
                    db.verifying,
                    db.waiting,
                    db.verification_dead,
                )
            ):
                return False
            return txn.put(key, raw, db=db.pending.sdb, overwrite=False)

    def pending_to_verifying(self, previous, record):
        """Move pending to verifying with a prepared charged attempt."""
        db = self._db
        key = record.associationSaid.encode()
        expected = db.pending.serializer(previous)
        raw = db.verifying.serializer(record)
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.pending.sdb) != expected:
                raise ValueError("verification source is absent or changed")
            txn.delete(key, db=db.pending.sdb)
            txn.put(key, raw, db=db.verifying.sdb)

    def resume_verifying(self, previous, record):
        """Replace interrupted verifying work with its prepared next attempt."""
        db = self._db
        key = record.associationSaid.encode()
        expected = db.verifying.serializer(previous)
        raw = db.verifying.serializer(record)
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.verifying.sdb) != expected:
                raise ValueError("verification source is absent or changed")
            txn.put(key, raw, db=db.verifying.sdb)

    def waiting_to_verifying(self, previous, record):
        """Move waiting to verifying and remove its due index."""
        db = self._db
        key = record.associationSaid.encode()
        expected = db.waiting.serializer(previous)
        raw = db.verifying.serializer(record)
        old_due = due_key(previous.nextAttemptAt, previous.associationSaid)
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.waiting.sdb) != expected:
                raise ValueError("verification source is absent or changed")
            txn.delete(key, db=db.waiting.sdb)
            txn.delete(old_due, db=db.verification_due.sdb)
            txn.put(key, raw, db=db.verifying.sdb)

    def verifying_to_waiting(self, previous, record):
        """Move verifying to waiting with a prepared retry deadline."""
        db = self._db
        key = record.associationSaid.encode()
        expected = db.verifying.serializer(previous)
        raw = db.waiting.serializer(record)
        new_due = due_key(record.nextAttemptAt, record.associationSaid)
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.verifying.sdb) != expected:
                raise ValueError("verification source is absent or changed")
            txn.delete(key, db=db.verifying.sdb)
            txn.put(key, raw, db=db.waiting.sdb)
            txn.put(new_due, key, db=db.verification_due.sdb)

    def verifying_to_dead_letter(self, previous, record):
        """Move failed or interrupted verifying work to verification_dead."""
        db = self._db
        key = record.associationSaid.encode()
        expected = db.verifying.serializer(previous)
        raw = db.verification_dead.serializer(record)
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.verifying.sdb) != expected:
                raise ValueError("verification source is absent or changed")
            txn.delete(key, db=db.verifying.sdb)
            txn.put(key, raw, db=db.verification_dead.sdb)

    def waiting_to_dead_letter(self, previous, record):
        """Move exhausted waiting work to verification_dead and remove its deadline."""
        db = self._db
        key = record.associationSaid.encode()
        expected = db.waiting.serializer(previous)
        raw = db.verification_dead.serializer(record)
        old_due = due_key(previous.nextAttemptAt, previous.associationSaid)
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.waiting.sdb) != expected:
                raise ValueError("verification source is absent or changed")
            txn.delete(key, db=db.waiting.sdb)
            txn.delete(old_due, db=db.verification_due.sdb)
            txn.put(key, raw, db=db.verification_dead.sdb)

    def pending_to_dead_letter(self, previous, record):
        """Move exhausted pending work to verification_dead."""
        db = self._db
        key = record.associationSaid.encode()
        expected = db.pending.serializer(previous)
        raw = db.verification_dead.serializer(record)
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.pending.sdb) != expected:
                raise ValueError("verification source is absent or changed")
            txn.delete(key, db=db.pending.sdb)
            txn.put(key, raw, db=db.verification_dead.sdb)

    def dead_letter_to_pending(self, previous, record):
        """Move corrected verification_dead work to pending with a reset budget."""
        db = self._db
        key = record.associationSaid.encode()
        expected = db.verification_dead.serializer(previous)
        raw = db.pending.serializer(record)
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.verification_dead.sdb) != expected:
                raise ValueError("verification source is absent or changed")
            txn.delete(key, db=db.verification_dead.sdb)
            txn.put(key, raw, db=db.pending.sdb)

    def complete_verified_candidate(self, result):
        """Commit result and acceptance obligation and remove verifying work atomically."""
        db = self._db
        key, raw = result.associationSaid.encode(), db.results.serializer(result)
        acceptance_raw = db.accepting.serializer(result)
        with db.env.begin(write=True) as txn:
            existing = txn.get(key, db=db.results.sdb)
            if existing is not None:
                if existing != raw:
                    raise ValueError("conflicting verification result")
                return
            if txn.get(key, db=db.verifying.sdb) is None:
                raise ValueError("active verification is absent")
            txn.put(key, raw, db=db.results.sdb)
            txn.put(key, acceptance_raw, db=db.accepting.sdb)
            txn.delete(key, db=db.verifying.sdb)

    def complete_rejected_candidate(self, result):
        """Commit rejected result and remove verifying work atomically."""
        db = self._db
        key, raw = result.associationSaid.encode(), db.results.serializer(result)
        with db.env.begin(write=True) as txn:
            existing = txn.get(key, db=db.results.sdb)
            if existing is not None:
                if existing != raw:
                    raise ValueError("conflicting verification result")
                return
            if txn.get(key, db=db.verifying.sdb) is None:
                raise ValueError("active verification is absent")
            txn.put(key, raw, db=db.results.sdb)
            txn.delete(key, db=db.verifying.sdb)

    def dead_letter_acceptance(self, previous, record):
        """Move accepting to acceptance_dead with a prepared diagnostic."""
        db = self._db
        key = record.associationSaid.encode()
        expected = db.accepting.serializer(previous)
        raw = db.acceptance_dead.serializer(record)
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.accepting.sdb) != expected:
                raise ValueError("acceptance source is absent or changed")
            txn.delete(key, db=db.accepting.sdb)
            txn.put(key, raw, db=db.acceptance_dead.sdb)

    def retry_dead_acceptance(self, previous, record):
        """Move corrected acceptance_dead back to accepting."""
        db = self._db
        key = record.associationSaid.encode()
        expected = db.acceptance_dead.serializer(previous)
        raw = db.accepting.serializer(record)
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.acceptance_dead.sdb) != expected:
                raise ValueError("acceptance source is absent or changed")
            txn.delete(key, db=db.acceptance_dead.sdb)
            txn.put(key, raw, db=db.accepting.sdb)

    def accept_association(self, status, nonce):
        """Commit nonce ownership and accepted status without delivery.

        False means this SAID already has status. NonceConflict aborts all writes.
        """
        from .keys import nonce_key
        from .records import AcceptedNonce

        db = self._db
        key, raw = status.associationSaid.encode(), db.associations.serializer(status)
        claim_key = nonce_key(nonce)
        claim_raw = db.accepted_nonces.serializer(AcceptedNonce(status.associationSaid))
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.associations.sdb) is not None:
                return False
            if not txn.put(
                claim_key, claim_raw, db=db.accepted_nonces.sdb, overwrite=False
            ):
                raise NonceConflict()
            txn.put(key, raw, db=db.associations.sdb)
            txn.delete(key, db=db.accepting.sdb)
        return True

    def accept_and_queue_delivery(self, status, nonce, delivery, reference, schedule):
        """Commit nonce ownership and accepted status with its ready event.

        False means this SAID already has status. NonceConflict aborts all writes.
        """
        from .keys import nonce_key
        from .records import AcceptedNonce

        db = self._db
        key, raw = status.associationSaid.encode(), db.associations.serializer(status)
        claim_key = nonce_key(nonce)
        claim_raw = db.accepted_nonces.serializer(AcceptedNonce(status.associationSaid))
        event_key, event_raw = delivery.eventId.encode(), db.outbox.serializer(delivery)
        ref_raw = db.delivery_ready.serializer(reference)
        schedule_key, schedule_raw = (
            delivery.destination.encode(),
            db.destinations.serializer(schedule),
        )
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.associations.sdb) is not None:
                return False
            if not txn.put(
                claim_key, claim_raw, db=db.accepted_nonces.sdb, overwrite=False
            ):
                raise NonceConflict()
            txn.put(key, raw, db=db.associations.sdb)
            txn.put(event_key, event_raw, db=db.outbox.sdb)
            txn.put(event_key, ref_raw, db=db.delivery_ready.sdb)
            txn.put(schedule_key, schedule_raw, db=db.destinations.sdb, overwrite=False)
            txn.delete(key, db=db.accepting.sdb)
        return True

    def reject_reused_nonce(self, status):
        """Save nonce-reuse rejection and remove accepting; never write a nonce or event."""
        db = self._db
        key, raw = status.associationSaid.encode(), db.associations.serializer(status)
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.associations.sdb) is not None:
                return False
            txn.put(key, raw, db=db.associations.sdb)
            txn.delete(key, db=db.accepting.sdb)
        return True

    def record_revocation(self, previous, status):
        """Replace accepted status with revoked status without delivery."""
        db = self._db
        key = status.associationSaid.encode()
        expected, raw = (
            db.associations.serializer(previous),
            db.associations.serializer(status),
        )
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.associations.sdb) != expected:
                raise ValueError("association changed before revocation")
            txn.put(key, raw, db=db.associations.sdb)

    def record_revocation_and_queue_delivery(
        self, previous, status, delivery, reference
    ):
        """Replace accepted status with revoked status and its ready revocation event."""
        db = self._db
        key = status.associationSaid.encode()
        expected, raw = (
            db.associations.serializer(previous),
            db.associations.serializer(status),
        )
        event_key, event_raw = delivery.eventId.encode(), db.outbox.serializer(delivery)
        ref_raw = db.delivery_ready.serializer(reference)
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.associations.sdb) != expected:
                raise ValueError("association changed before revocation")
            txn.put(key, raw, db=db.associations.sdb)
            txn.put(event_key, event_raw, db=db.outbox.sdb)
            txn.put(event_key, ref_raw, db=db.delivery_ready.sdb)

    def bind_scope(self, scope):
        """Insert a prepared scope once, rejecting a conflicting storage binding."""
        db = self._db
        raw = db.scope.serializer(scope)
        with db.env.begin(write=True) as txn:
            existing = txn.get(b"verification", db=db.scope.sdb)
            if existing is not None and existing != raw:
                raise ValueError("verifier scope changed")
            txn.put(b"verification", raw, db=db.scope.sdb, overwrite=False)

    def claim_nonce(self, peer, nonce, expires_at):
        """Atomically reserve an authenticated transport nonce without overwriting replay history."""
        from .records import ReplayClaim

        return self._db.replay_claims.put(
            keys=(peer, nonce), val=ReplayClaim(expires_at)
        )

    def delivery_ready_to_active(self, reference):
        """Move the expected ready reference to the single active sender slot."""
        db = self._db
        key, raw = reference.eventId.encode(), db.delivery_ready.serializer(reference)
        active_raw = db.delivery_active.serializer(reference)
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.delivery_ready.sdb) != raw:
                raise ValueError("ready delivery changed")
            if txn.get(b"sender", db=db.delivery_active.sdb) is not None:
                raise ValueError("sender already has active delivery")
            txn.put(b"sender", active_raw, db=db.delivery_active.sdb)
            txn.delete(key, db=db.delivery_ready.sdb)

    def record_delivery_attempt(self, previous, delivery, schedule):
        """Persist charged outbox progress and request-start pacing before HTTP."""
        db = self._db
        key = delivery.eventId.encode()
        expected, raw = db.outbox.serializer(previous), db.outbox.serializer(delivery)
        schedule_key, schedule_raw = (
            delivery.destination.encode(),
            db.destinations.serializer(schedule),
        )
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.outbox.sdb) != expected:
                raise ValueError("delivery changed before completion")
            txn.put(key, raw, db=db.outbox.sdb)
            txn.put(schedule_key, schedule_raw, db=db.destinations.sdb)

    def defer_delivery(self, previous, delivery, schedule):
        """Persist retry progress and cooldown, retaining the active reference."""
        db = self._db
        key = delivery.eventId.encode()
        expected, raw = db.outbox.serializer(previous), db.outbox.serializer(delivery)
        schedule_key, schedule_raw = (
            delivery.destination.encode(),
            db.destinations.serializer(schedule),
        )
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.outbox.sdb) != expected:
                raise ValueError("delivery changed before completion")
            txn.put(key, raw, db=db.outbox.sdb)
            txn.put(schedule_key, schedule_raw, db=db.destinations.sdb)

    def acknowledge_delivery(self, previous, delivery, schedule, reference):
        """Persist authenticated ACK progress and remove the matching ready/active references."""
        db = self._db
        key = delivery.eventId.encode()
        expected, raw = db.outbox.serializer(previous), db.outbox.serializer(delivery)
        schedule_key, schedule_raw = (
            delivery.destination.encode(),
            db.destinations.serializer(schedule),
        )
        active_raw = db.delivery_active.serializer(reference)
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.outbox.sdb) != expected:
                raise ValueError("delivery changed before completion")
            txn.put(key, raw, db=db.outbox.sdb)
            txn.put(schedule_key, schedule_raw, db=db.destinations.sdb)
            txn.delete(key, db=db.delivery_ready.sdb)
            if txn.get(b"sender", db=db.delivery_active.sdb) == active_raw:
                txn.delete(b"sender", db=db.delivery_active.sdb)

    def dead_letter_delivery(self, previous, delivery, schedule, reference):
        """Persist failed progress and move matching ready/active references to delivery_dead."""
        db = self._db
        key = delivery.eventId.encode()
        expected, raw = db.outbox.serializer(previous), db.outbox.serializer(delivery)
        schedule_key, schedule_raw = (
            delivery.destination.encode(),
            db.destinations.serializer(schedule),
        )
        active_raw = db.delivery_active.serializer(reference)
        dead_raw = db.delivery_dead.serializer(reference)
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.outbox.sdb) != expected:
                raise ValueError("delivery changed before completion")
            txn.put(key, raw, db=db.outbox.sdb)
            txn.put(schedule_key, schedule_raw, db=db.destinations.sdb)
            txn.delete(key, db=db.delivery_ready.sdb)
            if txn.get(b"sender", db=db.delivery_active.sdb) == active_raw:
                txn.delete(b"sender", db=db.delivery_active.sdb)
            txn.put(key, dead_raw, db=db.delivery_dead.sdb)

    def retry_dead_delivery(self, previous, delivery, reference):
        """Save a prepared reset and move its expected dead reference back to ready."""
        db = self._db
        key, raw = delivery.eventId.encode(), db.outbox.serializer(delivery)
        expected = db.outbox.serializer(previous)
        dead_raw = db.delivery_dead.serializer(reference)
        ready_raw = db.delivery_ready.serializer(reference)
        with db.env.begin(write=True) as txn:
            if (
                txn.get(key, db=db.delivery_dead.sdb) != dead_raw
                or txn.get(key, db=db.outbox.sdb) != expected
            ):
                raise ValueError("dead-letter delivery changed")
            txn.put(key, raw, db=db.outbox.sdb)
            txn.put(key, ready_raw, db=db.delivery_ready.sdb)
            txn.delete(key, db=db.delivery_dead.sdb)
