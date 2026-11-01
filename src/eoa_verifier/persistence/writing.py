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

    def move_grant(self, previous, source, record, target):
        """Save a prepared Grant phase and remove its expected source and due index.

        source is None for a native notice; other phases are active, waiting or
        dead. Comparing the source bytes prevents a stale caller removing work.
        """
        db = self._db
        tables = {
            "active": db.grant_active,
            "waiting": db.grant_waiting,
            "dead": db.grant_dead,
        }
        table = tables[target]
        key = b"receiver" if target == "active" else record.noticeId.encode()
        raw = table.serializer(record)
        source_table = tables[source] if source else None
        source_key = (
            (b"receiver" if source == "active" else previous.noticeId.encode())
            if source
            else None
        )
        expected = source_table.serializer(previous) if source else None
        old_due = (
            due_key(previous.nextAttemptAt, previous.noticeId)
            if source == "waiting"
            else None
        )
        new_due = (
            due_key(record.nextAttemptAt, record.noticeId)
            if target == "waiting"
            else None
        )
        with db.env.begin(write=True) as txn:
            if source_table is not None:
                if txn.get(source_key, db=source_table.sdb) != expected:
                    raise ValueError("Grant source changed")
                txn.delete(source_key, db=source_table.sdb)
            if old_due is not None:
                txn.delete(old_due, db=db.grant_due.sdb)
            txn.put(key, raw, db=table.sdb)
            if new_due is not None:
                txn.put(new_due, record.noticeId.encode(), db=db.grant_due.sdb)

    def complete_grant(self, record, verification=None):
        """Atomically settle the expected active Grant and enqueue optional work.

        Existing verification work/results retain duplicate semantics. A failed
        insert or source removal aborts both changes, leaving replay recoverable.
        """
        db = self._db
        expected = db.grant_active.serializer(record)
        key = verification.associationSaid.encode() if verification else None
        raw = db.pending.serializer(verification) if verification else None
        with db.env.begin(write=True) as txn:
            if txn.get(b"receiver", db=db.grant_active.sdb) != expected:
                raise ValueError("Grant source changed")
            if verification is not None and not any(
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

    def move_verification(self, previous, source, record, target):
        """Move the expected record and its due index as one prepared write set."""
        db = self._db
        tables = {
            "pending": db.pending,
            "verifying": db.verifying,
            "waiting": db.waiting,
            "dead-letter": db.verification_dead,
        }
        origin, destination = tables[source], tables[target]
        key = record.associationSaid.encode()
        expected, raw = origin.serializer(previous), destination.serializer(record)
        old_due = (
            due_key(previous.nextAttemptAt, previous.associationSaid)
            if source == "waiting"
            else None
        )
        new_due = (
            due_key(record.nextAttemptAt, record.associationSaid)
            if target == "waiting"
            else None
        )
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=origin.sdb) != expected:
                raise ValueError("active verification source is absent or changed")
            txn.delete(key, db=origin.sdb)
            if old_due is not None:
                txn.delete(old_due, db=db.verification_due.sdb)
            txn.put(key, raw, db=destination.sdb)
            if new_due is not None:
                txn.put(new_due, key, db=db.verification_due.sdb)

    def complete_verification(self, result, acceptance):
        """Save an immutable result, optional acceptance obligation and remove active work."""
        db = self._db
        key, raw = result.associationSaid.encode(), db.results.serializer(result)
        acceptance_raw = db.accepting.serializer(acceptance) if acceptance else None
        with db.env.begin(write=True) as txn:
            existing = txn.get(key, db=db.results.sdb)
            if existing is not None:
                if existing != raw:
                    raise ValueError("conflicting verification result")
                return
            if txn.get(key, db=db.verifying.sdb) is None:
                raise ValueError("active verification is absent")
            txn.put(key, raw, db=db.results.sdb)
            if acceptance_raw is not None:
                txn.put(key, acceptance_raw, db=db.accepting.sdb)
            txn.delete(key, db=db.verifying.sdb)

    def move_acceptance(self, previous, record, *, to_dead):
        """Persist a prepared acceptance/dead-letter move against its expected source."""
        db = self._db
        source, target = (
            (db.accepting, db.acceptance_dead)
            if to_dead
            else (db.acceptance_dead, db.accepting)
        )
        key, expected, raw = (
            record.associationSaid.encode(),
            source.serializer(previous),
            target.serializer(record),
        )
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=source.sdb) != expected:
                raise ValueError("acceptance work is absent or changed")
            txn.put(key, raw, db=target.sdb)
            txn.delete(key, db=source.sdb)

    def save_acceptance(
        self, status, claim, delivery=None, reference=None, schedule=None
    ):
        """Insert one prepared outcome with its optional nonce/event obligation atomically.

        False reports an existing immutable association. NonceConflict aborts the
        entire write set so the service can inspect the owner and prepare rejection.
        """
        from .keys import nonce_key

        db = self._db
        key, raw = status.associationSaid.encode(), db.associations.serializer(status)
        claim_key = nonce_key(claim.issuerAid, claim.nonce) if claim else None
        claim_raw = db.accepted_nonces.serializer(claim) if claim else None
        event_key = delivery.eventId.encode() if delivery else None
        event_raw = db.outbox.serializer(delivery) if delivery else None
        ref_raw = db.delivery_ready.serializer(reference) if reference else None
        schedule_key = delivery.destination.encode() if schedule else None
        schedule_raw = db.destinations.serializer(schedule) if schedule else None
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.associations.sdb) is not None:
                return False
            if claim is not None and not txn.put(
                claim_key, claim_raw, db=db.accepted_nonces.sdb, overwrite=False
            ):
                raise NonceConflict()
            txn.put(key, raw, db=db.associations.sdb)
            if event_raw is not None:
                txn.put(event_key, event_raw, db=db.outbox.sdb)
                txn.put(event_key, ref_raw, db=db.delivery_ready.sdb)
            if schedule_raw is not None:
                txn.put(
                    schedule_key, schedule_raw, db=db.destinations.sdb, overwrite=False
                )
            txn.delete(key, db=db.accepting.sdb)
        return True

    def save_retirement(self, previous, status, delivery=None, reference=None):
        """Replace the expected association and insert its prepared revocation event."""
        db = self._db
        key = status.associationSaid.encode()
        expected, raw = (
            db.associations.serializer(previous),
            db.associations.serializer(status),
        )
        event_key = delivery.eventId.encode() if delivery else None
        event_raw = db.outbox.serializer(delivery) if delivery else None
        ref_raw = db.delivery_ready.serializer(reference) if reference else None
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.associations.sdb) != expected:
                raise ValueError("association changed before retirement")
            txn.put(key, raw, db=db.associations.sdb)
            if event_raw is not None:
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
