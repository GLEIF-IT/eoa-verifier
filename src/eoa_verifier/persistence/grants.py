"""Grants persistence: bounded reads and explicit atomic writes."""

from .queues import due_key, due_record


class GrantReader:
    """Borrow the open store for grants persistence only."""

    def __init__(self, baser):
        """Borrow the application's already-open store."""
        self._db = baser

    def active_grant(self):
        """Return the receiver's interrupted Grant, if any."""
        return self._db.grant_active.get(keys=("receiver",))

    def waiting_grant(self):
        """Return the earliest indexed Grant, including one whose deadline is future."""
        return due_record(self._db.grant_due, self._db.grant_waiting)

    def dead_grant(self, notice_id):
        """Return one identified Grant dead letter."""
        return self._db.grant_dead.get(keys=(notice_id,))


class GrantWriter:
    """Borrow the open store for grants persistence only."""

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
