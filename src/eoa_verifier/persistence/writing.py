"""Short atomic saves of prepared application records.

Services choose outcomes, budgets and deadlines. Serialization precedes each
transaction; transactions contain only storage guards and their atomic write set.
"""


def due_key(when, identifier):
    """Encode a nonnegative UTC microsecond deadline followed by its item ID."""
    return f"{int(when * 1_000_000):016x}.{identifier}".encode()


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
