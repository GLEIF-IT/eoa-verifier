"""Bounded, detached application reads; no query consumes or schedules work."""


def first_record(table):
    """Copy and decode a phase head before closing its short-lived reader."""
    with table.db.env.begin(db=table.sdb) as txn, txn.cursor() as cursor:
        return table.deserializer(bytes(cursor.value())) if cursor.first() else None


def due_record(schedule, waiting):
    """Return the earliest waiting record without applying clock policy or deleting it."""
    with schedule.db.env.begin() as txn, txn.cursor(db=schedule.sdb) as cursor:
        if not cursor.first():
            return None
        record = waiting.deserializer(txn.get(bytes(cursor.value()), db=waiting.sdb))
    if record is None:
        raise ValueError("retry schedule has no waiting work")
    return record


class ApplicationReader:
    """Expose detached records to services while keeping LMDB handles private."""

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
