"""Bounded, detached application reads; no query consumes or schedules work."""


def first_record(table):
    """Copy and decode a phase head before closing its short-lived reader."""
    with table.db.env.begin(db=table.sdb) as txn, txn.cursor() as cursor:
        return table.deserializer(bytes(cursor.value())) if cursor.first() else None


def due_record(schedule, waiting):
    """Detach the earliest indexed waiting record, or None when the index is empty.

    schedule maps deadline/item keys to waiting-table keys. Copy/read the record
    inside a bounded reader and close it before returning. A dangling index raises
    ValueError. A future deadline still returns its record: the service, not this
    read helper, decides whether it is due. Neither table is changed.
    """
    with schedule.db.env.begin() as txn, txn.cursor(db=schedule.sdb) as cursor:
        if not cursor.first():
            return None
        record = waiting.deserializer(txn.get(bytes(cursor.value()), db=waiting.sdb))
    if record is None:
        raise ValueError("retry schedule has no waiting work")
    return record


def due_key(when, identifier):
    """Encode a nonnegative UTC microsecond deadline followed by its item ID."""
    return f"{int(when * 1_000_000):016x}.{identifier}".encode()
