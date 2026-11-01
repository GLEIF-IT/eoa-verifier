"""Explicit test fixture preparation; not a production enqueue API."""


def enqueue_verification(baser, verification):
    """Insert unfinished work once, preserving existing work and immutable results."""
    db = baser
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
