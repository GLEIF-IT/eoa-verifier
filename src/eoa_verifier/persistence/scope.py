"""Persistent startup scope binding and bounded history-existence checks."""

from .queues import first_record


class ScopeStore:
    """Borrow storage only for startup scope checks and binding."""

    def __init__(self, baser):
        """Borrow the application's already-open store."""
        self._db = baser

    def scope(self):
        """Read the persisted trust/network policy binding."""
        return self._db.scope.get(keys=("verification",))

    def has_history(self):
        """Check history existence from heads, without counting every stored record."""
        return any(
            first_record(table) is not None
            for table in (self._db.results, self._db.associations, self._db.outbox)
        )

    def bind_scope(self, scope):
        """Insert a prepared scope once, rejecting a conflicting storage binding."""
        db = self._db
        raw = db.scope.serializer(scope)
        with db.env.begin(write=True) as txn:
            existing = txn.get(b"verification", db=db.scope.sdb)
            if existing is not None and existing != raw:
                raise ValueError("verifier scope changed")
            txn.put(b"verification", raw, db=db.scope.sdb, overwrite=False)
