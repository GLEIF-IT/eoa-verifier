"""Last observed startup settings; operators own store/deployment compatibility."""


class ScopeStore:
    """Borrow storage for one advisory startup record."""

    def __init__(self, baser):
        """Borrow the application's already-open store."""
        self._db = baser

    def get(self):
        """Return the previous startup settings, or None on first use."""
        return self._db.scope.get(keys=("verification",))

    def save(self, scope):
        """Replace the startup baseline without touching verification or nonce state."""
        self._db.scope.pin(keys=("verification",), val=scope)
