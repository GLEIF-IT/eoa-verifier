"""Bound transport replay retention without changing association validity."""

from hio.base import doing
from keri.help import helping


class ReplayPruner(doing.Doer):
    """Borrow the application store and prune one bounded page per second."""

    def __init__(self, *, baser, tock=1.0, **kwa):
        self.baser = baser
        super().__init__(tock=tock, **kwa)

    def recur(self, tyme):
        """Use UTC for signed-message expiry; HIO controls cooperative scheduling."""
        self.baser.prune_replay_claims(int(helping.nowUTC().timestamp()))
        return False
