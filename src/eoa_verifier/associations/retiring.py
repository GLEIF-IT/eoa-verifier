"""Consume accepted TEL revocation handoffs, one credential per scheduler turn."""

from hio.base import doing


class RetirementDoer(doing.Doer):
    """Borrow both stores; retire locally before acknowledging the native handoff.

    A crash between commits repeats an idempotent retirement. Revocation before
    initial acceptance is handled by verification and the acceptance TEL guard;
    unrelated credentials do not create application status or delivery events.
    """

    def __init__(self, *, baser, rgy, tock=0.25, **kwa):
        """Borrow the application store and service-owned VerifierReger."""
        self.baser, self.rgy = baser, rgy
        super().__init__(tock=tock, **kwa)

    def recur(self, tyme):
        """Apply one handoff; completed association history is never a work source."""
        handoff = self.rgy.reger.next_revocation()
        if handoff is not None:
            said, _ = handoff
            association = self.baser.associations.get(keys=(said,))
            if association is not None and association.status == "accepted":
                self.baser.retire(said)
            self.rgy.reger.revocations.rem(keys=(said,))
        return False
