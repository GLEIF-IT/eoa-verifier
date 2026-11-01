"""Consume accepted TEL revocation identifiers, one credential per scheduler turn."""

from hio.base import doing


class RetirementDoer(doing.Doer):
    """Borrow both stores; retire locally before removing the native revocation record.

    A crash between commits repeats an idempotent retirement. Revocation before
    initial acceptance is handled by verification and the acceptance TEL guard;
    unrelated credentials do not create application status or delivery events.
    """

    def __init__(self, *, baser, rgy, tock=0.25, **kwa):
        """Borrow the application store and service-owned VerifierReger."""
        self.baser, self.rgy = baser, rgy
        super().__init__(tock=tock, **kwa)

    def recur(self, tyme):
        """Apply one credential revocation; completed association history is never a work source."""
        revocationIds = self.rgy.reger.next_revocation()
        if revocationIds is not None:
            credSaid, _telEvtSaid = revocationIds
            # The TEL event SAID records provenance; retirement selects by credential.
            associationStatus = self.baser.associations.get(keys=(credSaid,))
            if associationStatus is not None and associationStatus.status == "accepted":
                self.baser.retire(credSaid)
            self.rgy.reger.revocations.rem(keys=(credSaid,))
        return False
