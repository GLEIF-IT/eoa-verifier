"""Reconcile accepted native association revocation with durable application status."""

from hio.base import doing
from keri import kering


class RetirementDoer(doing.Doer):
    """Borrow stores and scan a bounded page of associations each scheduler turn.

    Read accepted local TEL state, without verification refreshes, peer polling or
    account/source checks. The scan recovers native/application commit gaps after
    restart and does not rely on transient cues or a new Grant notification.
    """

    def __init__(self, *, baser, rgy, tock=0.25, **kwa):
        self.baser, self.rgy = baser, rgy
        self.after = ""
        super().__init__(tock=tock, **kwa)

    def recur(self, tyme):
        """Retire only the exact SAID whose native TEL has accepted rev/brv state."""
        page = self.baser.association_batch(after=self.after)
        if not page:
            self.after = ""
        for association in page:
            self.after = association.associationSaid
            if association.status != "accepted":
                continue
            credential = self.rgy.reger.creds.get(keys=(self.after,))
            if credential is None:
                continue
            try:
                state = self.rgy.reger.tevers[credential.regi].vcState(self.after)
            except (KeyError, kering.MissingEntryError):
                continue
            if state is not None and state.et in ("rev", "brv"):
                self.baser.retire(self.after)
        return False
