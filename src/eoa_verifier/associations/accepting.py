"""Promote completed initial verification to durable acceptance without new RPC work."""

from hio.base import doing
from keri import kering


class AcceptanceDoer(doing.Doer):
    """Commit application acceptance using borrowed evidence and result stores.

    A bounded result scan recovers completion-to-acceptance gaps after restart.
    Read locally stored issuance evidence; do not repeat cryptographic or account
    verification. Missing local evidence leaves the completed result available for
    recovery. Existing accepted status never expires or gets reverified here.
    """

    def __init__(self, *, baser, rgy, destination=None, peer_aid=None, **kwa):
        self.baser, self.rgy = baser, rgy
        self.destination, self.peer_aid = destination, peer_aid
        self.after = ""
        super().__init__(**kwa)

    def recur(self, tyme):
        """Inspect one result page per turn, retaining KERIpy/application store separation."""
        page = self.baser.result_batch(after=self.after)
        if not page:
            self.after = ""
        for result in page:
            self.after = result.associationSaid
            if result.status != "verified" or self.baser.associations.get(
                keys=(self.after,)
            ):
                continue
            evidence = self.issuance_facts(self.after)
            if evidence is not None:
                association, nonce = evidence
                self.baser.accept(
                    self.after,
                    association=association,
                    nonce=nonce,
                    destination=self.destination,
                    peer_aid=self.peer_aid,
                )
        return False

    def issuance_facts(self, said):
        """Read association facts from KERIpy-accepted evidence for a completed verification.

        Return None when evidence is absent or already revoked; this is a local
        status guard before first acceptance, not continuing source monitoring.
        The coordinator already verified signatures, relationships and witnesses.
        """
        reger = self.rgy.reger
        if reger.saved.get(keys=(said,)) is None:
            return None
        credential = reger.creds.get(keys=(said,))
        if credential is None:
            return None
        try:
            state = reger.tevers[credential.regi].vcState(said)
        except (KeyError, kering.MissingEntryError):
            return None
        if state is None or state.et not in ("iss", "bis"):
            return None
        return {
            "issuerAid": credential.issuer,
            "leSaid": credential.edge["le"]["n"],
            "extId": credential.attrib["extId"],
            "issuanceAnchor": {
                "sequenceNumber": state.a["s"],
                "said": state.a["d"],
            },
        }, credential.sad["u"]
