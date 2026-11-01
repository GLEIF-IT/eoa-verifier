"""Promote completed initial verification to durable acceptance without new RPC work."""

from hio.base import doing
from keri import kering


class AcceptanceDoer(doing.Doer):
    """Commit application acceptance using borrowed evidence and result stores.

    The accepting phase recovers completion-to-acceptance gaps after restart.
    Read locally stored issuance evidence; do not repeat cryptographic or account
    verification. Missing or revoked local evidence stops in a dead letter for
    operator inspection. Existing accepted status never expires or gets reverified here.
    """

    def __init__(self, *, baser, rgy, destination=None, peer_aid=None, **kwa):
        self.baser, self.rgy = baser, rgy
        self.destination, self.peer_aid = destination, peer_aid
        super().__init__(**kwa)

    def recur(self, tyme):
        """Inspect one unfinished acceptance per turn, retaining KERIpy/application store separation."""
        verificationResult = self.baser.next_acceptance()
        if verificationResult is None:
            return False
        issuanceFacts = self.issuance_facts(verificationResult.associationSaid)
        if issuanceFacts is None:
            self.baser.stop_acceptance(
                verificationResult.associationSaid,
                "issuance evidence missing or revoked before acceptance",
            )
        else:
            associationFacts, nonce = issuanceFacts
            self.baser.accept(
                verificationResult.associationSaid,
                associationFacts=associationFacts,
                nonce=nonce,
                destination=self.destination,
                peer_aid=self.peer_aid,
            )
        return False

    def issuance_facts(self, credSaid):
        """Read association facts from KERIpy-accepted evidence for a completed verification.

        Return None when evidence is absent or already revoked; this is a local
        status guard before first acceptance, not continuing source monitoring.
        The coordinator already verified signatures, relationships and witnesses.
        """
        reger = self.rgy.reger
        if reger.saved.get(keys=(credSaid,)) is None:
            return None
        credential = reger.creds.get(keys=(credSaid,))
        if credential is None:
            return None
        try:
            state = reger.tevers[credential.regi].vcState(credSaid)
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
