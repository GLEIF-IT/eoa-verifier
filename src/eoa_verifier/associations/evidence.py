"""Native association issuance facts and accepted TEL revocation identifiers."""

from keri import kering


class AssociationEvidence:
    """Borrow Regery; return copied issuance facts and explicit revocation IDs."""

    def __init__(self, rgy):
        self._rgy = rgy

    def next_revocation(self):
        """Detach one credential/TEL-event SAID pair from the native queue."""
        return self._rgy.reger.next_revocation()

    def remove_revocation(self, cred_said):
        """Acknowledge native revocation after idempotent application retirement."""
        self._rgy.reger.revocations.rem(keys=(cred_said,))

    def issuance_facts(self, credSaid):
        """Read association facts from KERIpy-accepted evidence for a completed verification.

        Return None when evidence is absent or already revoked; this is a local
        status guard before first acceptance, not continuing source monitoring.
        The coordinator already verified signatures, relationships and witnesses.
        """
        reger = self._rgy.reger
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
