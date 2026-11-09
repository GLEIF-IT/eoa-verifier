"""KERIpy association issuance facts, chain sources and accepted TEL revocation identifiers."""

from keri import kering


class RevokedCredential(Exception):
    """A credential in the association's chain is revoked; str() is the rejection reason."""


class AssociationEvidence:
    """Borrow Regery; return copied issuance facts and explicit revocation IDs."""

    def __init__(self, rgy):
        """Borrow the already-open KERIpy registry without owning its lifecycle."""
        self._rgy = rgy

    def next_revocation(self):
        """Detach one credential/TEL-event SAID pair from the KERIpy queue."""
        return self._rgy.reger.next_revocation()

    def remove_revocation(self, cred_said):
        """Acknowledge KERIpy revocation after its application effect is durably recorded."""
        self._rgy.reger.revocations.rem(keys=(cred_said,))

    def issuance_facts(self, credSaid):
        """Read association facts and verified chain sources for a completed verification.

        Return (facts, nonce, {"le": leSaid, "qvi": qviSaid}), or None when evidence
        for the association, its LE or its QVI credential is absent. Raise
        RevokedCredential when any of them is known to be revoked. This is a local
        status guard before first acceptance, not continuing source monitoring.
        The coordinator already verified signatures, relationships and witnesses.
        """
        credential = self._issued(credSaid, "association")
        if credential is None:
            return None
        leSaid = credential.edge["le"]["n"]
        le = self._issued(leSaid, "LE")
        if le is None:
            return None
        qviSaid = le.edge["qvi"]["n"]
        if self._issued(qviSaid, "QVI") is None:
            return None
        state = self._state(credential)
        return {
            "issuerAid": credential.issuer,
            "leSaid": leSaid,
            "extId": credential.attrib["extId"],
            "issuanceAnchor": {
                "sequenceNumber": state.a["s"],
                "said": state.a["d"],
            },
        }, credential.sad["u"], {"le": leSaid, "qvi": qviSaid}

    def _issued(self, said, label):
        """Return the stored credential if saved and issued, or None if evidence is absent.

        label names the credential's chain position in the RevokedCredential reason.
        """
        reger = self._rgy.reger
        if reger.saved.get(keys=(said,)) is None:
            return None
        credential = reger.creds.get(keys=(said,))
        if credential is None:
            return None
        state = self._state(credential)
        if state is None:
            return None
        if state.et in ("rev", "brv"):
            raise RevokedCredential(f"{label} credential {said} is revoked")
        return credential

    def _state(self, credential):
        """Return a credential's current TEL state, or None when no local state exists."""
        try:
            return self._rgy.reger.tevers[credential.regi].vcState(credential.said)
        except (KeyError, kering.MissingEntryError):
            return None
