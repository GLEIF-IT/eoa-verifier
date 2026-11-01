"""Wallet proof/account policy and classification of external observation failures."""

from .eoa import ext_id_chain, verify_eoa_account, verify_eoa_proof


class EoaVerificationService:
    """Verify one proof before observing an account, distinguishing invalid from unavailable."""

    def __init__(self, observer, chain_id):
        """Borrow the RPC observation effect and configured chain policy."""
        self.observer, self.chain_id = observer, chain_id

    def verify(self, association):
        """Yield through one initial observation and return a cue for the ACDC's SAID.

        Local proof/configured-chain ValueErrors and account-policy ValueErrors fail
        the association. OSError or ValueError from RPC observation requests a retry;
        this includes timeouts and a responding node on the wrong chain. Input shape
        is assumed schema-validated. Unexpected programming errors propagate.
        """
        said = association["d"]
        try:
            verify_eoa_proof(association)
            if ext_id_chain(association["a"]["extId"]) != self.chain_id:
                raise ValueError("association chain does not match configured network")
        except ValueError as exc:
            return {"kin": "failed", "said": said, "error": str(exc)}

        wallet = association["a"]["extId"].split(":")[2]
        try:
            observation = yield from self.observer.observe(wallet)
        except (OSError, ValueError) as exc:
            # Transport/RPC failures are not evidence of an invalid credential.
            return {"kin": "retry", "said": said, "error": str(exc)}

        try:
            result = verify_eoa_account(
                association,
                chain_id=observation["chainId"],
                code=bytes.fromhex(observation["code"][2:]),
            )
        except ValueError as exc:
            return {"kin": "failed", "said": said, "error": str(exc)}
        result["accountObservation"] = observation
        return {"kin": "verified", "said": said, "eoaResult": result}
