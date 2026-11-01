"""Wallet proof/account policy and classification of external observation failures."""

from .eoa import ext_id_chain, verify_eoa_account, verify_eoa_proof


class WalletVerifier:
    """Check the association's EIP-712 wallet proof, Ethereum chain and initial account-code policy.

    The borrowed EthAccountReader supplies one identified-block account snapshot.
    Return a verified/failed/retry cue; own no credential evidence, persistent phases
    or acceptance policy. Invalid local proofs fail before any RPC is attempted.
    """

    def __init__(self, account_reader, chain_id):
        """Borrow the Ethereum account reader and configured chain policy."""
        self.account_reader, self.chain_id = account_reader, chain_id

    def verify(self, association):
        """Check one schema-validated association's wallet proof and initial Ethereum account.

        Return a cue keyed by its ACDC SAID. Proof/configured-chain mismatches fail before
        RPC. Then read chain/block/code and apply the EOA/EIP-7702 code rule. Account-policy
        ValueErrors fail the candidate; OSError or ValueError from RPC reads requests a
        retry, including timeouts or a node on the wrong chain. Unexpected programming
        errors propagate. Successful accountObservation describes this initial snapshot,
        not ongoing ownership, code safety, local acceptance or on-chain endorsement.
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
            observation = yield from self.account_reader.read(wallet)
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
