"""HIO request/cue flow for EOA proof and account verification."""

import re

from hio.base import doing
from hio.core import http
from hio.help import decking
from keri.help import helping

from eoa_verifier.verification.rpc import RpcClientDoer, request_rpc
from eoa_verifier.verification.eoa import (
    ext_id_chain,
    verify_eoa_account,
    verify_eoa_proof,
)


class EoaVerifierDoer(doing.DoDoer):
    """Own initial wallet verification and one sequential account observation at a time.

    msgs contains schema-validated association ACDC dictionaries, including d, i,
    u, a.extId, a.proof and e.le.n. cues contains ordinary dictionaries:
    - {kin: "verified", said, eoaResult: {wallet, accountObservation}};
    - {kin: "failed", said, error} for an invalid wallet proof or account;
    - {kin: "retry", said, error} for unavailable or unusable RPC responses.

    accountObservation contains chainId and blockNumber integers, blockHash and code hex
    strings, and observedAt ISO timestamp. The coordinator persists successful
    observations with completed results; this worker owns no application storage. Programming errors
    propagate instead of becoming retry cues. Each HTTP ClientDoer is a child whose
    lifetime ends on completion, failure or cancellation.
    """

    def __init__(self, *, rpc_url, chain_id, timeout=5.0, **kwa):
        """Configure the trusted rpc_url, expected chain_id and per-call timeout in seconds.

        msgs and cues are transient HIO decks; the coordinator persists work status
        instead of these queues. kwa supplies HIO DoDoer options such as scheduling tock.
        """
        self.rpc_url = rpc_url
        self.chain_id = chain_id
        self.timeout = timeout
        self.msgs = decking.Deck()
        self.cues = decking.Deck()
        super().__init__(doers=[doing.doify(self.verify_do)], **kwa)

    def verify_do(self, tymth, tock=0.0, **opts):
        """Yield on the HIO clock while idle; process messages sequentially and append cues.

        This long-lived generator has no result of its own. Cancellation unwinds any
        active observation through its child-client cleanup.
        """
        yield tock
        while True:
            if not self.msgs:
                yield self.tock
                continue
            cue = yield from self._verify_one(self.msgs.popleft())
            self.cues.append(cue)

    def _verify_one(self, association):
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
            observation = yield from self._observe_account(wallet)
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

    def _observe_account(self, wallet):
        """Yield through chain ID, latest block, then code at that block; return observation.

        A new worker-owned client prevents late responses from a timed-out observation
        being consumed by another association. Each RPC has its own timeout. Finally
        remove its ClientDoer, closing the connection even on cancellation or failure.
        The timestamp records observation time, not an association validity deadline.
        """
        client = http.Client(path=self.rpc_url, reconnectable=True)
        client_doer = RpcClientDoer(client=client)
        try:
            self.extend([client_doer])
            chain_id = yield from self._read_chain_id(client, self.chain_id)
            block = yield from self._read_block(client)
            code = yield from self._read_code(client, wallet, block["hash"])
            return {
                "chainId": chain_id,
                "blockNumber": int(block["number"], 16),
                "blockHash": block["hash"],
                "code": code,
                "observedAt": helping.nowIso8601(),
            }
        finally:
            self.remove([client_doer])

    def _read_chain_id(self, client, expected_chain_id):
        """Yield for eth_chainId and return its integer value if it matches expected_chain_id.

        Use the worker's per-call timeout; raise ValueError for a noncanonical quantity
        or another network. Transport and envelope failures propagate to _verify_one.
        """
        chain = yield from request_rpc(
            client,
            request_id=1,
            method="eth_chainId",
            params=[],
            tymth=self.tymth,
            timeout=self.timeout,
            tock=self.tock,
        )
        if not isinstance(chain, str) or not re.fullmatch(
            r"0x[1-9a-f][0-9a-f]*", chain
        ):
            raise ValueError("eth_chainId returned an invalid quantity")
        chain_id = int(chain, 16)
        if chain_id != expected_chain_id:
            raise ValueError("RPC chain does not match configured network")
        return chain_id

    def _read_block(self, client):
        """Yield for the latest block and return its dictionary after number/hash checks.

        Require a canonical hex quantity and 32-byte lowercase hash; unusable results
        raise ValueError. This identifies the subsequent code read, not finality.
        """
        block = yield from request_rpc(
            client,
            request_id=2,
            method="eth_getBlockByNumber",
            params=["latest", False],
            tymth=self.tymth,
            timeout=self.timeout,
            tock=self.tock,
        )
        if (
            not isinstance(block, dict)
            or not isinstance(block.get("number"), str)
            or not re.fullmatch(r"0x(?:0|[1-9a-f][0-9a-f]*)", block["number"])
            or not isinstance(block.get("hash"), str)
            or not re.fullmatch(r"0x[0-9a-f]{64}", block["hash"])
        ):
            raise ValueError("RPC returned no identified block")
        return block

    def _read_code(self, client, wallet, block_hash):
        """Yield for wallet code at block_hash with requireCanonical=True; return hex data.

        Raise ValueError for unusable byte encoding. RPC refusal of the block is a
        retryable observation failure, not evidence that the association is invalid.
        """
        code = yield from request_rpc(
            client,
            request_id=3,
            method="eth_getCode",
            params=[wallet, {"blockHash": block_hash, "requireCanonical": True}],
            tymth=self.tymth,
            timeout=self.timeout,
            tock=self.tock,
        )
        if not isinstance(code, str) or not re.fullmatch(r"0x(?:[0-9a-f]{2})*", code):
            raise ValueError("eth_getCode returned invalid hex data")
        return code
