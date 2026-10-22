"""HIO request/cue flow for EOA proof and account verification."""

import re

from hio.base import doing
from hio.core import http
from hio.help import decking
from keri.help import helping

from eoa_verifier.rpc import request_rpc
from eoa_verifier.verification.eoa import (
    ext_id_chain,
    verify_eoa_account,
    verify_eoa_proof,
)


class EoaVerifierDoer(doing.DoDoer):
    """Consume association ACDCs from ``msgs`` and emit completion ``cues``.

    Each cue identifies the association by ``said`` and has a ``kin`` of
    ``verified`` (with result fields), ``failed`` (invalid proof/account), or
    ``retry`` (RPC unavailable or unusable). Only the coordinator persists state.
    One request runs at a time; HTTP clients are owned and closed by this worker.
    """

    def __init__(self, *, rpc_url, chain_id, timeout=5.0, **kwa):
        self.rpc_url = rpc_url
        self.chain_id = chain_id
        self.timeout = timeout
        self.msgs = decking.Deck()
        self.cues = decking.Deck()
        super().__init__(doers=[doing.doify(self.verify_do)], **kwa)

    def verify_do(self, tymth, tock=0.0, **opts):
        """Consume one association at a time and emit its result cue."""
        yield tock
        while True:
            if not self.msgs:
                yield self.tock
                continue
            cue = yield from self._verify_one(self.msgs.popleft())
            self.cues.append(cue)

    def _verify_one(self, association):
        """Keep proof/account failures distinct from unavailable RPC evidence."""
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
        result["observation"] = observation
        return {"kin": "verified", "said": said, "verified": result}

    def _observe_account(self, wallet):
        """Own one HTTP client through the sequential RPC observation."""
        # A new connection prevents a late response from a timed-out operation
        # from being consumed as evidence for another association.
        client = http.Client(path=self.rpc_url, reconnectable=True)
        client_doer = http.ClientDoer(client=client)
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
        """Read a canonical chain quantity and require the configured network."""
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
        """Require an identified block before requesting account code."""
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
        """Read account code at the identified, still-canonical block."""
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
