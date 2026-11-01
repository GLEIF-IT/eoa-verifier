"""Sequential identified-block account observations with owned RPC client lifetimes."""

import re

from hio.core import http
from keri.help import helping

from .rpc import RpcClientDoer, request_rpc


class AccountObserver:
    """Translate Ethereum RPC responses into detached account observations."""

    def __init__(self, scheduler, *, rpc_url, chain_id, timeout):
        """Borrow the HIO parent that schedules and closes each temporary client."""
        self.scheduler = scheduler
        self.rpc_url, self.chain_id, self.timeout = rpc_url, chain_id, timeout

    def observe(self, wallet):
        """Yield through chain ID, latest block, then code at that block; return observation.

        A new worker-owned client prevents late responses from a timed-out observation
        being consumed by another association. Each RPC has its own timeout. Finally
        remove its ClientDoer, closing the connection even on cancellation or failure.
        The timestamp records observation time, not an association validity deadline.
        """
        client = http.Client(path=self.rpc_url, reconnectable=True)
        client_doer = RpcClientDoer(client=client)
        try:
            self.scheduler.extend([client_doer])
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
            self.scheduler.remove([client_doer])

    def _read_chain_id(self, client, expected_chain_id):
        """Yield for eth_chainId and return its integer value if it matches expected_chain_id.

        Use the worker's per-call timeout; raise ValueError for a noncanonical quantity
        or another network. Transport and envelope failures propagate to the worker,
        which classifies them as retry cues.
        """
        chain = yield from request_rpc(
            client,
            request_id=1,
            method="eth_chainId",
            params=[],
            tymth=self.scheduler.tymth,
            timeout=self.timeout,
            tock=self.scheduler.tock,
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
            tymth=self.scheduler.tymth,
            timeout=self.timeout,
            tock=self.scheduler.tock,
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
            tymth=self.scheduler.tymth,
            timeout=self.timeout,
            tock=self.scheduler.tock,
        )
        if not isinstance(code, str) or not re.fullmatch(r"0x(?:[0-9a-f]{2})*", code):
            raise ValueError("eth_getCode returned invalid hex data")
        return code
