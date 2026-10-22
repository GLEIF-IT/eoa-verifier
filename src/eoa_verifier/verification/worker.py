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
        """Check the proof, yield for RPC responses, then emit one result cue."""
        yield tock
        while True:
            if not self.msgs:
                yield self.tock
                continue
            association = self.msgs.popleft()
            said = association["d"]
            try:
                verify_eoa_proof(association)
                if ext_id_chain(association["a"]["extId"]) != self.chain_id:
                    raise ValueError(
                        "association chain does not match configured network"
                    )
            except ValueError as exc:
                self.cues.append({"kin": "failed", "said": said, "error": str(exc)})
                continue

            client_doer = None
            try:
                # A new connection per operation prevents late timed-out responses
                # from being consumed as evidence for the next association.
                client = http.Client(path=self.rpc_url, reconnectable=True)
                client_doer = http.ClientDoer(client=client)
                self.extend([client_doer])
                wallet = association["a"]["extId"].split(":")[2]
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
                if chain_id != self.chain_id:
                    raise ValueError("RPC chain does not match configured network")
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
                    or not re.fullmatch(
                        r"0x(?:0|[1-9a-f][0-9a-f]*)", block.get("number", "")
                    )
                    or not re.fullmatch(r"0x[0-9a-f]{64}", block.get("hash", ""))
                ):
                    raise ValueError("RPC returned no identified block")
                code_hex = yield from request_rpc(
                    client,
                    request_id=3,
                    method="eth_getCode",
                    params=[
                        wallet,
                        {"blockHash": block["hash"], "requireCanonical": True},
                    ],
                    tymth=self.tymth,
                    timeout=self.timeout,
                    tock=self.tock,
                )
                if not isinstance(code_hex, str) or not re.fullmatch(
                    r"0x(?:[0-9a-f]{2})*", code_hex
                ):
                    raise ValueError("eth_getCode returned invalid hex data")
                code = bytes.fromhex(code_hex[2:])
                observation = {
                    "chainId": chain_id,
                    "blockNumber": int(block["number"], 16),
                    "blockHash": block["hash"],
                    "code": code_hex,
                    "observedAt": helping.nowIso8601(),
                }
            except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
                # Transport/RPC failures are not evidence of an invalid credential.
                self.cues.append({"kin": "retry", "said": said, "error": str(exc)})
                continue
            finally:
                if client_doer is not None:
                    self.remove([client_doer])

            try:
                result = verify_eoa_account(association, chain_id=chain_id, code=code)
            except ValueError as exc:
                self.cues.append({"kin": "failed", "said": said, "error": str(exc)})
            else:
                result["observation"] = observation
                self.cues.append({"kin": "verified", "said": said, "verified": result})
