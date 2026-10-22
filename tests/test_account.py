"""Exercise the account boundary over real HIO HTTP requests."""

import falcon
import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data
from hio.base import doing
from hio.core import http, tcp
from keri import core
from keri.core import coring
from native_helpers import association_from_challenge
from test_native import KEY, free_port

from eoa_verifier.verification.eoa import build_challenge
from eoa_verifier.verification.worker import EoaVerifierDoer


class Rpc:
    def __init__(self, chain="0x7a69", code="0x"):
        self.chain, self.code, self.calls = chain, code, []

    def on_post(self, req, rep):
        body = req.media
        self.calls.append(body)
        rep.media = {
            "jsonrpc": "2.0",
            "id": body["id"],
            "result": {
                "eth_chainId": self.chain,
                "eth_getBlockByNumber": {"number": "0x2a", "hash": "0x" + "12" * 32},
                "eth_getCode": self.code,
            }[body["method"]],
        }


def candidate():
    said = coring.Diger(ser=b"test").qb64
    challenge = build_challenge(
        issuer_aid=core.Signer().verfer.qb64,
        le_vlei_said=said,
        ext_id=f"eip155:31337:{Account.from_key(KEY).address.lower()}",
        nonce="test-account",
    )
    sig = Account.sign_message(encode_typed_data(full_message=challenge), KEY).signature
    return association_from_challenge(challenge, "0x" + sig.hex(), said).sad


def run_worker(worker, server_doer):
    def watch(tymth, tock=0.0, **kwa):
        yield tock
        while not worker.cues:
            yield 0.01
        parent.remove([worker, server_doer])

    parent = doing.DoDoer(doers=[worker, server_doer, doing.doify(watch)])
    doing.Doist(real=True, tock=0.01, limit=3).do(doers=[parent])
    assert parent.done, "account request did not finish"
    assert not any(isinstance(d, http.ClientDoer) for d in worker.doers)
    return worker.cues.popleft()


@pytest.mark.parametrize(
    "chain,code,expected",
    [
        ("0x7a69", "0x", "verified"),
        ("0x7a69", "0xef0100" + "12" * 20, "verified"),
        ("0x7a69", "0x6000", "failed"),
        ("0x7a69", "invalid", "retry"),
        ("0x1", "0x", "retry"),
        ("0x00", "0x", "retry"),
    ],
)
def test_account_checks(chain, code, expected):
    endpoint, app = Rpc(chain, code), falcon.App()
    app.add_route("/", endpoint)
    server = http.Server(host="127.0.0.1", port=free_port(), app=app)
    worker = EoaVerifierDoer(
        rpc_url=f"http://127.0.0.1:{server.servant.ha[1]}", chain_id=31337
    )
    worker.msgs.append(candidate())
    cue = run_worker(worker, http.ServerDoer(server=server))
    assert cue["kin"] == expected
    if expected == "verified":
        assert cue["verified"]["observation"]["blockNumber"] == 42
        assert endpoint.calls[-1]["params"][1] == {
            "blockHash": "0x" + "12" * 32,
            "requireCanonical": True,
        }


def test_invalid_wallet_proof_never_contacts_rpc():
    worker = EoaVerifierDoer(rpc_url="http://127.0.0.1:1", chain_id=31337)
    bad = candidate()
    bad["u"] = "changed"
    worker.msgs.append(bad)
    doing.Doist(limit=0.05).do(doers=[worker])
    assert worker.cues.popleft()["kin"] == "failed"


def test_rpc_timeout_yields_and_closes_connection():
    server = tcp.Server(host="127.0.0.1", port=free_port())
    worker = EoaVerifierDoer(
        rpc_url=f"http://127.0.0.1:{server.ha[1]}", chain_id=31337, timeout=0.1
    )
    worker.msgs.append(candidate())
    cue = run_worker(worker, tcp.ServerDoer(server=server))
    assert cue["kin"] == "retry" and "timed out" in cue["error"]
