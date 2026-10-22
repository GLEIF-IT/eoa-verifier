"""Exercise the account boundary over real HIO HTTP requests."""

import falcon
import pytest
from hio.base import doing
from hio.core import http, tcp
from native_helpers import candidate, free_port

from eoa_verifier.verification.worker import EoaVerifierDoer


class Rpc:
    """Falcon endpoint simulating RPC facts over real HIO HTTP transport, without an Ethereum node."""

    def __init__(self, chain="0x7a69", code="0x"):
        """Set simulated chain/code results and an initially empty calls list for request assertions."""
        self.chain, self.code, self.calls = chain, code, []

    def on_post(self, req, rep):
        """Record the request and return deterministic chain, identified-block or account-code JSON."""
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


def run_worker(worker, server_doer):
    """Schedule the worker and test server until a cue arrives, returning that cue.

    Own both task lifetimes through the parent DoDoer; assert completion within
    three real seconds and verify the worker released its child client.
    """

    def watch(tymth, tock=0.0, **kwa):
        """Yield until a result exists, then unschedule worker/server so HIO closes their resources."""
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
    """Exercise chain/code policy against simulated facts carried by real local HTTP requests."""
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
    """Tamper with the signed nonce and prove rejection occurs before any account observation."""
    worker = EoaVerifierDoer(rpc_url="http://127.0.0.1:1", chain_id=31337)
    bad = candidate()
    bad["u"] = "changed"
    worker.msgs.append(bad)
    doing.Doist(limit=0.05).do(doers=[worker])
    assert worker.cues.popleft()["kin"] == "failed"


def test_rpc_timeout_yields_and_closes_connection():
    """A real TCP peer that never replies must yield a retry cue and close the client."""
    server = tcp.Server(host="127.0.0.1", port=free_port())
    worker = EoaVerifierDoer(
        rpc_url=f"http://127.0.0.1:{server.ha[1]}", chain_id=31337, timeout=0.1
    )
    worker.msgs.append(candidate())
    cue = run_worker(worker, tcp.ServerDoer(server=server))
    assert cue["kin"] == "retry" and "timed out" in cue["error"]


@pytest.mark.parametrize("payload", [None, [], {"id": 1}, {"id": 1, "error": {}}])
def test_malformed_rpc_envelope_remains_retryable(payload):
    """Malformed simulated JSON-RPC envelopes must remain retryable over the actual HTTP path."""

    class Endpoint:
        """Serve the selected invalid envelope without applying normal RPC response construction."""

        def on_post(self, req, rep):
            """Serialize the parametrized bad payload as the HTTP JSON response."""
            import json

            rep.content_type = "application/json"
            rep.text = json.dumps(payload)

    app = falcon.App()
    app.add_route("/", Endpoint())
    server = http.Server(host="127.0.0.1", port=free_port(), app=app)
    worker = EoaVerifierDoer(
        rpc_url=f"http://127.0.0.1:{server.servant.ha[1]}", chain_id=31337
    )
    worker.msgs.append(candidate())
    cue = run_worker(worker, http.ServerDoer(server=server))
    assert cue["kin"] == "retry" and "invalid RPC response" in cue["error"]


@pytest.mark.parametrize(
    "block",
    [None, {"number": 42, "hash": "0x" + "12" * 32}, {"number": "0x2a", "hash": None}],
)
def test_malformed_block_remains_retryable(block):
    """Invalid block identity must request retry before any code read is sent."""

    class Endpoint(Rpc):
        """Keep valid chain responses while replacing only the block result."""

        def on_post(self, req, rep):
            """Use the common simulated RPC handler, then override the selected block response."""
            super().on_post(req, rep)
            if req.media["method"] == "eth_getBlockByNumber":
                rep.media["result"] = block

    app = falcon.App()
    endpoint = Endpoint()
    app.add_route("/", endpoint)
    server = http.Server(host="127.0.0.1", port=free_port(), app=app)
    worker = EoaVerifierDoer(
        rpc_url=f"http://127.0.0.1:{server.servant.ha[1]}", chain_id=31337
    )
    worker.msgs.append(candidate())
    cue = run_worker(worker, http.ServerDoer(server=server))
    assert cue["kin"] == "retry" and "no identified block" in cue["error"]
    assert [call["method"] for call in endpoint.calls] == [
        "eth_chainId",
        "eth_getBlockByNumber",
    ]


def test_programming_error_surfaces_and_closes_client(monkeypatch):
    """Inject an unexpected RPC helper error; it must escape while closing the owned client."""
    clients = []

    def broken_request(client, **kwa):
        """Capture the real allocated client and raise a simulated implementation defect."""
        clients.append(client)
        raise AttributeError("programming defect")

    monkeypatch.setattr("eoa_verifier.verification.worker.request_rpc", broken_request)
    worker = EoaVerifierDoer(rpc_url="http://127.0.0.1:1", chain_id=31337)
    worker.msgs.append(candidate())
    with pytest.raises(AttributeError, match="programming defect"):
        doing.Doist(limit=0.05).do(doers=[worker])
    assert not worker.cues
    assert not any(isinstance(d, http.ClientDoer) for d in worker.doers)
    assert clients and not clients[0].connector.opened


def test_cancellation_closes_in_flight_client_without_result():
    """Cancel after a real TCP connection and prove cleanup emits no verification result."""
    server = tcp.Server(host="127.0.0.1", port=free_port())
    server_doer = tcp.ServerDoer(server=server)
    worker = EoaVerifierDoer(rpc_url=f"http://127.0.0.1:{server.ha[1]}", chain_id=31337)
    worker.msgs.append(candidate())
    clients = []

    def cancel(tymth, tock=0.0, **kwa):
        """Yield until the server accepts a connection, capture clients and remove both child tasks."""
        yield tock
        while not server.ixes:
            yield 0.01
        clients.extend(d.client for d in worker.doers if isinstance(d, http.ClientDoer))
        parent.remove([worker, server_doer])

    parent = doing.DoDoer(doers=[worker, server_doer, doing.doify(cancel)])
    doing.Doist(real=True, tock=0.01, limit=2).do(doers=[parent])
    assert parent.done and clients
    assert not clients[0].connector.opened
    assert not worker.cues
    assert not any(isinstance(d, http.ClientDoer) for d in worker.doers)
