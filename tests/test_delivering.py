"""Webhook delivery and retry over real HIO HTTP, using KERI AID signatures."""

import json

import falcon
import pytest
from hio.base import doing
from hio.core import http, tcp
from keri.app import habbing
from keri.db import dbing

from eoa_verifier.delivery.authing import ServiceAuthenticator
from eoa_verifier.persistence.basing import VerifierBaser
from eoa_verifier.persistence.records import PendingVerification, VerificationResult
from eoa_verifier.delivery.delivering import WebhookSender
from keripy_helpers import free_port


@pytest.mark.parametrize(
    "reply",
    [
        "stored",
        "stored-query",
        "signed-error",
        "wrong-event",
        "old-ack-shape",
        "wrong-attempt",
        "unsigned",
        "tampered",
        "timeout",
        "refused",
        "disconnect",
        "retirement",
        "retirement-initial-ack",
        "lost-ack",
        "unauthorized",
    ],
)
def test_webhook_completes_only_for_expected_authenticated_ack(tmp_path, reply):
    """A real request completes only when status, signature, attempt and event all agree."""
    with (
        habbing.openHby(name="sender", temp=True) as sender_hby,
        habbing.openHby(name="receiver", temp=True) as receiver_hby,
        dbing.openLMDB(
            cls=VerifierBaser, name="sender", headDirPath=str(tmp_path), temp=False
        ) as baser,
        dbing.openLMDB(cls=VerifierBaser, name="receiver", temp=True) as receiver_db,
    ):
        sender_hab = sender_hby.makeHab(name="sender")
        receiver_hab = receiver_hby.makeHab(name="receiver")
        sender_hby.psr.parse(ims=bytearray(receiver_hab.makeOwnEvent(sn=0)))
        receiver_hby.psr.parse(ims=bytearray(sender_hab.makeOwnEvent(sn=0)))
        port = free_port()
        query = "memo=a+b&path=%2F" if reply == "stored-query" else "chain=1"
        target = f"http://127.0.0.1:{port}/hook?{query}"
        receiver = ServiceAuthenticator(
            hab=receiver_hab, baser=receiver_db, peer_aid=sender_hab.pre
        )
        received_bodies, references, effects = [], [], set()

        class Endpoint:
            """Authenticate actual request bytes and return the selected ACK boundary case."""

            def on_post(self, req, rep):
                """Read signed bytes and reply with the case-selected HTTP status/body/signature."""
                body = req.bounded_stream.read()
                received_bodies.append(body)
                received = receiver.verify(
                    method=req.method,
                    target=f"http://127.0.0.1:{port}" + req.relative_uri,
                    action="status",
                    body=body,
                    headers=req.headers,
                )
                references.append(received.reference)
                event_id = json.loads(body)["eventId"]
                if reply == "lost-ack":
                    effects.add(
                        event_id
                    )  # Durable receiver behavior is qualified against the real oracle too.
                    if len(received_bodies) == 1:
                        rep.status = (
                            503  # Receipt committed, but its accepting ACK was lost.
                        )
                        return
                ack = json.dumps(
                    {
                        "eventId": (
                            "wrong"
                            if reply == "wrong-event"
                            else "association:1"
                            if reply == "retirement-initial-ack"
                            else event_id
                        ),
                        ("accepted" if reply == "old-ack-shape" else "stored"): True,
                    }
                ).encode()
                status = (
                    500
                    if reply == "signed-error"
                    else 401
                    if reply == "unauthorized"
                    else 200
                )
                headers, _ = receiver.sign(
                    method=req.method,
                    target=target,
                    action="ack",
                    request="wrong" if reply == "wrong-attempt" else received.reference,
                    status=status,
                    body=ack,
                )
                rep.status = status
                rep.data = ack + b" " if reply == "tampered" else ack
                if reply != "unsigned":
                    rep.set_headers(headers)

        app = falcon.App()
        app.add_route("/hook", Endpoint())
        if reply in ("timeout", "disconnect"):
            server = tcp.Server(host="127.0.0.1", port=port)
            server_doer = tcp.ServerDoer(server=server)
        else:
            server = http.Server(host="127.0.0.1", port=port, app=app)
            server_doer = http.ServerDoer(server=server)
        baser.enqueue(PendingVerification("association", "grant"))
        baser.finish(
            VerificationResult(
                "association",
                "verified",
                eoaResult={"wallet": "wallet", "accountObservation": {"chainId": 31337}},
            )
        )
        accepted = baser.accept(
            "association", association={}, destination=target, peer_aid=receiver_hab.pre
        )
        if reply.startswith("retirement"):
            # Initial delivery is already acknowledged; retirement needs its own
            # event ACK, even if the target signs another acceptance of event 1.
            baser.delivery_result(accepted.eventId)
            accepted = baser.retire("association")
        sender = WebhookSender(
            baser=baser,
            hab=sender_hab,
            timeout=1,
            interval=0.05,
            backoff_base=0.05,
            backoff_cap=0.05,
        )
        # The sender discovers the committed event; intake need not enqueue it again.

        def wait_for_attempt(tymth, tock=0.0, **kwa):
            """Stop after one recorded result so failed ACKs cannot be hidden by retries."""
            yield tock
            truncated = False
            while True:
                if reply == "disconnect":
                    # Close a real connection in the middle of the declared ACK body.
                    for address, connection in list(server.ixes.items()):
                        if connection.rxbs and not truncated:
                            connection.tx(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n{"
                            )
                            truncated = True
                        elif truncated and not connection.txbs:
                            server.removeIx(address)
                event = baser.outbox.get(keys=(accepted.eventId,))
                if event.acknowledged or (
                    reply != "lost-ack"
                    and event.error
                    and event.error != "attempt started; authenticated ACK not recorded"
                ):
                    parent.remove([sender, server_doer])
                    return
                yield 0.01

        network = [] if reply == "refused" else [server_doer]
        parent = doing.DoDoer(doers=[sender, *network, doing.doify(wait_for_attempt)])
        doing.Doist(real=True, tock=0.01, limit=3).do(doers=[parent])
        event = baser.outbox.get(keys=(accepted.eventId,))
        assert parent.done
        assert event.acknowledged == (
            reply in ("stored", "stored-query", "retirement", "lost-ack")
        )
        assert event.attempts == (2 if reply == "lost-ack" else 1)
        assert received_bodies == (
            []
            if reply in ("timeout", "refused", "disconnect")
            else [event.body.encode()] * event.attempts
        )
        assert bool(event.error) == (
            reply not in ("stored", "stored-query", "retirement", "lost-ack")
        )

        if reply == "disconnect":
            assert "closed" in event.error
        if reply == "lost-ack":
            assert effects == {event.eventId}
            assert (
                len(set(references)) == 2
            )  # Immutable body, fresh signed attempt references.
        elif not event.acknowledged:
            assert event.blocked == (
                reply not in ("signed-error", "timeout", "refused", "disconnect")
            )


def test_malformed_chunk_response_preserves_pending_delivery(tmp_path):
    """Bad HTTP framing closes only its client and leaves the immutable event recoverable."""

    class BadResponsePeer(tcp.ServerDoer):
        """Send an invalid chunk-size line over a real TCP connection."""

        def recur(self, tyme):
            """Wait for a request before returning malformed chunk framing."""
            super().recur(tyme)
            for peer in self.server.ixes.values():
                if peer.rxbs:
                    peer.rxbs.clear()
                    peer.tx(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZ\r\n")

    with (
        habbing.openHby(name="sender", temp=True) as hby,
        dbing.openLMDB(
            cls=VerifierBaser, name="chunk", headDirPath=str(tmp_path), temp=False
        ) as baser,
    ):
        hab = hby.makeHab(name="sender")
        server = tcp.Server(host="127.0.0.1", port=free_port())
        peer = BadResponsePeer(server=server)
        baser.enqueue(PendingVerification("association", "grant"))
        baser.finish(
            VerificationResult(
                "association", "verified",
                eoaResult={"wallet": "wallet", "accountObservation": {}},
            )
        )
        status = baser.accept(
            "association", association={},
            destination=f"http://127.0.0.1:{server.ha[1]}/hook", peer_aid=hab.pre,
        )
        original = baser.outbox.get(keys=(status.eventId,))
        sender = WebhookSender(baser=baser, hab=hab)
        clients = []

        def watch(tymth, tock=0.0, **kwa):
            """A sibling must run after parsing fails and observe per-attempt cleanup."""
            yield tock
            while True:
                clients.extend(
                    d.client for d in sender.doers if isinstance(d, http.ClientDoer)
                )
                event = baser.outbox.get(keys=(status.eventId,))
                if event.blocked:
                    assert not any(isinstance(d, http.ClientDoer) for d in sender.doers)
                    parent.remove([sender, peer])
                    return
                yield 0.01

        parent = doing.DoDoer(doers=[sender, peer, doing.doify(watch)])
        doing.Doist(real=True, tock=0.01, limit=3).do(doers=[parent])
        assert parent.done and clients
        assert all(not client.connector.opened for client in clients)
        event = baser.outbox.get(keys=(status.eventId,))
        assert not event.acknowledged and event.blocked and event.attempts == 1
        assert "invalid literal" in event.error
        assert event.body == original.body
        # Framing errors use the existing blocked-delivery correction/resume path.
        baser.close()
        baser.reopen()
        assert baser.outbox.get(keys=(status.eventId,)) == event
