"""Real HTTP response signatures, framing and client lifetime."""

import json

import falcon
import pytest
from hio.base import doing
from hio.core import http, tcp
from keri.app import habbing
from keri.db import dbing

from eoa_verifier.delivery.authing import HttpSignatures
from eoa_verifier.delivery.delivering import (
    WebhookSender,
)
from eoa_verifier.delivery.keys import ServiceKeys
from eoa_verifier.persistence.associations import AssociationReader
from eoa_verifier.persistence.basing import VerifierBaser
from eoa_verifier.persistence.delivery import DeliveryReader, DeliveryWriter
from eoa_verifier.persistence.records import VerificationRecord, VerificationResult
from tests.support.acceptance import acceptance_service, revocation_service
from tests.support.network import free_port
from tests.support.persistence import enqueue_verification
from tests.support.services import delivery_service, verification_service


@pytest.mark.parametrize(
    "reply",
    [
        "stored",
        "stored-query",
        "signed-error",
        "opaque-body",
        "partial-signature",
        "unknown-signer",
        "unsigned",
        "tampered",
        "timeout",
        "refused",
        "disconnect",
        "revocation",
        "unsigned-204",
        "unsigned-202",
        "signed-empty",
        "lost-ack",
        "unauthorized",
    ],
)
def test_webhook_accepts_unsigned_success_and_verifies_supplied_signatures(
    tmp_path, reply
):
    """A real target needs no signing identity; supplied signatures must verify."""
    with (
        habbing.openHby(name="sender", temp=True) as sender_hby,
        habbing.openHby(name="receiver", temp=True) as receiver_hby,
        dbing.openLMDB(
            cls=VerifierBaser, name="sender", headDirPath=str(tmp_path), temp=False
        ) as baser,
    ):
        sender_hab = sender_hby.makeHab(name="sender")
        localAids = set(sender_hby.kevers)
        receiver_hab = (
            None
            if reply.startswith("unsigned")
            else receiver_hby.makeHab(name="receiver")
        )
        if reply != "unknown-signer" and not reply.startswith("unsigned"):
            sender_hby.psr.parse(ims=bytearray(receiver_hab.makeOwnEvent(sn=0)))
        if not reply.startswith("unsigned"):
            receiver_hby.psr.parse(ims=bytearray(sender_hab.makeOwnEvent(sn=0)))
        else:
            assert set(sender_hby.kevers) == localAids
        port = free_port()
        query = "memo=a+b&path=%2F" if reply == "stored-query" else "chain=1"
        target = f"http://127.0.0.1:{port}/hook?{query}"
        receiver = HttpSignatures(
            keys=ServiceKeys(receiver_hab),
        )
        received_bodies, effects = [], set()

        class Endpoint:
            """Authenticate actual request bytes and return the selected ACK boundary case."""

            def on_post(self, req, rep):
                """Read signed bytes and reply with the case-selected HTTP status/body/signature."""
                body = req.bounded_stream.read()
                received_bodies.append(body)
                if not reply.startswith("unsigned"):
                    assert (
                        receiver.verify(
                            method=req.method,
                            target=req.path,
                            body=body,
                            headers=req.headers,
                        )
                        == sender_hab.pre
                    )
                event_id = json.loads(body)["eventId"]
                if reply == "lost-ack":
                    effects.add(
                        event_id
                    )  # Durable receiver behavior is qualified against the real oracle too.
                    if len(received_bodies) == 1:
                        rep.status = (
                            503  # Status event committed, but its signed ACK was lost.
                        )
                        return
                responseBody = (
                    b""
                    if reply in ("signed-empty", "unsigned-204")
                    else b"arbitrary target response"
                    if reply == "opaque-body"
                    else json.dumps({"eventId": event_id, "stored": True}).encode()
                )
                status = (
                    500
                    if reply == "signed-error"
                    else 401
                    if reply == "unauthorized"
                    else 204
                    if reply in ("unsigned-204", "signed-empty")
                    else 202
                    if reply == "unsigned-202"
                    else 200
                )
                rep.status = status
                rep.data = responseBody + b" " if reply == "tampered" else responseBody
                if not reply.startswith("unsigned"):
                    headers = receiver.sign(
                        method=req.method, target=req.path, body=responseBody
                    )
                    if reply == "partial-signature":
                        del headers["signature-input"]
                    rep.set_headers(headers)

        app = falcon.App()
        app.add_route("/hook", Endpoint())
        if reply in ("timeout", "disconnect"):
            server = tcp.Server(host="127.0.0.1", port=port)
            server_doer = tcp.ServerDoer(server=server)
        else:
            server = http.Server(host="127.0.0.1", port=port, app=app)
            server_doer = http.ServerDoer(server=server)
        enqueue_verification(baser, VerificationRecord("association", "grant"))
        verificationService = verification_service(baser)
        verificationService.start_pending(verificationService.next_pending())
        verification_service(baser).finish(
            VerificationResult(
                "association",
                "verified",
                eoaResult={
                    "wallet": "wallet",
                    "accountObservation": {"chainId": 31337},
                },
            )
        )
        associationStatus = acceptance_service(baser).accept(
            "association",
            associationFacts={"issuerAid": "issuer"},
            nonce="other",
            destination=target,
        )
        if reply.startswith("revocation"):
            # Initial delivery is complete; revocation needs a separate HTTP delivery.
            delivery_service(baser).complete(associationStatus.eventId)
            associationStatus = revocation_service(baser).apply_revocation(
                "association"
            )
        sender = WebhookSender(
            reader=DeliveryReader(baser),
            writer=DeliveryWriter(baser),
            keys=ServiceKeys(sender_hab),
            timeout=1,
            interval=0.05,
            backoff_base=0.05,
            backoff_cap=0.05,
            association_reader=AssociationReader(baser),
        )
        # Acceptance atomically queued this event; the sender reads only its work phase.

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
                delivery = baser.outbox.get(keys=(associationStatus.eventId,))
                if delivery.delivered or (
                    reply != "lost-ack"
                    and delivery.error
                    and delivery.error != "attempt started; HTTP success not recorded"
                ):
                    parent.remove([sender, server_doer])
                    return
                yield 0.01

        network = [] if reply == "refused" else [server_doer]
        parent = doing.DoDoer(doers=[sender, *network, doing.doify(wait_for_attempt)])
        doing.Doist(real=True, tock=0.01, limit=3).do(doers=[parent])
        delivery = baser.outbox.get(keys=(associationStatus.eventId,))
        assert parent.done
        assert delivery.delivered == (
            reply
            in (
                "stored",
                "stored-query",
                "revocation",
                "lost-ack",
                "unsigned",
                "unsigned-202",
                "unsigned-204",
                "signed-empty",
                "opaque-body",
            )
        )
        assert delivery.attempts == (2 if reply == "lost-ack" else 1)
        assert received_bodies == (
            []
            if reply in ("timeout", "refused", "disconnect")
            else [delivery.body.encode()] * delivery.attempts
        )
        assert bool(delivery.error) == (
            reply
            not in (
                "stored",
                "stored-query",
                "revocation",
                "lost-ack",
                "unsigned",
                "unsigned-202",
                "unsigned-204",
                "signed-empty",
                "opaque-body",
            )
        )

        if reply == "disconnect":
            assert "closed" in delivery.error
        if reply == "lost-ack":
            assert effects == {delivery.eventId}
        elif not delivery.delivered:
            assert delivery.blocked == (
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
                    peer.tx(
                        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZ\r\n"
                    )

    with (
        habbing.openHby(name="sender", temp=True) as hby,
        dbing.openLMDB(
            cls=VerifierBaser, name="chunk", headDirPath=str(tmp_path), temp=False
        ) as baser,
    ):
        hab = hby.makeHab(name="sender")
        server = tcp.Server(host="127.0.0.1", port=free_port())
        peer = BadResponsePeer(server=server)
        enqueue_verification(baser, VerificationRecord("association", "grant"))
        verificationService = verification_service(baser)
        verificationService.start_pending(verificationService.next_pending())
        verification_service(baser).finish(
            VerificationResult(
                "association",
                "verified",
                eoaResult={"wallet": "wallet", "accountObservation": {}},
            )
        )
        status = acceptance_service(baser).accept(
            "association",
            associationFacts={"issuerAid": "issuer"},
            nonce="other",
            destination=f"http://127.0.0.1:{server.ha[1]}/hook",
        )
        original = baser.outbox.get(keys=(status.eventId,))
        sender = WebhookSender(
            reader=DeliveryReader(baser),
            writer=DeliveryWriter(baser),
            keys=ServiceKeys(hab),
            association_reader=AssociationReader(baser),
        )
        clients = []

        def watch(tymth, tock=0.0, **kwa):
            """A sibling must run after parsing fails and observe per-attempt cleanup."""
            yield tock
            while True:
                clients.extend(
                    d.client for d in sender.doers if isinstance(d, http.ClientDoer)
                )
                delivery = baser.outbox.get(keys=(status.eventId,))
                if delivery.blocked:
                    assert not any(isinstance(d, http.ClientDoer) for d in sender.doers)
                    parent.remove([sender, peer])
                    return
                yield 0.01

        parent = doing.DoDoer(doers=[sender, peer, doing.doify(watch)])
        doing.Doist(real=True, tock=0.01, limit=3).do(doers=[parent])
        assert parent.done and clients
        assert all(not client.connector.opened for client in clients)
        delivery = baser.outbox.get(keys=(status.eventId,))
        assert not delivery.delivered and delivery.blocked and delivery.attempts == 1
        assert "invalid literal" in delivery.error
        assert delivery.body == original.body
        # Framing errors use the existing blocked-delivery correction/resume path.
        baser.close()
        baser.reopen()
        assert baser.outbox.get(keys=(status.eventId,)) == delivery
