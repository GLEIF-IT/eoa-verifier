"""Basic webhook delivery over real HIO HTTP, using native peer signatures."""

import json

import falcon
import pytest
from hio.base import doing
from hio.core import http, tcp
from keri.app import habbing
from keri.db import dbing

from eoa_verifier.authing import ServiceAuthenticator
from eoa_verifier.basing import PendingVerification, VerificationResult, VerifierBaser
from eoa_verifier.delivering import WebhookSender
from native_helpers import free_port


@pytest.mark.parametrize(
    "reply",
    [
        "accepted",
        "signed-error",
        "wrong-event",
        "wrong-attempt",
        "unsigned",
        "tampered",
        "timeout",
        "refused",
        "retirement",
        "retirement-initial-ack",
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
        target = f"http://127.0.0.1:{port}/hook?chain=1"
        receiver = ServiceAuthenticator(
            hab=receiver_hab, baser=receiver_db, peer_aid=sender_hab.pre
        )
        received_bodies = []

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
                event_id = json.loads(body)["eventId"]
                ack = json.dumps(
                    {
                        "eventId": (
                            "wrong"
                            if reply == "wrong-event"
                            else "association:1"
                            if reply == "retirement-initial-ack"
                            else event_id
                        ),
                        "accepted": True,
                    }
                ).encode()
                status = 500 if reply == "signed-error" else 200
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
        if reply == "timeout":
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
                verified={"wallet": "wallet", "observation": {"chainId": 31337}},
            )
        )
        accepted = baser.accept(
            "association", facts={}, destination=target, peer_aid=receiver_hab.pre
        )
        if reply.startswith("retirement"):
            # Initial delivery is already acknowledged; retirement needs its own
            # event ACK, even if the target signs another acceptance of event 1.
            baser.delivery_result(accepted.eventId)
            accepted = baser.retire("association")
        sender = WebhookSender(baser=baser, hab=sender_hab, timeout=1)
        # The sender discovers the committed event; intake need not enqueue it again.

        def wait_for_attempt(tymth, tock=0.0, **kwa):
            """Stop after one recorded result so failed ACKs cannot be hidden by retries."""
            yield tock
            while True:
                event = baser.outbox.get(keys=(accepted.eventId,))
                if event.delivered or (
                    event.error
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
        assert event.delivered == (reply in ("accepted", "retirement"))
        assert event.attempts == 1
        assert received_bodies == (
            [] if reply in ("timeout", "refused") else [event.body.encode()]
        )
        assert bool(event.error) == (reply not in ("accepted", "retirement"))

        # Reopening delivery state does not resend an already-attempted event.
        # Automatic recovery of failed attempts is intentionally a later increment.
        baser.close()
        baser.reopen()
        resumed = WebhookSender(baser=baser, hab=sender_hab)
        doing.Doist(tock=0.01, limit=0.1).do(doers=[resumed])
        assert baser.outbox.get(keys=(accepted.eventId,)) == event
