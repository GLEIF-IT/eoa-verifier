"""Producer recovery at durable receiver and sender completion boundaries."""

import falcon
import pytest
from hio.base import doing
from hio.core import http
from keri.app import habbing

from eoa_verifier.delivery.authing import ServiceAuthenticator
from eoa_verifier.delivery.delivering import WebhookSender
from scripts.integration.receiver import ReceiptStore, Receiver
from tests.support.network import free_port


@pytest.mark.parametrize("gap", ["none", "before-ack", "before-sender-completion"])
def test_real_sender_recovers_commit_ack_gaps(
    verified_store, tmp_path, monkeypatch, gap
):
    """Reopen durable stores and retry identical bytes after either commit gap."""
    with (
        habbing.openHby(name="producer", temp=True) as producer,
        habbing.openHby(
            name="receiver", headDirPath=str(tmp_path / "receiver"), temp=False
        ) as receiver,
    ):
        sender_hab = producer.makeHab(name="producer")
        receiver_hab = receiver.makeHab(name="receiver")
        producer.psr.parse(ims=bytearray(receiver_hab.makeOwnEvent(sn=0)))
        receiver.psr.parse(ims=bytearray(sender_hab.makeOwnEvent(sn=0)))
        port = free_port()
        target = f"http://127.0.0.1:{port}/hook"
        store = ReceiptStore(receiver.db)
        auth = ServiceAuthenticator(
            hab=receiver_hab, baser=store, peer_aid=sender_hab.pre
        )
        app = falcon.App()
        app.add_route("/hook", Receiver(auth, store, target, False))
        server = http.ServerDoer(
            server=http.Server(host="127.0.0.1", port=port, app=app)
        )
        baser = verified_store
        accepted = baser.accept(
            "association",
            association={"issuerAid": sender_hab.pre},
            nonce="gap-fixture",
            destination=target,
            peer_aid=receiver_hab.pre,
        )

        def fail(*args, **kwargs):
            """Model loss at a precise durable/network boundary."""
            raise RuntimeError("simulated process loss")

        def attempt(*, expect_failure=False):
            """Own native HTTP tasks until exactly one durable sender attempt settles."""
            sender = WebhookSender(baser=baser, hab=sender_hab, timeout=1)
            starting = baser.outbox.get(keys=(accepted.eventId,)).attempts

            def settled(tymth, tock=0.0, **kwargs):
                yield tock
                while True:
                    event = baser.outbox.get(keys=(accepted.eventId,))
                    if event.acknowledged or (
                        event.attempts > starting
                        and event.error
                        and event.error
                        != "attempt started; authenticated ACK not recorded"
                    ):
                        parent.remove([server, sender])
                        return
                    yield 0.01

            parent = doing.DoDoer(doers=[server, sender, doing.doify(settled)])
            scheduler = doing.Doist(real=True, tock=0.01, limit=3)
            if expect_failure:
                with pytest.raises(RuntimeError, match="simulated process loss"):
                    scheduler.do(doers=[parent])
            else:
                scheduler.do(doers=[parent])
                assert parent.done
            assert not server.server.servant.opened

        with monkeypatch.context() as patch:
            if gap == "before-ack":
                patch.setattr(auth, "sign", fail)
            elif gap == "before-sender-completion":
                patch.setattr(baser, "delivery_result", fail)
            attempt(expect_failure=(gap == "before-sender-completion"))

        committed = store.events.get(keys=(accepted.eventId,))
        assert committed == baser.outbox.get(keys=(accepted.eventId,)).body
        if gap != "none":
            assert not baser.outbox.get(keys=(accepted.eventId,)).acknowledged
            baser.close()
            baser.reopen()
            # Rebind receipt subdatabases after a native persistent reopen.
            receiver.db.close(clear=False)
            receiver.db.reopen()
            store = ReceiptStore(receiver.db)
            auth.baser = store
            app = falcon.App()
            app.add_route("/hook", Receiver(auth, store, target, False))
            server = http.ServerDoer(
                server=http.Server(host="127.0.0.1", port=port, app=app)
            )
            attempt()
        acknowledged = baser.outbox.get(keys=(accepted.eventId,))
        assert acknowledged.acknowledged
        assert acknowledged.attempts == (1 if gap == "none" else 2)
        assert list(store.events.getItemIter()) == [((accepted.eventId,), committed)]
