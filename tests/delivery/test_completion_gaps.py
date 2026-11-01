"""Producer recovery at durable receiver and sender completion boundaries."""

import falcon
import pytest
from hio.base import doing
from hio.core import http
from keri.app import habbing

from eoa_verifier.delivery.authing import HttpSignatures
from eoa_verifier.delivery.delivering import DeliveryService, WebhookSender
from eoa_verifier.delivery.keys import ServiceKeys
from eoa_verifier.persistence.associations import AssociationReader
from eoa_verifier.persistence.delivery import DeliveryReader, DeliveryWriter
from scripts.integration.receiver import Receiver, StatusEventService, StatusEventStore
from tests.support.acceptance import acceptance_service
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
        store = StatusEventStore(receiver.db)
        auth = HttpSignatures(
            keys=ServiceKeys(receiver_hab),
        )
        app = falcon.App()
        app.add_route(
            "/hook",
            Receiver(
                auth,
                StatusEventService(store),
                target,
                verifier_aid=sender_hab.pre,
                producer_ready=lambda: sender_hab.pre in receiver.kevers,
            ),
        )
        server = http.ServerDoer(
            server=http.Server(host="127.0.0.1", port=port, app=app)
        )
        baser = verified_store
        associationStatus = acceptance_service(baser).accept(
            "association",
            associationFacts={"issuerAid": sender_hab.pre},
            nonce="gap-fixture",
            destination=target,
        )

        def fail(*args, **kwargs):
            """Model loss at a precise durable/network boundary."""
            raise RuntimeError("simulated process loss")

        def attempt(*, expect_failure=False):
            """Own HIO HTTP tasks until exactly one durable sender attempt settles."""
            sender = WebhookSender(
                reader=DeliveryReader(baser),
                writer=DeliveryWriter(baser),
                keys=ServiceKeys(sender_hab),
                timeout=1,
                association_reader=AssociationReader(baser),
            )
            starting = baser.outbox.get(keys=(associationStatus.eventId,)).attempts

            def settled(tymth, tock=0.0, **kwargs):
                yield tock
                while True:
                    delivery = baser.outbox.get(keys=(associationStatus.eventId,))
                    if delivery.delivered or (
                        delivery.attempts > starting
                        and delivery.error
                        and delivery.error
                        != "attempt started; HTTP success not recorded"
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
                patch.setattr(DeliveryService, "complete", fail)
            attempt(expect_failure=(gap == "before-sender-completion"))

        committed = store.events.get(keys=(associationStatus.eventId,))
        assert committed == baser.outbox.get(keys=(associationStatus.eventId,)).body
        if gap != "none":
            assert not baser.outbox.get(keys=(associationStatus.eventId,)).delivered
            baser.close()
            baser.reopen()
            # Rebind status-event subdatabases after a KERIpy database reopen.
            receiver.db.close(clear=False)
            receiver.db.reopen()
            store = StatusEventStore(receiver.db)

            app = falcon.App()
            app.add_route(
                "/hook",
                Receiver(
                    auth,
                    StatusEventService(store),
                    target,
                    verifier_aid=sender_hab.pre,
                    producer_ready=lambda: sender_hab.pre in receiver.kevers,
                ),
            )
            server = http.ServerDoer(
                server=http.Server(host="127.0.0.1", port=port, app=app)
            )
            attempt()
        delivered = baser.outbox.get(keys=(associationStatus.eventId,))
        assert delivered.delivered
        assert delivered.attempts == (1 if gap == "none" else 2)
        assert list(store.events.getItemIter()) == [
            ((associationStatus.eventId,), committed)
        ]
