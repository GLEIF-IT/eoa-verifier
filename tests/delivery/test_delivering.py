"""delivery/test_delivering.py."""

import json
from datetime import datetime, timezone
from email.utils import format_datetime
from functools import partial
from unittest.mock import patch

import falcon
import pytest
from hio.base import doing
from hio.core import http, tcp
from keri.app import habbing
from keri.db import dbing

from eoa_verifier.delivery.authing import ServiceAuthenticator
from eoa_verifier.delivery.delivering import (
    WebhookSender,
    _retry_after,
    _TransientFailure,
)
from eoa_verifier.delivery.keys import ServiceKeys
from eoa_verifier.persistence.associations import AssociationReader
from eoa_verifier.persistence.basing import VerifierBaser
from eoa_verifier.persistence.delivery import DeliveryReader, DeliveryWriter
from eoa_verifier.persistence.records import VerificationRecord, VerificationResult
from eoa_verifier.persistence.transport import claim_nonce
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
        "wrong-event",
        "old-ack-shape",
        "wrong-attempt",
        "unsigned",
        "tampered",
        "timeout",
        "refused",
        "disconnect",
        "revocation",
        "revocation-initial-ack",
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
            keys=ServiceKeys(receiver_hab),
            claim_nonce=partial(claim_nonce, receiver_db),
            peer_aid=sender_hab.pre,
        )
        received_bodies, references, effects = [], [], set()

        class Endpoint:
            """Authenticate actual request bytes and return the selected ACK boundary case."""

            def on_post(self, req, rep):
                """Read signed bytes and reply with the case-selected HTTP status/body/signature."""
                body = req.bounded_stream.read()
                received_bodies.append(body)
                verifiedAuth = receiver.verify(
                    method=req.method,
                    target=f"http://127.0.0.1:{port}" + req.relative_uri,
                    action="status",
                    body=body,
                    headers=req.headers,
                )
                references.append(verifiedAuth.reference)
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
                ack = json.dumps(
                    {
                        "eventId": (
                            "wrong"
                            if reply == "wrong-event"
                            else (
                                "association:1"
                                if reply == "revocation-initial-ack"
                                else event_id
                            )
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
                    request="wrong"
                    if reply == "wrong-attempt"
                    else verifiedAuth.reference,
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
            peer_aid=receiver_hab.pre,
        )
        if reply.startswith("revocation"):
            # Initial delivery is already acknowledged; revocation needs its own
            # event ACK, even if the target signs another acceptance of event 1.
            delivery_service(baser).acknowledge(associationStatus.eventId)
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
            claim_nonce=partial(claim_nonce, baser),
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
                if delivery.acknowledged or (
                    reply != "lost-ack"
                    and delivery.error
                    and delivery.error
                    != "attempt started; authenticated ACK not recorded"
                ):
                    parent.remove([sender, server_doer])
                    return
                yield 0.01

        network = [] if reply == "refused" else [server_doer]
        parent = doing.DoDoer(doers=[sender, *network, doing.doify(wait_for_attempt)])
        doing.Doist(real=True, tock=0.01, limit=3).do(doers=[parent])
        delivery = baser.outbox.get(keys=(associationStatus.eventId,))
        assert parent.done
        assert delivery.acknowledged == (
            reply in ("stored", "stored-query", "revocation", "lost-ack")
        )
        assert delivery.attempts == (2 if reply == "lost-ack" else 1)
        assert received_bodies == (
            []
            if reply in ("timeout", "refused", "disconnect")
            else [delivery.body.encode()] * delivery.attempts
        )
        assert bool(delivery.error) == (
            reply not in ("stored", "stored-query", "revocation", "lost-ack")
        )

        if reply == "disconnect":
            assert "closed" in delivery.error
        if reply == "lost-ack":
            assert effects == {delivery.eventId}
            assert (
                len(set(references)) == 2
            )  # Immutable body, fresh signed attempt references.
        elif not delivery.acknowledged:
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
            peer_aid=hab.pre,
        )
        original = baser.outbox.get(keys=(status.eventId,))
        sender = WebhookSender(
            reader=DeliveryReader(baser),
            writer=DeliveryWriter(baser),
            keys=ServiceKeys(hab),
            claim_nonce=partial(claim_nonce, baser),
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
        assert not delivery.acknowledged and delivery.blocked and delivery.attempts == 1
        assert "invalid literal" in delivery.error
        assert delivery.body == original.body
        # Framing errors use the existing blocked-delivery correction/resume path.
        baser.close()
        baser.reopen()
        assert baser.outbox.get(keys=(status.eventId,)) == delivery


def accept(baser, said):
    """Create a completed result and its event at one shared destination."""
    enqueue_verification(baser, VerificationRecord(said, "grant"))
    verificationService = verification_service(baser)
    verificationService.start_pending(verificationService.next_pending())
    verification_service(baser).finish(
        VerificationResult(
            said, "verified", eoaResult={"wallet": "wallet", "accountObservation": {}}
        )
    )
    return acceptance_service(baser).accept(
        said,
        associationFacts={"issuerAid": "issuer"},
        nonce=said,
        destination="https://receiver.example/hook",
        peer_aid="peer",
    )


def test_retry_backoff_caps_and_paces_successes(outbox):
    """One sender grows jitter bounds, caps repeated failures, and paces even successful events."""
    accept(outbox, "a")
    accept(outbox, "b")
    scheduler = doing.Doist(tock=0.01, limit=1000)
    clock = lambda: 1000 + scheduler.tyme
    ranges, starts = [], []

    def lower_bound(lower, upper):
        """Record the offered jitter range and choose its lower bound deterministically."""
        ranges.append((lower, upper))
        return lower

    sender = WebhookSender(
        reader=DeliveryReader(outbox),
        writer=DeliveryWriter(outbox),
        keys=ServiceKeys(None),
        clock=clock,
        uniform=lower_bound,
        max_attempts=12,
        claim_nonce=partial(claim_nonce, outbox),
        association_reader=AssociationReader(outbox),
    )

    def attempt(delivery):
        """Hold each attempt open over scheduler turns, then fail ten times before succeeding."""
        starts.append(clock())
        yield 1.5 if len(ranges) < 10 else 0.2
        if len(ranges) < 10:
            raise TimeoutError("target unavailable")
        if len(starts) == 11:
            # Queue another event as this attempt succeeds; retain request-start pacing.
            accept(outbox, "c")

    with patch.object(sender.service, "send", attempt):
        scheduler.do(doers=[sender])
    assert ranges == [(n, 2 * n) for n in (1, 2, 4, 8, 16, 32, 64, 128, 150, 150)]
    assert len(starts) == 13
    assert all(b - a >= 1.5 - 1e-6 for a, b in zip(starts[:10], starts[1:11]))
    assert all(b - a >= 1 - 1e-6 for a, b in zip(starts, starts[1:]))
    assert all(delivery.acknowledged for _, delivery in outbox.outbox.getItemIter())
    assert (
        outbox.destinations.get(keys=("https://receiver.example/hook",)).failures == 0
    )


def test_cooldown_survives_restart_and_gates_new_events(outbox):
    """Retry-After beyond the cap gates a new backlog event after restart, then ACK resets failures."""
    original = accept(outbox, "a")
    scheduler = doing.Doist(tock=0.01, limit=1)
    clock = lambda: 1000 + scheduler.tyme
    sender = WebhookSender(
        reader=DeliveryReader(outbox),
        writer=DeliveryWriter(outbox),
        keys=ServiceKeys(None),
        clock=clock,
        uniform=lambda low, high: high,
        claim_nonce=partial(claim_nonce, outbox),
        association_reader=AssociationReader(outbox),
    )

    def unavailable(delivery):
        """Return the same transient classification as a rate-limited HTTP endpoint."""
        yield 0.01
        raise _TransientFailure("webhook HTTP 429", retry_after=600)

    with patch.object(sender.service, "send", unavailable):
        scheduler.do(doers=[sender])
    delivery = outbox.outbox.get(keys=(original.eventId,))
    schedule = outbox.destinations.get(keys=(delivery.destination,))
    assert schedule.failures == 1 and schedule.nextAttemptAt >= 1600
    outbox.close()
    outbox.reopen()
    accept(outbox, "b")  # Acceptance must not replace the destination's cooldown.
    assert outbox.destinations.get(keys=(delivery.destination,)) == schedule

    resumed = WebhookSender(
        reader=DeliveryReader(outbox),
        writer=DeliveryWriter(outbox),
        keys=ServiceKeys(None),
        clock=clock,
        claim_nonce=partial(claim_nonce, outbox),
        association_reader=AssociationReader(outbox),
    )
    starts = []

    def acknowledge(delivery):
        """Record the dispatch time; network ACK validation is covered by signed HTTP tests."""
        starts.append(clock())
        yield 0.01

    scheduler.tyme = 599
    scheduler.limit = 5
    with patch.object(resumed.service, "send", acknowledge):
        scheduler.do(doers=[resumed], tyme=599)
    assert len(starts) == 2 and min(starts) >= schedule.nextAttemptAt
    assert starts[1] - starts[0] >= 1 - 1e-6
    assert outbox.destinations.get(keys=(delivery.destination,)).failures == 0
    assert outbox.outbox.get(keys=(original.eventId,)).attempts == 2


def test_permanent_failure_waits_for_explicit_resumption(outbox):
    """Permanent failures remain visible and blocked across restart until the caller corrects/resumes them."""
    associationStatus = accept(outbox, "a")
    scheduler = doing.Doist(tock=0.01, limit=2)
    clock = lambda: 1000 + scheduler.tyme
    sender = WebhookSender(
        reader=DeliveryReader(outbox),
        writer=DeliveryWriter(outbox),
        keys=ServiceKeys(None),
        clock=clock,
        claim_nonce=partial(claim_nonce, outbox),
        association_reader=AssociationReader(outbox),
    )

    def misconfigured(delivery):
        """Model a permanent endpoint failure without replacing any signature test."""
        yield 0.01
        raise ValueError("webhook HTTP 401")

    with patch.object(sender.service, "send", misconfigured):
        scheduler.do(doers=[sender])
    failed = outbox.outbox.get(keys=(associationStatus.eventId,))
    assert failed.blocked and not failed.acknowledged and failed.attempts == 1
    outbox.close()
    outbox.reopen()
    resumed = WebhookSender(
        reader=DeliveryReader(outbox),
        writer=DeliveryWriter(outbox),
        keys=ServiceKeys(None),
        clock=clock,
        claim_nonce=partial(claim_nonce, outbox),
        association_reader=AssociationReader(outbox),
    )
    with patch.object(resumed.service, "send") as network:
        scheduler.do(doers=[resumed], tyme=2)
        network.assert_not_called()
    assert outbox.outbox.get(keys=(associationStatus.eventId,)) == failed

    def corrected(delivery):
        """Finish the explicit attempt after the operator has corrected configuration."""
        yield 0.01

    resumed.service.retry(associationStatus.eventId)
    with patch.object(resumed.service, "send", corrected):
        scheduler.do(doers=[resumed], tyme=4)
    delivered = outbox.outbox.get(keys=(associationStatus.eventId,))
    assert delivered.acknowledged and not delivered.blocked and delivered.attempts == 1


def test_retry_after_supports_seconds_and_http_date():
    """Use server delay or future HTTP date; malformed/past values add no delay."""
    now = 1000
    future = format_datetime(datetime.fromtimestamp(1600, timezone.utc), usegmt=True)
    sender = WebhookSender(
        reader=DeliveryReader(None),
        writer=DeliveryWriter(None),
        keys=ServiceKeys(None),
        clock=lambda: now,
        claim_nonce=partial(claim_nonce, None),
        association_reader=AssociationReader(None),
    )
    for value in ("600", future):
        with pytest.raises(_TransientFailure) as caught:
            sender.service.check_response(
                None,
                None,
                None,
                {
                    "errored": False,
                    "status": 429,
                    "headers": {"retry-after": value},
                },
            )
        assert caught.value.retry_after == 600
    assert _retry_after("nonsense", now) == _retry_after("-1", now) == 0
    assert _retry_after(future, 1700) == 0


def test_transient_attempt_budget_moves_to_dead_letter_without_history_scan(outbox):
    """A finite sender stops after three failures and restart never discovers it again."""
    associationStatus = accept(outbox, "bounded")
    sender = WebhookSender(
        reader=DeliveryReader(outbox),
        writer=DeliveryWriter(outbox),
        keys=ServiceKeys(None),
        interval=0.01,
        backoff_base=0.01,
        backoff_cap=0.01,
        clock=lambda: 1000,
        uniform=lambda low, high: low,
        claim_nonce=partial(claim_nonce, outbox),
        association_reader=AssociationReader(outbox),
    )

    def unavailable(delivery):
        yield 0.0
        raise TimeoutError("unavailable")

    deliveryService = delivery_service(outbox)
    deliveryService.start_ready(deliveryService.next_ready())
    for attempt in range(3):
        delivery = deliveryService.next_active()
        assert delivery.eventId == associationStatus.eventId
        with patch.object(sender.service, "send", unavailable):
            list(sender.service.attempt(delivery))
    delivery = outbox.outbox.get(keys=(associationStatus.eventId,))
    assert delivery.blocked and not delivery.acknowledged and delivery.attempts == 3
    assert outbox.delivery_dead.get(keys=(associationStatus.eventId,)) is not None
    outbox.close()
    outbox.reopen()
    assert delivery_service(outbox).next_active() is None
    assert delivery_service(outbox).next_ready() is None
    delivery_service(outbox).retry(associationStatus.eventId)
    assert delivery_service(outbox).next_ready().attempts == 0


def test_delivery_phase_resumes_active_and_releases_completed(outbox):
    """A crash retains the active event; ACK atomically removes its scheduling reference."""
    associationStatus = accept(outbox, "phase")
    deliveryService = delivery_service(outbox)
    delivery = deliveryService.next_ready()
    deliveryService.start_ready(delivery)
    assert delivery.eventId == associationStatus.eventId
    assert outbox.delivery_ready.cntAll() == 0
    outbox.close()
    outbox.reopen()
    assert delivery_service(outbox).next_active() == delivery
    delivery_service(outbox).acknowledge(delivery.eventId)
    assert outbox.delivery_active.cntAll() == 0
    assert delivery_service(outbox).next_active() is None
    assert delivery_service(outbox).next_ready() is None
    assert outbox.outbox.get(keys=(delivery.eventId,)).acknowledged


def test_late_completion_keeps_another_active_reference(outbox):
    """Completing an earlier event cannot remove the sender's different current item."""
    from eoa_verifier.persistence.records import DeliveryReference

    earlier = accept(outbox, "earlier")
    current = accept(outbox, "current")
    outbox.delivery_ready.rem(keys=(current.eventId,))
    outbox.delivery_active.pin(keys=("sender",), val=DeliveryReference(current.eventId))
    delivery_service(outbox).acknowledge(earlier.eventId)
    assert outbox.delivery_active.get(keys=("sender",)).eventId == current.eventId
    assert outbox.associations.get(keys=("current",)) == current
    assert not outbox.outbox.get(keys=(current.eventId,)).acknowledged
