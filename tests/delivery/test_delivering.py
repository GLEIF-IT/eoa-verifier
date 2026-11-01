"""delivery/test_delivering.py."""

import json
from datetime import datetime, timezone
from email.utils import format_datetime
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
from eoa_verifier.persistence.basing import VerifierBaser
from eoa_verifier.persistence.records import PendingVerification, VerificationResult
from tests.support.network import free_port


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
                            else (
                                "association:1"
                                if reply == "retirement-initial-ack"
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
        baser.next_verification(now=0)
        baser.finish(
            VerificationResult(
                "association",
                "verified",
                eoaResult={
                    "wallet": "wallet",
                    "accountObservation": {"chainId": 31337},
                },
            )
        )
        accepted = baser.accept(
            "association",
            association={"issuerAid": "issuer"},
            nonce="other",
            destination=target,
            peer_aid=receiver_hab.pre,
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
        baser.enqueue(PendingVerification("association", "grant"))
        baser.next_verification(now=0)
        baser.finish(
            VerificationResult(
                "association",
                "verified",
                eoaResult={"wallet": "wallet", "accountObservation": {}},
            )
        )
        status = baser.accept(
            "association",
            association={"issuerAid": "issuer"},
            nonce="other",
            destination=f"http://127.0.0.1:{server.ha[1]}/hook",
            peer_aid=hab.pre,
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


def accept(baser, said):
    """Create a completed result and its event at one shared destination."""
    baser.enqueue(PendingVerification(said, "grant"))
    baser.next_verification(now=0)
    baser.finish(
        VerificationResult(
            said, "verified", eoaResult={"wallet": "wallet", "accountObservation": {}}
        )
    )
    return baser.accept(
        said,
        association={"issuerAid": "issuer"},
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
        baser=outbox, hab=None, clock=clock, uniform=lower_bound, max_attempts=12
    )

    def attempt(event):
        """Hold each attempt open over scheduler turns, then fail ten times before succeeding."""
        starts.append(clock())
        yield 1.5 if len(ranges) < 10 else 0.2
        if len(ranges) < 10:
            raise TimeoutError("target unavailable")
        if len(starts) == 11:
            # Queue another event as this attempt succeeds; retain request-start pacing.
            accept(outbox, "c")

    with patch.object(sender, "_send", attempt):
        scheduler.do(doers=[sender])
    assert ranges == [(n, 2 * n) for n in (1, 2, 4, 8, 16, 32, 64, 128, 150, 150)]
    assert len(starts) == 13
    assert all(b - a >= 1.5 - 1e-6 for a, b in zip(starts[:10], starts[1:11]))
    assert all(b - a >= 1 - 1e-6 for a, b in zip(starts, starts[1:]))
    assert all(event.acknowledged for _, event in outbox.outbox.getItemIter())
    assert (
        outbox.destinations.get(keys=("https://receiver.example/hook",)).failures == 0
    )


def test_cooldown_survives_restart_and_gates_new_events(outbox):
    """Retry-After beyond the cap gates a new backlog event after restart, then ACK resets failures."""
    original = accept(outbox, "a")
    scheduler = doing.Doist(tock=0.01, limit=1)
    clock = lambda: 1000 + scheduler.tyme
    sender = WebhookSender(
        baser=outbox, hab=None, clock=clock, uniform=lambda low, high: high
    )

    def unavailable(event):
        """Return the same transient classification as a rate-limited HTTP endpoint."""
        yield 0.01
        raise _TransientFailure("webhook HTTP 429", retry_after=600)

    with patch.object(sender, "_send", unavailable):
        scheduler.do(doers=[sender])
    event = outbox.outbox.get(keys=(original.eventId,))
    schedule = outbox.destinations.get(keys=(event.destination,))
    assert schedule.failures == 1 and schedule.nextAttemptAt >= 1600
    outbox.close()
    outbox.reopen()
    accept(outbox, "b")  # Acceptance must not replace the destination's cooldown.
    assert outbox.destinations.get(keys=(event.destination,)) == schedule

    resumed = WebhookSender(baser=outbox, hab=None, clock=clock)
    starts = []

    def acknowledge(event):
        """Record the dispatch time; network ACK validation is covered by signed HTTP tests."""
        starts.append(clock())
        yield 0.01

    scheduler.tyme = 599
    scheduler.limit = 5
    with patch.object(resumed, "_send", acknowledge):
        scheduler.do(doers=[resumed], tyme=599)
    assert len(starts) == 2 and min(starts) >= schedule.nextAttemptAt
    assert starts[1] - starts[0] >= 1 - 1e-6
    assert outbox.destinations.get(keys=(event.destination,)).failures == 0
    assert outbox.outbox.get(keys=(original.eventId,)).attempts == 2


def test_permanent_failure_waits_for_explicit_resumption(outbox):
    """Permanent failures remain visible and blocked across restart until the caller corrects/resumes them."""
    accepted = accept(outbox, "a")
    scheduler = doing.Doist(tock=0.01, limit=2)
    clock = lambda: 1000 + scheduler.tyme
    sender = WebhookSender(baser=outbox, hab=None, clock=clock)

    def misconfigured(event):
        """Model a permanent endpoint failure without replacing any signature test."""
        yield 0.01
        raise ValueError("webhook HTTP 401")

    with patch.object(sender, "_send", misconfigured):
        scheduler.do(doers=[sender])
    failed = outbox.outbox.get(keys=(accepted.eventId,))
    assert failed.blocked and not failed.acknowledged and failed.attempts == 1
    outbox.close()
    outbox.reopen()
    resumed = WebhookSender(baser=outbox, hab=None, clock=clock)
    with patch.object(resumed, "_send") as network:
        scheduler.do(doers=[resumed], tyme=2)
        network.assert_not_called()
    assert outbox.outbox.get(keys=(accepted.eventId,)) == failed

    def corrected(event):
        """Finish the explicit attempt after the operator has corrected configuration."""
        yield 0.01

    resumed.request(accepted.eventId)
    with patch.object(resumed, "_send", corrected):
        scheduler.do(doers=[resumed], tyme=4)
    delivered = outbox.outbox.get(keys=(accepted.eventId,))
    assert delivered.acknowledged and not delivered.blocked and delivered.attempts == 1


def test_retry_after_supports_seconds_and_http_date():
    """Use server delay or future HTTP date; malformed/past values add no delay."""
    now = 1000
    future = format_datetime(datetime.fromtimestamp(1600, timezone.utc), usegmt=True)
    sender = WebhookSender(baser=None, hab=None, clock=lambda: now)
    for value in ("600", future):
        with pytest.raises(_TransientFailure) as caught:
            sender._check_response(
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
    accepted = accept(outbox, "bounded")
    sender = WebhookSender(
        baser=outbox,
        hab=None,
        interval=0.01,
        backoff_base=0.01,
        backoff_cap=0.01,
        clock=lambda: 1000,
        uniform=lambda low, high: low,
    )

    def unavailable(event):
        yield 0.0
        raise TimeoutError("unavailable")

    for attempt in range(3):
        event = outbox.next_delivery()
        assert event.eventId == accepted.eventId
        with patch.object(sender, "_send", unavailable):
            list(sender._attempt(event))
    event = outbox.outbox.get(keys=(accepted.eventId,))
    assert event.blocked and not event.acknowledged and event.attempts == 3
    assert outbox.delivery_dead.get(keys=(accepted.eventId,)) is not None
    outbox.close()
    outbox.reopen()
    assert outbox.next_delivery() is None
    outbox.retry_delivery(accepted.eventId)
    assert outbox.next_delivery().attempts == 0


def test_delivery_phase_resumes_active_and_releases_completed(outbox):
    """A crash retains the active event; ACK atomically removes its scheduling reference."""
    accepted = accept(outbox, "phase")
    event = outbox.next_delivery()
    assert event.eventId == accepted.eventId
    assert outbox.delivery_ready.cntAll() == 0
    outbox.close()
    outbox.reopen()
    assert outbox.next_delivery() == event
    outbox.delivery_result(event.eventId)
    assert outbox.delivery_active.cntAll() == 0
    assert outbox.next_delivery() is None
    assert outbox.outbox.get(keys=(event.eventId,)).acknowledged
