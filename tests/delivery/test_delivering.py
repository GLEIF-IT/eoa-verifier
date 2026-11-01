"""Delivery progression, pacing, bounded retries and recovery."""

from datetime import datetime, timezone
from email.utils import format_datetime
from unittest.mock import patch

import pytest
from hio.base import doing

from eoa_verifier.delivery.delivering import (
    WebhookSender,
    _retry_after,
    _TransientFailure,
)
from eoa_verifier.delivery.keys import ServiceKeys
from eoa_verifier.persistence.associations import AssociationReader
from eoa_verifier.persistence.delivery import DeliveryReader, DeliveryWriter
from eoa_verifier.persistence.records import VerificationRecord, VerificationResult
from tests.support.acceptance import acceptance_service
from tests.support.persistence import enqueue_verification
from tests.support.services import delivery_service, verification_service


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
    assert all(delivery.delivered for _, delivery in outbox.outbox.getItemIter())
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
        association_reader=AssociationReader(outbox),
    )
    starts = []

    def complete(delivery):
        """Record the dispatch time; network ACK validation is covered by signed HTTP tests."""
        starts.append(clock())
        yield 0.01

    scheduler.tyme = 599
    scheduler.limit = 5
    with patch.object(resumed.service, "send", complete):
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
        association_reader=AssociationReader(outbox),
    )

    def misconfigured(delivery):
        """Model a permanent endpoint failure without replacing any signature test."""
        yield 0.01
        raise ValueError("webhook HTTP 401")

    with patch.object(sender.service, "send", misconfigured):
        scheduler.do(doers=[sender])
    failed = outbox.outbox.get(keys=(associationStatus.eventId,))
    assert failed.blocked and not failed.delivered and failed.attempts == 1
    outbox.close()
    outbox.reopen()
    resumed = WebhookSender(
        reader=DeliveryReader(outbox),
        writer=DeliveryWriter(outbox),
        keys=ServiceKeys(None),
        clock=clock,
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
    assert delivered.delivered and not delivered.blocked and delivered.attempts == 1


def test_retry_after_supports_seconds_and_http_date():
    """Use server delay or future HTTP date; malformed/past values add no delay."""
    now = 1000
    future = format_datetime(datetime.fromtimestamp(1600, timezone.utc), usegmt=True)
    sender = WebhookSender(
        reader=DeliveryReader(None),
        writer=DeliveryWriter(None),
        keys=ServiceKeys(None),
        clock=lambda: now,
        association_reader=AssociationReader(None),
    )
    for value in ("600", future):
        with pytest.raises(_TransientFailure) as caught:
            sender.service.check_response(
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
    assert delivery.blocked and not delivery.delivered and delivery.attempts == 3
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
    delivery_service(outbox).complete(delivery.eventId)
    assert outbox.delivery_active.cntAll() == 0
    assert delivery_service(outbox).next_active() is None
    assert delivery_service(outbox).next_ready() is None
    assert outbox.outbox.get(keys=(delivery.eventId,)).delivered


def test_late_completion_keeps_another_active_reference(outbox):
    """Completing an earlier event cannot remove the sender's different current item."""
    from eoa_verifier.persistence.records import DeliveryReference

    earlier = accept(outbox, "earlier")
    current = accept(outbox, "current")
    outbox.delivery_ready.rem(keys=(current.eventId,))
    outbox.delivery_active.pin(keys=("sender",), val=DeliveryReference(current.eventId))
    delivery_service(outbox).complete(earlier.eventId)
    assert outbox.delivery_active.get(keys=("sender",)).eventId == current.eventId
    assert outbox.associations.get(keys=("current",)) == current
    assert not outbox.outbox.get(keys=(current.eventId,)).delivered
