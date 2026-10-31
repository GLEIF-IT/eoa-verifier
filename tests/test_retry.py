"""Exercise delivery scheduling with KERIpy storage and virtual HIO time, without network waits."""

from datetime import datetime, timezone
from email.utils import format_datetime
from unittest.mock import patch

import pytest
from hio.base import doing
from keri.db import dbing

from eoa_verifier.persistence.basing import VerifierBaser
from eoa_verifier.persistence.records import PendingVerification, VerificationResult
from eoa_verifier.delivery.delivering import WebhookSender, _TransientFailure, _retry_after


@pytest.fixture
def outbox(tmp_path):
    """Keep real application delivery records across reopen; no credential verification is simulated."""
    with dbing.openLMDB(
        cls=VerifierBaser, name="retry", headDirPath=str(tmp_path), temp=False
    ) as baser:
        yield baser


def accept(baser, said):
    """Create a completed result and its event at one shared destination."""
    baser.enqueue(PendingVerification(said, "grant"))
    baser.finish(
        VerificationResult(
            said, "verified", eoaResult={"wallet": "wallet", "accountObservation": {}}
        )
    )
    return baser.accept(
        said, association={}, destination="https://receiver.example/hook", peer_aid="peer"
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

    sender = WebhookSender(baser=outbox, hab=None, clock=clock, uniform=lower_bound)

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
    assert delivered.acknowledged and not delivered.blocked and delivered.attempts == 2


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
