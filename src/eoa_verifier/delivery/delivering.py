"""One-item delivery policy over prepared atomic saves and a signed HTTP effect."""

import json
import math
import random
import ssl
import time
from dataclasses import replace
from email.utils import parsedate_to_datetime

from hio.base import doing

from eoa_verifier.persistence.records import DeliveryReference

from .authing import AuthenticationError
from .httping import WebhookHttp


class _TransientFailure(Exception):
    """An HTTP result that remains pending, optionally honoring Retry-After."""

    def __init__(self, message, *, retry_after=0.0):
        super().__init__(message)
        self.retry_after = retry_after


class DeliveryService:
    """Own work selection, attempts, backoff and authenticated ACK policy."""

    def __init__(
        self,
        reader,
        writer,
        transport=None,
        *,
        interval=1.0,
        backoff_base=1.0,
        backoff_cap=150.0,
        clock=time.time,
        uniform=random.uniform,
        max_attempts=3,
    ):
        """Borrow adapters; transport is unnecessary for offline recovery operations."""
        self.reader, self.writer, self.transport = reader, writer, transport
        self.interval, self.backoff_base, self.backoff_cap = (
            interval,
            backoff_base,
            backoff_cap,
        )
        self.clock, self.uniform = clock, uniform
        if max_attempts < 1:
            raise ValueError("max_attempts must be positive")
        self.max_attempts = max_attempts

    def next_delivery(self):
        """Resume active work before claiming the ready head; never scan outbox history."""
        reference = self.reader.delivery_reference("active")
        if reference is None:
            reference = self.reader.delivery_reference("ready")
            if reference is None:
                return None
            self.writer.activate_delivery(reference)
        delivery = self.reader.delivery(reference.eventId)
        if delivery is None:
            raise ValueError("scheduled delivery event is absent")
        return delivery

    def retry(self, event_id):
        """Reset a corrected dead letter without resetting destination cooldown."""
        reference = self.reader.delivery_reference("dead", event_id)
        if reference is None:
            raise ValueError("unknown dead-letter event")
        previous = self.reader.delivery(event_id)
        delivery = replace(previous, blocked=False, error="", attempts=0)
        self.writer.retry_delivery(previous, delivery, reference)

    def record_attempt(self, event_id, *, next_attempt_at=None):
        """Prepare durable attempt accounting and request-start pacing before I/O."""
        previous = self.reader.delivery(event_id)
        if previous is None:
            raise ValueError("unknown delivery event")
        if previous.acknowledged:
            return previous
        delivery = replace(
            previous,
            attempts=previous.attempts + 1,
            blocked=False,
            error="attempt started; authenticated ACK not recorded",
        )
        schedule = None
        if next_attempt_at is not None:
            schedule = self.reader.destination_schedule(delivery.destination)
            schedule = replace(
                schedule, nextAttemptAt=max(schedule.nextAttemptAt, next_attempt_at)
            )
        self.writer.save_delivery(previous, delivery, schedule)
        return delivery

    def complete(self, event_id, *, outcome, error="", schedule=None):
        """Persist an explicit acknowledged, retry or dead-letter outcome."""
        if outcome not in ("acknowledged", "retry", "dead-letter"):
            raise ValueError("unknown delivery outcome")
        previous = self.reader.delivery(event_id)
        if previous is None:
            raise ValueError("unknown delivery event")
        if previous.acknowledged:
            return
        acknowledged, blocked = outcome == "acknowledged", outcome == "dead-letter"
        delivery = replace(
            previous, error=error, blocked=blocked, acknowledged=acknowledged
        )
        if acknowledged:
            schedule = replace(
                self.reader.destination_schedule(delivery.destination), failures=0
            )
        self.writer.save_delivery(
            previous,
            delivery,
            schedule,
            completed=acknowledged or blocked,
            dead=DeliveryReference(event_id) if blocked else None,
        )

    def process_one(self):
        """Advance one ready/current event, yielding only through its HTTP effect."""
        delivery = self.next_delivery()
        if delivery is None:
            return
        status = self.reader.association(delivery.associationSaid)
        if (
            status is None
            or status.status not in ("accepted", "revoked")
            or status.eventId != delivery.eventId
        ):
            self.complete(
                delivery.eventId,
                outcome="dead-letter",
                error="event is no longer the current association status",
            )
            return
        if (
            self.reader.destination_schedule(delivery.destination).nextAttemptAt
            <= self.clock()
        ):
            yield from self.attempt(delivery)

    def attempt(self, delivery):
        """Persist pacing before HTTP; prepare the explicit result after it returns."""
        if delivery.attempts >= self.max_attempts:
            self.complete(
                delivery.eventId,
                outcome="dead-letter",
                error="delivery attempt limit reached",
            )
            return
        delivery = self.record_attempt(
            delivery.eventId, next_attempt_at=self.clock() + self.interval
        )
        try:
            yield from self.send(delivery)
        except (AuthenticationError, ValueError, ssl.SSLCertVerificationError) as error:
            self.complete(
                delivery.eventId,
                outcome="dead-letter",
                error=str(error) or type(error).__name__,
            )
        except (_TransientFailure, OSError) as error:
            schedule = self.reader.destination_schedule(delivery.destination)
            schedule = replace(schedule, failures=schedule.failures + 1)
            exponent = min(
                schedule.failures - 1,
                math.ceil(math.log2(self.backoff_cap / self.backoff_base)),
            )
            lower = min(self.backoff_base * 2**exponent, self.backoff_cap)
            delay = max(
                self.uniform(lower, 2 * lower), getattr(error, "retry_after", 0.0)
            )
            schedule = replace(
                schedule,
                nextAttemptAt=max(schedule.nextAttemptAt, self.clock() + delay),
            )
            self.complete(
                delivery.eventId,
                outcome="dead-letter"
                if delivery.attempts >= self.max_attempts
                else "retry",
                error=str(error) or type(error).__name__,
                schedule=schedule,
            )
        else:
            self.complete(delivery.eventId, outcome="acknowledged")

    def send(self, delivery):
        """Authenticate and validate the response produced by the signed HTTP adapter."""
        auth, requestAuth, response = yield from self.transport.send(delivery)
        self.check_response(delivery, auth, requestAuth, response)

    def check_response(self, delivery, auth, requestAuth, response):
        """Require HTTP success and the signed ACK for this attempt and event."""
        if response["errored"]:
            raise ValueError(f"webhook HTTP framing: {response['error']}")
        statusCode = response["status"]
        if statusCode in (408, 429) or (
            500 <= statusCode < 600 and statusCode not in (501, 505)
        ):
            raise _TransientFailure(
                f"webhook HTTP {statusCode}",
                retry_after=_retry_after(
                    response["headers"].get("retry-after"), self.clock()
                ),
            )
        if statusCode != 200:
            raise ValueError(f"webhook HTTP {statusCode}")
        auth.verify(
            method="POST",
            target=delivery.destination,
            action="ack",
            body=response["body"],
            headers=response["headers"],
            request=requestAuth.reference,
            status=response["status"],
        )
        ack = json.loads(response["body"])
        if (
            not isinstance(ack, dict)
            or set(ack) != {"eventId", "stored"}
            or ack["eventId"] != delivery.eventId
            or ack["stored"] is not True
        ):
            raise ValueError(
                "webhook ACK does not confirm storage of the expected event"
            )


class WebhookSender(doing.DoDoer):
    """Schedule one delivery operation and own its temporary HTTP child tasks."""

    def __init__(
        self,
        *,
        reader,
        writer,
        keys,
        timeout=10.0,
        interval=1.0,
        backoff_base=1.0,
        backoff_cap=150.0,
        clock=time.time,
        uniform=random.uniform,
        max_attempts=3,
        **kwa,
    ):
        """Compose the delivery service with this scheduler's HTTP client adapter."""
        self.service = DeliveryService(
            reader,
            writer,
            WebhookHttp(self, keys, writer.claim_nonce, timeout=timeout),
            interval=interval,
            backoff_base=backoff_base,
            backoff_cap=backoff_cap,
            clock=clock,
            uniform=uniform,
            max_attempts=max_attempts,
        )
        super().__init__(doers=[doing.doify(self.send_do)], **kwa)

    def send_do(self, tymth, tock=0.0, **opts):
        """Yield after every single operation, including stale/dead-letter decisions."""
        yield tock
        while True:
            yield from self.service.process_one()
            yield self.tock


def _retry_after(value, now):
    """Return a nonnegative server-requested delay; ignore malformed values."""
    if value is None:
        return 0.0
    value = value.strip()
    if value.isascii() and value.isdigit():
        seconds = float(value)
        return seconds if math.isfinite(seconds) else 0.0
    try:
        date = parsedate_to_datetime(value)
        return max(0.0, date.timestamp() - now) if date.tzinfo else 0.0
    except (TypeError, ValueError, OverflowError):
        return 0.0
