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
        """Retain a transient failure and the optional server-requested delay."""
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
        association_reader,
        interval=1.0,
        backoff_base=1.0,
        backoff_cap=150.0,
        clock=time.time,
        uniform=random.uniform,
        max_attempts=3,
    ):
        """Borrow adapters; transport is unnecessary for offline recovery operations."""
        self.reader, self.writer, self.transport = reader, writer, transport
        self.association_reader = association_reader
        self.interval, self.backoff_base, self.backoff_cap = (
            interval,
            backoff_base,
            backoff_cap,
        )
        self.clock, self.uniform = clock, uniform
        if max_attempts < 1:
            raise ValueError("max_attempts must be positive")
        self.max_attempts = max_attempts

    def next_active(self):
        """Read the active delivery without consulting or claiming ready work."""
        reference = self.reader.active_ref()
        return self._delivery(reference.eventId) if reference is not None else None

    def next_ready(self):
        """Read the ready delivery head without changing its scheduling reference."""
        reference = self.reader.ready_ref()
        return self._delivery(reference.eventId) if reference is not None else None

    def start_ready(self, delivery):
        """Commit ready-to-active before attempting the selected delivery."""
        self.writer.ready_to_active(DeliveryReference(delivery.eventId))

    def retry(self, event_id):
        """Reset a corrected dead letter without resetting destination cooldown."""
        reference = self.reader.dead_ref(event_id)
        if reference is None:
            raise ValueError("unknown dead-letter event")
        previous = self.reader.delivery(event_id)
        delivery = replace(previous, blocked=False, error="", attempts=0)
        self.writer.dead_to_ready(previous, delivery, reference)

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
        schedule = self.reader.schedule(delivery.destination)
        if next_attempt_at is not None:
            schedule = replace(
                schedule, nextAttemptAt=max(schedule.nextAttemptAt, next_attempt_at)
            )
        self.writer.record_attempt(previous, delivery, schedule)
        return delivery

    def acknowledge(self, event_id):
        """Prepare authenticated completion and reset destination failure backoff."""
        previous = self._delivery(event_id)
        if previous.acknowledged:
            return
        delivery = replace(previous, error="", blocked=False, acknowledged=True)
        schedule = replace(
            self.reader.schedule(delivery.destination), failures=0
        )
        self.writer.ack(
            previous, delivery, schedule, DeliveryReference(event_id)
        )

    def defer(self, event_id, *, error, schedule=None):
        """Prepare retry progress while retaining the active delivery reference."""
        previous = self._delivery(event_id)
        if previous.acknowledged:
            return
        delivery = replace(previous, error=error, blocked=False, acknowledged=False)
        schedule = schedule or self.reader.schedule(delivery.destination)
        self.writer.defer(previous, delivery, schedule)

    def dead_letter(self, event_id, *, error, schedule=None):
        """Prepare a stopped event and its dedicated dead-letter reference."""
        previous = self._delivery(event_id)
        if previous.acknowledged:
            return
        delivery = replace(previous, error=error, blocked=True, acknowledged=False)
        schedule = schedule or self.reader.schedule(delivery.destination)
        self.writer.dead_letter(
            previous, delivery, schedule, DeliveryReference(event_id)
        )

    def _delivery(self, event_id):
        """Read an identified event or fail on missing durable state."""
        delivery = self.reader.delivery(event_id)
        if delivery is None:
            raise ValueError("unknown delivery event")
        return delivery

    def process_one(self):
        """Advance one ready/current event, yielding only through its HTTP effect."""
        delivery = self.next_active()
        if delivery is None:
            delivery = self.next_ready()
            if delivery is None:
                return
            self.start_ready(delivery)
        status = self.association_reader.association(delivery.associationSaid)
        if (
            status is None
            or status.status not in ("accepted", "revoked")
            or status.eventId != delivery.eventId
        ):
            self.dead_letter(
                delivery.eventId,
                error="event is no longer the current association status",
            )
            return
        if (
            self.reader.schedule(delivery.destination).nextAttemptAt
            <= self.clock()
        ):
            yield from self.attempt(delivery)

    def attempt(self, delivery):
        """Persist pacing before HTTP; prepare the explicit result after it returns."""
        if delivery.attempts >= self.max_attempts:
            self.dead_letter(
                delivery.eventId,
                error="delivery attempt limit reached",
            )
            return
        delivery = self.record_attempt(
            delivery.eventId, next_attempt_at=self.clock() + self.interval
        )
        try:
            yield from self.send(delivery)
        except (AuthenticationError, ValueError, ssl.SSLCertVerificationError) as error:
            self.dead_letter(
                delivery.eventId,
                error=str(error) or type(error).__name__,
            )
        except (_TransientFailure, OSError) as error:
            schedule = self.reader.schedule(delivery.destination)
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
            reason = str(error) or type(error).__name__
            if delivery.attempts >= self.max_attempts:
                self.dead_letter(delivery.eventId, error=reason, schedule=schedule)
            else:
                self.defer(delivery.eventId, error=reason, schedule=schedule)
        else:
            self.acknowledge(delivery.eventId)

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
        claim_nonce,
        association_reader,
        timeout=10.0,
        interval=1.0,
        backoff_base=1.0,
        backoff_cap=150.0,
        clock=time.time,
        uniform=random.uniform,
        max_attempts=3,
        **kwa,
    ):
        """Borrow delivery persistence and a transport replay-claim callable.

        Compose the delivery service with this scheduler's HTTP client adapter."""
        self.service = DeliveryService(
            reader,
            writer,
            WebhookHttp(self, keys, claim_nonce, timeout=timeout),
            association_reader=association_reader,
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
