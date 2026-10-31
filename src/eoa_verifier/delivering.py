"""One-at-a-time webhook attempts; delivery policy stays outside authentication."""

import json
import math
import random
import ssl
import time
from email.utils import parsedate_to_datetime

from hio.base import doing
from hio.core import http
from hio.help import decking

from .authing import AuthenticationError, ServiceAuthenticator


class _ClientDoer(http.ClientDoer):
    """Contain socket failure in one attempt; HIO exit still owns socket cleanup."""

    error = None

    def recur(self, tyme):
        """Let the sender record a failed attempt instead of stopping the service."""
        try:
            return super().recur(tyme)
        except OSError as error:
            self.error = error
            return True


class _TransientFailure(Exception):
    """An HTTP result that remains pending, optionally honoring Retry-After."""

    def __init__(self, message, *, retry_after=0.0):
        super().__init__(message)
        self.retry_after = retry_after


class WebhookSender(doing.DoDoer):
    """Own sequential attempts, destination pacing and authenticated completion.

    Scan pending outbox events across restart. Transient failures cool down every
    event for that destination; permanent failures wait for correction and explicit
    request(event_id). Reuse stored bytes/target but sign every attempt anew.
    The injected UTC clock and uniform random source permit deterministic policy tests.
    """

    def __init__(
        self,
        *,
        baser,
        hab,
        timeout=10.0,
        interval=1.0,
        backoff_base=1.0,
        backoff_cap=150.0,
        clock=time.time,
        uniform=random.uniform,
        **kwa,
    ):
        self.baser, self.hab, self.timeout = baser, hab, timeout
        self.interval, self.backoff_base, self.backoff_cap = (
            interval,
            backoff_base,
            backoff_cap,
        )
        self.clock, self.uniform = clock, uniform
        self.requests = decking.Deck()
        self.after = ""
        super().__init__(doers=[doing.doify(self.send_do)], **kwa)

    def request(self, event_id):
        """Resume an event after correcting its failure; still respect destination cooldown."""
        if event_id not in self.requests:
            self.requests.append(event_id)

    def send_do(self, tymth, tock=0.0, **opts):
        """Process requests sequentially; HIO child removal closes each HTTP client."""
        yield tock
        while True:
            if not self.requests:
                page = self.baser.delivery_batch(after=self.after)
                self.after = page[-1].eventId if page else ""
                for event in page:
                    if not event.acknowledged and not event.blocked:
                        self.request(event.eventId)
                yield self.tock
                continue
            event_id = self.requests.popleft()
            event = self.baser.outbox.get(keys=(event_id,))
            if event is None or event.acknowledged:
                continue
            status = self.baser.associations.get(keys=(event.associationSaid,))
            if (
                status is None
                or status.status not in ("accepted", "revoked")
                or status.eventId != event_id
            ):
                self.baser.delivery_result(
                    event_id,
                    error="event is no longer the current association status",
                    blocked=True,
                )
                continue
            schedule = self.baser.destinations.get(keys=(event.destination,))
            if schedule.nextAttemptAt > self.clock():
                self.request(event_id)
                yield self.tock
                continue
            yield from self._attempt(event)
            yield self.tock

    def _attempt(self, event):
        """Persist pacing before I/O, then atomically record the result and cooldown."""
        self.baser.record_attempt(
            event.eventId, next_attempt_at=self.clock() + self.interval
        )
        try:
            yield from self._send(event)
        except (AuthenticationError, ValueError, ssl.SSLCertVerificationError) as error:
            self.baser.delivery_result(
                event.eventId, error=str(error) or type(error).__name__, blocked=True
            )
        except (_TransientFailure, OSError) as error:
            schedule = self.baser.destinations.get(keys=(event.destination,))
            schedule.failures += 1
            # Clamp the exponent before computing it; failures can accumulate indefinitely.
            exponent = min(
                schedule.failures - 1,
                math.ceil(math.log2(self.backoff_cap / self.backoff_base)),
            )
            lower = min(self.backoff_base * 2**exponent, self.backoff_cap)
            delay = max(
                self.uniform(lower, 2 * lower), getattr(error, "retry_after", 0.0)
            )
            schedule.nextAttemptAt = max(schedule.nextAttemptAt, self.clock() + delay)
            self.baser.delivery_result(
                event.eventId,
                error=str(error) or type(error).__name__,
                schedule=schedule,
            )
        else:
            self.baser.delivery_result(event.eventId)

    def _send(self, event):
        """Yield through one signed HTTP request and validate its complete ACK contract.

        The receiver must return HTTP 200, authenticate the actual response bytes
        and this request reference, and return exactly {eventId, stored: true}.
        A valid signature on an error response never establishes delivery success.
        This component, not ServiceAuthenticator, owns that decision.
        """
        auth = ServiceAuthenticator(
            hab=self.hab, baser=self.baser, peer_aid=event.peerAid
        )
        body = event.body.encode("utf-8")
        headers, sent = auth.sign(
            method="POST", target=event.destination, action="status", body=body
        )
        client = http.Client(
            path=event.destination, reconnectable=False, redirectable=False
        )
        child = _ClientDoer(client=client)
        try:
            self.extend([child])
            deadline = self.tyme + self.timeout
            client.request(method="POST", headers=headers, body=body)
            while not client.responses:
                if child.error is not None:
                    raise child.error
                if self.tyme >= deadline:
                    raise TimeoutError("webhook request timed out")
                yield self.tock
            response = client.responses.popleft()
            if response["errored"] and client.connector.cutoff:
                raise ConnectionError(
                    "webhook connection closed before a complete response"
                )
            self._check_response(event, auth, sent, response)
        finally:
            self.remove([child])

    def _check_response(self, event, auth, sent, response):
        """Require HTTP success and the signed ACK for this attempt and event."""
        if response["errored"]:
            raise ValueError(f"webhook HTTP framing: {response['error']}")
        status = response["status"]
        if status in (408, 429) or (500 <= status < 600 and status not in (501, 505)):
            raise _TransientFailure(
                f"webhook HTTP {status}",
                retry_after=_retry_after(
                    response["headers"].get("retry-after"), self.clock()
                ),
            )
        if status != 200:
            raise ValueError(f"webhook HTTP {status}")
        auth.verify(
            method="POST",
            target=event.destination,
            action="ack",
            body=response["body"],
            headers=response["headers"],
            request=sent.reference,
            status=response["status"],
        )
        ack = json.loads(response["body"])
        if (
            not isinstance(ack, dict)
            or set(ack) != {"eventId", "stored"}
            or ack["eventId"] != event.eventId
            or ack["stored"] is not True
        ):
            raise ValueError("webhook ACK does not confirm storage of the expected event")


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
