"""One-at-a-time webhook attempts; delivery policy stays outside authentication."""

import json

from hio.base import doing
from hio.core import http
from hio.help import decking
from keri.help import helping

from .authing import AuthenticationError, ServiceAuthenticator


class _ClientDoer(http.ClientDoer):
    """Contain socket failure in one attempt; native exit still owns socket cleanup."""

    error = None

    def recur(self, tyme):
        """Let the sender record a failed attempt instead of stopping the service."""
        try:
            return super().recur(tyme)
        except OSError as error:
            self.error = error
            return True


class WebhookSender(doing.DoDoer):
    """Borrow stores/identity and own each attempt's HTTP client through HIO.

    Never-attempted events receive one initial attempt; request(event_id) schedules
    an explicit redelivery. Failure remains pending; this increment has no automatic
    retry loop. The persisted body and target are reused, but each attempt receives
    a new native signature and nonce.
    """

    def __init__(self, *, baser, hab, timeout=10.0, **kwa):
        self.baser, self.hab, self.timeout = baser, hab, timeout
        self.requests = decking.Deck()
        self.after = ""
        super().__init__(doers=[doing.doify(self.send_do)], **kwa)

    def request(self, event_id):
        """Queue one explicit attempt; delivered events are ignored when dispatched."""
        if event_id not in self.requests:
            self.requests.append(event_id)

    def send_do(self, tymth, tock=0.0, **opts):
        """Process requests sequentially; native child removal closes each HTTP client."""
        yield tock
        while True:
            if not self.requests:
                page = self.baser.delivery_batch(after=self.after)
                self.after = page[-1].eventId if page else ""
                for event in page:
                    if event.attempts == 0 and not event.delivered:
                        self.request(event.eventId)
                yield self.tock
                continue
            event_id = self.requests.popleft()
            event = self.baser.outbox.get(keys=(event_id,))
            if event is None or event.delivered:
                continue
            status = self.baser.associations.get(keys=(event.associationSaid,))
            if (
                status is None
                or status.status not in ("accepted", "revoked")
                or status.eventId != event_id
            ):
                self.baser.delivery_result(
                    event_id, error="event is no longer the current association status"
                )
                continue
            schedule = self.baser.destinations.get(keys=(event.destination,))
            if schedule.nextAttemptAt > helping.nowUTC().timestamp():
                self.request(event_id)
                yield self.tock
                continue
            self.baser.record_attempt(event_id)
            try:
                yield from self._send(event)
            except (AuthenticationError, OSError, ValueError) as error:
                self.baser.delivery_result(event_id, error=str(error))
            else:
                self.baser.delivery_result(event_id)
            yield self.tock

    def _send(self, event):
        """Yield through one signed HTTP request and validate its complete ACK contract.

        The receiver must return HTTP 200, authenticate the actual response bytes
        and this request reference, and return exactly {eventId, accepted: true}.
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
            if response["errored"]:
                raise ValueError(f"webhook HTTP framing: {response['error']}")
            if response["status"] != 200:
                raise ValueError(f"webhook HTTP {response['status']}")
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
                or set(ack) != {"eventId", "accepted"}
                or ack["eventId"] != event.eventId
                or ack["accepted"] is not True
            ):
                raise ValueError("webhook ACK does not accept the expected event")
        finally:
            self.remove([child])
