"""Owned HIO client lifetime for one signed immutable status-event POST."""

from hio.core import http

from .authing import ServiceAuthenticator


class _ClientDoer(http.ClientDoer):
    """Contain socket/framing failure in one attempt; HIO exit still owns socket cleanup."""

    error = None

    def recur(self, tyme):
        """Let the sender record a failed attempt instead of stopping the service."""
        try:
            return super().recur(tyme)
        except (OSError, ValueError) as error:
            # HIO chunk-size parsing raises ValueError outside its HTTPException path.
            self.error = error
            return True


class WebhookHttp:
    """Perform HTTP effects; leave response/ACK policy to the delivery service."""

    def __init__(self, scheduler, keys, claim_nonce, *, timeout=10.0):
        """Borrow scheduler/signing/replay dependencies and own each temporary client."""
        self.scheduler, self.keys, self.claim_nonce = scheduler, keys, claim_nonce
        self.timeout = timeout

    def send(self, delivery):
        """Yield through a signed POST and return authentication context plus raw response.

        The client closes before the application service checks the ACK. Framing,
        disconnect and timeout failures propagate; no delivery outcome is persisted here.
        """
        auth = ServiceAuthenticator(
            keys=self.keys, claim_nonce=self.claim_nonce, peer_aid=delivery.peerAid
        )
        body = delivery.body.encode("utf-8")
        headers, requestAuth = auth.sign(
            method="POST", target=delivery.destination, action="status", body=body
        )
        client = http.Client(
            path=delivery.destination, reconnectable=False, redirectable=False
        )
        child = _ClientDoer(client=client)
        try:
            self.scheduler.extend([child])
            deadline = self.scheduler.tyme + self.timeout
            client.request(method="POST", headers=headers, body=body)
            while not client.responses:
                if child.error is not None:
                    raise child.error
                if self.scheduler.tyme >= deadline:
                    raise TimeoutError("webhook request timed out")
                yield self.scheduler.tock
            response = client.responses.popleft()
            if response["errored"] and client.connector.cutoff:
                raise ConnectionError(
                    "webhook connection closed before a complete response"
                )
            return auth, requestAuth, response
        finally:
            self.scheduler.remove([child])
