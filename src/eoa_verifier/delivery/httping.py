"""Owned HIO client lifetime for one signed immutable status-event POST."""

from hio.core import http

from .authing import HttpSignatures


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
    """Sign HTTP requests and check optional response signatures; leave result policy to the service."""

    def __init__(self, scheduler, keys, *, timeout=10.0):
        """Borrow scheduler/signing dependencies and own each temporary client."""
        self.scheduler, self.signatures = scheduler, HttpSignatures(keys)
        self.timeout = timeout

    def send(self, delivery):
        """Send signed bytes, check any response signature, and return the HTTP result.

        The client closes before the application service decides delivery success. Framing,
        disconnect and timeout failures propagate; no delivery outcome is persisted here.
        """
        body = delivery.body.encode("utf-8")
        headers = self.signatures.sign(
            method="POST", target=delivery.destination, body=body
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
            self.signatures.verify_optional(
                method="POST",
                target=delivery.destination,
                body=response["body"],
                headers=response["headers"],
            )
            return response
        finally:
            self.scheduler.remove([child])
