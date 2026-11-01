"""OOBI HTTP clients tolerate the pinned HIO initial-connect race.

HIO 0.6.22 can report a successful connect_ex followed by EINVAL/ENOTCONN
from getpeername when a peer has not started. Reopen only that unconnected
socket and retain the queued GET. Established-connection and TLS failures
still propagate; KERIpy owns resolution, parsing and its normal retry policy.
"""

import errno
import logging
from urllib.parse import urlparse

from hio.core import http
from keri.app import httping
from keri.help import helping

logger = logging.getLogger(__name__)


class _OobiClientDoer(http.ClientDoer):
    """Keep an initial refused connection from stopping the service scheduler."""

    def recur(self, tyme):
        """Retry only the unconnected-socket race, preserving native GET state."""
        try:
            return super().recur(tyme)
        except OSError as error:
            if self.client.connector.connected or error.errno not in (
                errno.EINVAL,
                errno.ENOTCONN,
            ):
                raise
            self.client.connector.reopen()


class OobiClienter(httping.Clienter):
    """Retain KERIpy client ownership with a narrowly adapted HTTP child doer."""

    def request(self, method, url, body=None, headers=None):
        """Mirror pinned Clienter.request while containing the initial-connect race.

        The base Clienter still owns child shutdown and completed-client cleanup.
        URL/header/body handling and its client timestamp records retain the
        pinned implementation's shape; no application retry budget is added.
        """
        parsed = urlparse(url)
        try:
            client = http.Client(
                scheme=parsed.scheme,
                hostname=parsed.hostname,
                port=parsed.port,
                portOptional=True,
            )
        except Exception as error:
            logger.warning("Cannot create OOBI HTTP client for %s: %s", url, error)
            return None
        if hasattr(body, "encode"):
            body = body.encode("utf-8")
        client.request(
            method=method,
            path=f"{parsed.path}?{parsed.query}",
            qargs=None,
            headers=headers,
            body=body,
        )
        doer = _OobiClientDoer(client=client)
        self.extend([doer])
        self.clients.append((client, doer, helping.nowUTC()))
        return client
