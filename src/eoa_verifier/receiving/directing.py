"""Direct CESR intake and KERIpy parser/escrow scheduling."""

import logging

import falcon
from hio.base import doing
from hio.help import decking
from keri import kering
from keri.app import httping
from keri.core import coring

logger = logging.getLogger(__name__)


class Receiver(doing.DoDoer):
    """Schedule one borrowed parser and its KERIpy escrow processors.

    ``parser`` must provide KEL, reply, exchange, TEL and credential processors.
    ``msg_tock`` and ``escrow_tock`` are HIO-clock intervals in seconds. The
    service supplies the existing KERIpy mailbox timing settings for compatibility;
    this receiver does not poll mailboxes. HTTP intake and Grant replay share the
    processors. ``msgs`` holds completed HTTP requests in separate bytearrays;
    it is transient intake, not a durable work queue. Closing this Doer stops its
    tasks, not the borrowed stores."""

    def __init__(self, parser, *, msg_tock, escrow_tock, **kwa):
        self.parser = parser
        self.msgs = decking.Deck()
        super().__init__(
            doers=[
                doing.doify(self.msgDo, tock=msg_tock),
                doing.doify(self.escrowDo, tock=escrow_tock),
            ],
            **kwa,
        )

    def msgDo(self, tymth, tock=0.0, **opts):
        """Parse one remote message per turn without carrying shortage across requests.

        An outward onceParsator yield requests more bytes. Each HTTP request is
        complete, so discard its remainder and close that generator on a yield.
        The pinned parser has a separate receipt-shortage path that does not yield;
        this boundary does not remedy that dependency defect.
        Complete evidence still uses the shared KERIpy processors and escrows.
        """
        self.wind(tymth)
        yield tock
        frame = bytearray()
        while True:
            if not frame and self.msgs:
                frame = self.msgs.popleft()
            if frame:
                parser = self.parser.onceParsator(
                    ims=frame, framed=True, local=False
                )
                try:
                    try:
                        next(parser)
                    except StopIteration:
                        pass
                    else:
                        logger.warning("Discarding incomplete CESR HTTP request")
                        frame.clear()
                finally:
                    parser.close()
            yield tock

    def escrowDo(self, tymth, tock=0.0, **opts):
        """Retry the same KERI evidence escrows used by the inbound parser."""
        self.wind(tymth)
        yield tock
        while True:
            self.parser.kvy.processEscrows()
            self.parser.rvy.processEscrowReply()
            self.parser.exc.processEscrow()
            self.parser.tvy.processEscrows()
            self.parser.vry.processEscrows()
            yield tock


class CesrEnd:
    """Accept JSON/CESR-attachment POST requests and raw PUT streams at ``/``.

    Borrow the receiver's ``msgs`` deck; enqueue one bytearray per completed
    request on the service event loop. A 204 acknowledges only in-memory intake, not
    durable storage, signature verification or association acceptance. KERIpy
    parsing and escrow processing happen later. No signed webhook ACK is emitted.
    There is no SSE/query response service; unsupported methods return Falcon 405."""

    def __init__(self, msgs):
        self.msgs = msgs

    def on_post(self, req, rep):
        """Enqueue a JSON message with its CESR attachments.

        Parameters:
            req (falcon.Request): POST / with Content-Type exactly
                application/cesr+json, a JSON event/credential object as body,
                and the required CESR-ATTACHMENT header containing CESR text.
                KERIpy serialization reconstructs the body before appending
                UTF-8 attachment bytes; this is not raw JSON byte preservation.
            rep (falcon.Response): Set to 204 No Content with an empty body,
                Cache-Control: no-cache and Connection: close on intake.

        Raises:
            falcon.HTTPError: 406 for an unsupported content type; 412 for a
                missing attachment header; 400 for malformed JSON/envelopes or
                an explicit KERI qry envelope. KERIpy framing checks run first.

        Returns:
            None. A 204 is not evidence acceptance; KERIpy verification runs
            asynchronously and can reject or escrow the queued material. Incomplete
            attachments are discarded when the parser yields for missing bytes.
        """
        cr = httping.parseCesrHttpRequest(req)
        if not isinstance(cr.payload, dict):
            raise falcon.HTTPBadRequest(title="Malformed CESR envelope")
        try:
            sadder = coring.Sadder(ked=cr.payload)
            msg = bytearray(sadder.raw)
            msg.extend(cr.attachments.encode("utf-8"))
        except (kering.KeriError, ValueError, TypeError, KeyError) as error:
            raise falcon.HTTPBadRequest(title="Malformed CESR envelope") from error
        if (
            sadder.proto == kering.Protocols.keri
            and sadder.ked.get("t") == kering.Ilks.qry
        ):
            raise falcon.HTTPBadRequest(title="Queries are not supported")
        self._enqueue_request(rep, msg)

    def on_put(self, req, rep):
        """Enqueue a CESR stream without interpreting or filtering its messages.

        Parameters:
            req (falcon.Request): PUT / whose bounded HTTP body contains CESR
                bytes, including attachments and optionally concatenated messages.
                No CESR-ATTACHMENT header or content-type check is required here.
                Empty bodies and embedded query messages are not rejected here.
            rep (falcon.Response): Set to 204 No Content with an empty body,
                Cache-Control: no-cache and Connection: close after enqueueing.

        Returns:
            None. Bytes are queued unchanged for KERIpy parsing. A 204 does not
            confirm valid framing, signatures or durable acceptance. An incomplete
            remainder is discarded on a parser shortage yield; complete preceding
            messages may already have been processed. Embedded
            queries receive no query result or SSE stream from this endpoint.
        """
        self._enqueue_request(rep, req.bounded_stream.read())

    def _enqueue_request(self, rep, msg):
        self.msgs.append(bytearray(msg))
        rep.set_header("Cache-Control", "no-cache")
        rep.set_header("connection", "close")
        rep.status = falcon.HTTP_204
