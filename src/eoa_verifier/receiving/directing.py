"""Direct CESR intake and native parser/escrow scheduling."""

import falcon
from hio.base import doing
from keri import kering
from keri.app import httping
from keri.core import coring


class Receiver(doing.DoDoer):
    """Schedule one borrowed parser and its native escrow processors."""

    def __init__(self, parser, *, msg_tock, escrow_tock, **kwa):
        self.parser = parser
        super().__init__(
            doers=[
                doing.doify(self.msgDo, tock=msg_tock),
                doing.doify(self.escrowDo, tock=escrow_tock),
            ],
            **kwa,
        )

    def msgDo(self, tymth, tock=0.0, **opts):
        """Delegate stream parsing to KERIpy; closing this task closes its generator."""
        self.wind(tymth)
        yield tock
        parser = self.parser.parsator(local=True)
        try:
            while True:
                try:
                    next(parser)
                except StopIteration:
                    return
                yield tock
        finally:
            parser.close()

    def escrowDo(self, tymth, tock=0.0, **opts):
        """Retry the same native evidence escrows used by the inbound parser."""
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
    """Accept native CESR POST envelopes and raw PUT streams, without query service."""

    def __init__(self, rxbs):
        self.rxbs = rxbs

    def on_post(self, req, rep):
        """Decode HTTP framing only; native parsing verifies the queued evidence."""
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
        self._accept(rep, msg)

    def on_put(self, req, rep):
        """Preserve native raw-stream intake without filtering embedded messages."""
        self._accept(rep, req.bounded_stream.read())

    def _accept(self, rep, msg):
        self.rxbs.extend(msg)
        rep.set_header("Cache-Control", "no-cache")
        rep.set_header("connection", "close")
        rep.status = falcon.HTTP_204
