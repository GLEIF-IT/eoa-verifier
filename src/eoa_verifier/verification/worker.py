"""HIO request/cue flow for EOA proof and account verification."""

from hio.base import doing
from hio.help import decking

from .checking import EoaVerificationService
from .observing import AccountObserver


class EoaVerifierDoer(doing.DoDoer):
    """Own initial wallet verification and one sequential account observation at a time.

    msgs contains schema-validated association ACDC dictionaries, including d, i,
    u, a.extId, a.proof and e.le.n. cues contains ordinary dictionaries:
    - {kin: "verified", said, eoaResult: {wallet, accountObservation}};
    - {kin: "failed", said, error} for an invalid wallet proof or account;
    - {kin: "retry", said, error} for unavailable or unusable RPC responses.

    accountObservation contains chainId and blockNumber integers, blockHash and code hex
    strings, and observedAt ISO timestamp. The coordinator persists successful
    observations with completed results; this worker owns no application storage. Programming errors
    propagate instead of becoming retry cues. Each HTTP ClientDoer is a child whose
    lifetime ends on completion, failure or cancellation.
    """

    def __init__(self, *, rpc_url, chain_id, timeout=5.0, **kwa):
        """Configure the trusted rpc_url, expected chain_id and per-call timeout in seconds.

        msgs and cues are transient HIO decks; the coordinator persists work status
        instead of these queues. kwa supplies HIO DoDoer options such as scheduling tock.
        """
        self.service = EoaVerificationService(
            AccountObserver(self, rpc_url=rpc_url, chain_id=chain_id, timeout=timeout),
            chain_id,
        )
        self.msgs = decking.Deck()
        self.cues = decking.Deck()
        super().__init__(doers=[doing.doify(self.verify_do)], **kwa)

    def verify_do(self, tymth, tock=0.0, **opts):
        """Yield on the HIO clock while idle; process messages sequentially and append cues.

        This long-lived generator has no result of its own. Cancellation unwinds any
        active observation through its child-client cleanup.
        """
        yield tock
        while True:
            if not self.msgs:
                yield self.tock
                continue
            cue = yield from self.service.verify(self.msgs.popleft())
            self.cues.append(cue)
