"""HIO dispatch and cue correlation for the durable verification service."""

from hio.base import doing


class VerificationCoordinator(doing.DoDoer):
    """Schedule one asynchronous EOA check; the service owns durable progression."""

    def __init__(self, *, service, eoa_verifier, **kwa):
        """Borrow the application service and own the EOA worker's scheduler lifetime."""
        self.service, self.eoa_verifier = service, eoa_verifier
        self.activeCredSaid = None
        super().__init__(doers=[eoa_verifier, doing.doify(self.verify_do)], **kwa)

    def verify_do(self, tymth, tock=0.0, **opts):
        """Apply one response or begin one attempt per scheduler turn."""
        yield tock
        while True:
            if not self.process_results():
                self.process_ready()
            yield self.tock

    def process_results(self):
        """Discard unrelated cues; pass the one dispatched result to its service."""
        if not self.eoa_verifier.cues:
            return
        cue = self.eoa_verifier.cues.popleft()
        if cue["said"] != self.activeCredSaid:
            return
        self.service.apply_cue(cue)
        self.activeCredSaid = None
        return True

    def process_ready(self):
        """Dispatch prepared work only while no observation is in flight."""
        if self.activeCredSaid is not None:
            return
        # Select one phase explicitly. An exhausted record still consumes this turn.
        if (record := self.service.next_verifying()) is not None:
            verification = self.service.resume_verifying(record)
        elif (record := self.service.next_waiting()) is not None:
            verification = self.service.retry_waiting(record)
        elif (record := self.service.next_pending()) is not None:
            verification = self.service.start_pending(record)
        else:
            return
        if verification is None:
            return
        association = self.service.prepare(verification)
        if association is not None:
            self.activeCredSaid = association.said
            self.eoa_verifier.msgs.append(association.sad)
