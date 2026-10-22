"""Persist initial verification progress independently of native evidence."""

from dataclasses import dataclass

from keri.db import dbing, koming

STATE_AWAITING_ARTIFACTS = "awaiting_artifacts"
STATE_VERIFYING = "verifying"
STATE_VERIFIED = "verified"
STATE_FAILED = "failed"


@dataclass
class VerificationWork:
    associationSaid: str
    state: str = STATE_VERIFYING
    grantSaid: str = ""
    failureReason: str = ""


class VerifierBaser(dbing.LMDBer):
    TailDirPath = "eoa-verifier/db"
    AltTailDirPath = ".eoa-verifier/db"
    TempPrefix = "eoa_verifier_db_"

    def reopen(self, **kwa):
        super().reopen(**kwa)
        self.verifications = koming.Komer(
            db=self, subkey="verification.", schema=VerificationWork
        )
        return self.env

    def get_verification(self, said):
        return self.verifications.get(keys=(said,))

    def pin_verification(self, work):
        self.verifications.pin(keys=(work.associationSaid,), val=work)
        return work

    def start_verification(self, *, association_said, grant_said):
        # Repeated Grants never reset completed, failed or pending work.
        existing = self.get_verification(association_said)
        return (
            existing
            if existing is not None
            else self.pin_verification(
                VerificationWork(associationSaid=association_said, grantSaid=grant_said)
            )
        )

    def complete_verification(self, work):
        current = self.get_verification(work.associationSaid)
        if current is None or current.state != STATE_VERIFYING:
            raise ValueError("only unfinished verification can complete")
        current.state, current.failureReason = STATE_VERIFIED, ""
        self.pin_verification(current)

    def mark_awaiting_artifacts(self, work, reason):
        if work.state != STATE_AWAITING_ARTIFACTS or work.failureReason != reason:
            work.state, work.failureReason = STATE_AWAITING_ARTIFACTS, reason
            self.pin_verification(work)
        return work

    def mark_failed(self, work, reason):
        work.state, work.failureReason = STATE_FAILED, reason
        return self.pin_verification(work)

    def verification_by_state(self, *states):
        for _, work in self.verifications.getItemIter():
            if work.state in states:
                yield work
