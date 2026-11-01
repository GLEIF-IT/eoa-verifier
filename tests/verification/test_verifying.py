"""Verification service phase policy, budgets and preconditions."""

import pytest
from keri.db import dbing

from eoa_verifier.persistence.associations import AssociationReader
from eoa_verifier.persistence.basing import VerifierBaser
from eoa_verifier.persistence.records import VerificationRecord, VerificationResult
from eoa_verifier.persistence.verification import VerificationReader
from tests.support.persistence import enqueue_verification
from tests.support.services import verification_service


def test_active_waiting_budget_and_manual_retry_survive_restart(tmp_path):
    """Restart neither loses a dispatch nor resets its cooldown/attempt budget."""
    with dbing.openLMDB(
        cls=VerifierBaser, name="phases", headDirPath=str(tmp_path), temp=False
    ) as baser:
        enqueue_verification(baser, VerificationRecord("a", "first"))
        verificationService = verification_service(baser, clock=lambda: 100)
        verification = verificationService.start_pending(
            verificationService.next_pending()
        )
        assert verification.attempts == 1 and baser.pending.cntAll() == 0
        baser.close()
        baser.reopen()
        verification = verificationService.resume_verifying(
            verificationService.next_verifying()
        )
        assert verification.attempts == 2  # Interrupted dispatch consumes an attempt.
        verification_service(baser).defer_verification(
            verification, reason="RPC unavailable", next_attempt_at=105
        )
        assert not enqueue_verification(baser, VerificationRecord("a", "duplicate"))
        baser.close()
        baser.reopen()
        verificationService.clock = lambda: 104
        assert verificationService.next_waiting() is None
        verificationService.clock = lambda: 105
        verification = verificationService.retry_waiting(
            verificationService.next_waiting()
        )
        assert verification.attempts == 3 and verification.grantSaid == "first"
        verification_service(baser).defer_verification(
            verification, reason="RPC unavailable", next_attempt_at=110
        )
        assert VerificationReader(baser).progress("a")[0] == "dead-letter"
        assert verificationService.next_verifying() is None
        assert verificationService.next_waiting() is None
        assert verificationService.next_pending() is None
        assert not enqueue_verification(baser, VerificationRecord("a", "duplicate"))
        verification_service(baser).retry("a")
        verificationService.clock = lambda: 1000
        verification = verificationService.start_pending(
            verificationService.next_pending()
        )
        assert verification.attempts == 1
        verification_service(baser).finish(
            VerificationResult("a", "rejected", "bad proof")
        )
        assert verificationService.next_verifying() is None
        assert verificationService.next_waiting() is None
        assert verificationService.next_pending() is None
        assert not enqueue_verification(baser, VerificationRecord("a", "duplicate"))


def test_completion_requires_an_active_attempt():
    """Ready work cannot skip its durable claim, including through direct callers."""
    import pytest

    with dbing.openLMDB(cls=VerifierBaser) as baser:
        enqueue_verification(baser, VerificationRecord("a", "grant"))
        with pytest.raises(ValueError, match="active verification"):
            verification_service(baser).finish(VerificationResult("a", "verified"))
        assert baser.pending.get(keys=("a",)) is not None
        assert baser.results.cntAll() == 0


def test_pending_rejects_nonfresh_work_without_moving_it():
    """New/manual-retry pending work is fresh; malformed state is not a retry phase."""
    with dbing.openLMDB(cls=VerifierBaser) as baser:
        record = VerificationRecord("bad", "grant", attempts=3)
        baser.pending.put(keys=("bad",), val=record)
        with pytest.raises(ValueError, match="fresh attempt"):
            verification_service(baser).start_pending(record)
        assert baser.pending.get(keys=("bad",)) == record
        assert baser.verification_dead.get(keys=("bad",)) is None


def test_duplicates_completion_and_restart(tmp_path):
    """Retain first Grants, results and waiting information across reopen."""
    baser = VerifierBaser(name="work", headDirPath=str(tmp_path), temp=False)
    try:
        verification = VerificationRecord("a", "first")
        assert enqueue_verification(baser, verification)
        verificationService = verification_service(baser)
        verification = verificationService.start_pending(
            verificationService.next_pending()
        )
        verification_service(baser).defer_verification(
            verification, reason="missing source", next_attempt_at=5
        )
        assert not enqueue_verification(baser, VerificationRecord("a", "duplicate"))
        enqueue_verification(baser, VerificationRecord("b", "first"))
        result = VerificationResult(
            "b",
            "verified",
            eoaResult={"wallet": "wallet", "accountObservation": {"chainId": 31337}},
        )
        verificationService = verification_service(baser)
        verificationService.start_pending(verificationService.next_pending())
        verification_service(baser).finish(result)
        verification_service(baser).finish(result)
        with pytest.raises(ValueError, match="conflicting"):
            verification_service(baser).finish(
                VerificationResult("b", "rejected", "wrong")
            )
        assert not enqueue_verification(baser, VerificationRecord("b", "duplicate"))
        baser.close()
        baser.reopen()
        assert baser.waiting.get(keys=("a",)) == VerificationRecord(
            "a", "first", "missing source", 1, 5
        )
        assert baser.pending.get(keys=("b",)) is None
        assert baser.results.get(keys=("b",)) == result
        assert AssociationReader(baser).acceptance() == result
    finally:
        baser.close()
