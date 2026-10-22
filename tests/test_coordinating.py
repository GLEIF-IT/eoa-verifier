"""Bounded scheduling over real persisted work, with controlled native outcomes."""

from unittest.mock import patch

from hio.base import tyming
from keri.db import dbing

from eoa_verifier.basing import VerifierBaser
from eoa_verifier.verification.coordinating import PresentationVerifierDoer
from eoa_verifier.verification.errors import MissingCredentialArtifactsError
from eoa_verifier.verification.worker import EoaVerifierDoer


def test_work_scan_is_bounded_and_resumes_after_terminal_records():
    """Page through real LMDB history, observing between-page writes and stopping at the final key."""
    with dbing.openLMDB(cls=VerifierBaser) as baser:
        for i in range(65):
            work = baser.start_verification(association_said=f"{i:03}", grant_said="")
            baser.complete_verification(work)
        page = baser.verification_batch()
        assert len(page) == 32
        # Mutations between pages must be visible; no read transaction is retained.
        work = baser.start_verification(association_said="065", grant_said="")
        baser.mark_awaiting_artifacts(work, "missing")
        page = baser.verification_batch(after=page[-1].associationSaid)
        assert len(page) == 32 and page[-1].associationSaid == "063"
        page = baser.verification_batch(after="063")
        assert [work.associationSaid for work in page] == ["064", "065"]
        assert page[-1].state == "awaiting_artifacts"
        assert baser.verification_batch(after="065") == []
        assert baser.verification_batch(after="999") == []


def test_busy_worker_skips_scan_and_missing_artifacts_wait_fairly():
    """Use a controlled HIO clock and simulated missing evidence to check busy, fairness and cooldown rules."""
    with dbing.openLMDB(cls=VerifierBaser) as baser:
        for said in ("a", "b"):
            baser.start_verification(association_said=said, grant_said="")
        clock = tyming.Tymist()
        worker = EoaVerifierDoer(rpc_url="http://unused", chain_id=31337)
        coordinator = PresentationVerifierDoer(
            baser=baser, rgy=None, trusted_geda_aid="", eoa_verifier=worker
        )
        coordinator.wind(clock.tymen())
        coordinator.pending = "busy"
        with patch.object(baser, "verification_batch", side_effect=AssertionError):
            coordinator.process_ready()
        coordinator.pending = None
        # Simulate missing native evidence only; use actual work storage and clock.
        with (
            patch("eoa_verifier.verification.coordinating.grant_candidate"),
            patch(
                "eoa_verifier.verification.coordinating.verify_association",
                side_effect=MissingCredentialArtifactsError("missing"),
            ) as verify,
        ):
            coordinator.process_ready()
            assert verify.call_count == 1
            coordinator.process_ready()
            assert verify.call_count == 2  # b gets a turn despite a still waiting.
            for _ in range(5):
                coordinator.process_ready()
            assert verify.call_count == 2
            clock.tick(coordinator.retry_delay)
            coordinator.process_ready()
            assert verify.call_count == 3
            coordinator.process_ready()
            assert verify.call_count == 4
            assert baser.get_verification("a").state == "awaiting_artifacts"
