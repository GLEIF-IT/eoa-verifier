"""Bounded scheduling over real persisted work, with controlled native outcomes."""

from unittest.mock import patch

from hio.base import tyming
from keri.db import dbing

from eoa_verifier.basing import VerifierBaser, PendingVerification, VerificationResult
from eoa_verifier.verification.coordinating import PresentationVerifierDoer
from eoa_verifier.verification.errors import MissingCredentialArtifactsError
from eoa_verifier.verification.worker import EoaVerifierDoer


def test_pending_scan_excludes_results_and_bounds_pages():
    """Completed history never participates in pending scans; pages see intervening writes."""
    with dbing.openLMDB(cls=VerifierBaser) as baser:
        for i in range(65):
            baser.enqueue(PendingVerification(f"done-{i}", "first"))
            baser.finish(VerificationResult(f"done-{i}", "verified"))
            baser.enqueue(PendingVerification(f"{i:03}", "first"))
        page = baser.pending_batch()
        assert len(page) == 32
        baser.enqueue(PendingVerification("065", "first"))
        page = baser.pending_batch(after=page[-1].associationSaid)
        assert len(page) == 32 and page[-1].associationSaid == "063"
        assert [w.associationSaid for w in baser.pending_batch(after="063")] == [
            "064",
            "065",
        ]
        assert baser.pending_batch(after="065") == []


def test_busy_worker_skips_scan_and_missing_artifacts_wait_fairly():
    """Use a controlled HIO clock and simulated missing evidence to check busy, fairness and cooldown rules."""
    with dbing.openLMDB(cls=VerifierBaser) as baser:
        for said in ("a", "b"):
            baser.enqueue(PendingVerification(said, ""))
        clock = tyming.Tymist()
        worker = EoaVerifierDoer(rpc_url="http://unused", chain_id=31337)
        coordinator = PresentationVerifierDoer(
            baser=baser, rgy=None, trusted_geda_aid="", eoa_verifier=worker
        )
        coordinator.wind(clock.tymen())
        coordinator.inflight = "busy"
        with patch.object(baser, "pending_batch", side_effect=AssertionError):
            coordinator.process_ready()
        coordinator.inflight = None
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
            assert baser.pending.get(keys=("a",)).reason == "missing"


def test_rpc_retry_and_success_move_only_on_completion():
    """A temporary RPC failure remains pending; a successful cue persists its observation."""
    with dbing.openLMDB(cls=VerifierBaser) as baser:
        baser.enqueue(PendingVerification("a", "first"))
        worker = EoaVerifierDoer(rpc_url="http://unused", chain_id=31337)
        coordinator = PresentationVerifierDoer(
            baser=baser, rgy=None, trusted_geda_aid="", eoa_verifier=worker
        )
        coordinator.wind(tyming.Tymist().tymen())
        coordinator.inflight = "a"
        worker.cues.append({"kin": "retry", "said": "a", "error": "RPC unavailable"})
        coordinator.process_results()
        assert baser.pending.get(keys=("a",)).reason == "RPC unavailable"
        assert baser.results.get(keys=("a",)) is None
        coordinator.inflight = "a"
        observation = {"wallet": "wallet", "observation": {"chainId": 31337}}
        worker.cues.append({"kin": "verified", "said": "a", "verified": observation})
        with patch("eoa_verifier.verification.coordinating.verify_association"):
            coordinator.process_results()
        assert baser.pending.get(keys=("a",)) is None
        assert baser.results.get(keys=("a",)).verified == observation
