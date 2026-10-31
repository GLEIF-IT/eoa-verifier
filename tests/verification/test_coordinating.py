"""verification/test_coordinating.py."""

from unittest.mock import patch

from hio.base import tyming
from keri.db import dbing

from eoa_verifier.persistence.basing import VerifierBaser
from eoa_verifier.persistence.records import PendingVerification, VerificationResult
from eoa_verifier.receiving.grants import GrantNotificationDoer
from eoa_verifier.verification.constants import ASSOCIATION_SCHEMA
from eoa_verifier.verification.coordinating import VerificationCoordinator
from eoa_verifier.verification.errors import MissingCredentialArtifactsError
from eoa_verifier.verification.worker import EoaVerifierDoer
from tests.support.issuers import candidate, signed_notice
from tests.support.services import entered_service


def test_pending_scan_excludes_results_and_bounds_pages():
    """Completed history never participates in pending scans; pages see intervening writes."""
    with dbing.openLMDB(cls=VerifierBaser) as baser:
        for i in range(65):
            baser.enqueue(PendingVerification(f"done-{i}", "first"))
            baser.finish(VerificationResult(f"done-{i}", "verified"))
            baser.enqueue(PendingVerification(f"{i:03}", "first"))
        page = baser.pending_batch(limit=32)
        assert len(page) == 32
        baser.enqueue(PendingVerification("065", "first"))
        page = baser.pending_batch(after=page[-1].associationSaid, limit=32)
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
        coordinator = VerificationCoordinator(
            baser=baser,
            rgy=None,
            trusted_geda_aid="",
            association_schema=ASSOCIATION_SCHEMA,
            eoa_verifier=worker,
        )
        coordinator.wind(clock.tymen())
        coordinator.inflight = "busy"
        with patch.object(baser, "pending_batch", side_effect=AssertionError):
            coordinator.process_ready()
        coordinator.inflight = None
        # Simulate missing KERI evidence only; use actual work storage and clock.
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
        coordinator = VerificationCoordinator(
            baser=baser,
            rgy=None,
            trusted_geda_aid="",
            association_schema=ASSOCIATION_SCHEMA,
            eoa_verifier=worker,
        )
        coordinator.wind(tyming.Tymist().tymen())
        coordinator.inflight = "a"
        worker.cues.append({"kin": "retry", "said": "a", "error": "RPC unavailable"})
        coordinator.process_results()
        assert baser.pending.get(keys=("a",)).reason == "RPC unavailable"
        assert baser.results.get(keys=("a",)) is None
        coordinator.inflight = "a"
        observation = {"wallet": "wallet", "accountObservation": {"chainId": 31337}}
        worker.cues.append({"kin": "verified", "said": "a", "eoaResult": observation})
        with patch("eoa_verifier.verification.coordinating.verify_association"):
            coordinator.process_results()
        assert baser.pending.get(keys=("a",)) is None
        assert baser.results.get(keys=("a",)).eoaResult == observation


def test_wrong_schema_is_coordinator_rejection_without_keripy_acceptance(config):
    """A real signed Grant supplies rejection evidence, never KERIpy credential acceptance."""
    from keri.app import habbing
    from keri.core import serdering

    from eoa_verifier.verification.constants import LE_SCHEMA
    from eoa_verifier.verification.coordinating import VerificationCoordinator

    with (
        entered_service(config) as runtime,
        habbing.openHby(name="sender", temp=True) as hby,
    ):
        grants = next(d for d in runtime.doers if isinstance(d, GrantNotificationDoer))
        coordinator = next(
            d for d in runtime.doers if isinstance(d, VerificationCoordinator)
        )
        sad = candidate()
        sad["s"] = LE_SCHEMA
        creder = serdering.SerderACDC(sad=sad, makify=True)
        sender = hby.makeHab(name="sender")
        grant_said = signed_notice(runtime, grants, sender, creder.sad)
        attrs = {"d": grant_said}
        grants.process_grant_notice(attrs)
        pending = runtime.baser.pending.get(keys=(creder.said,))
        assert pending is not None
        assert runtime.baser.results.get(keys=(creder.said,)) is None
        assert runtime.rgy.reger.creds.get(keys=(creder.said,)) is None
        assert runtime.rgy.reger.saved.get(keys=(creder.said,)) is None
        grants.process_grant_notice(attrs)
        assert runtime.baser.pending.get(keys=(creder.said,)) == pending
        coordinator.process_ready()
        result = runtime.baser.results.get(keys=(creder.said,))
        assert result.status == "rejected"
        assert "unexpected schema" in result.reason
        assert runtime.baser.pending.get(keys=(creder.said,)) is None
        grants.process_grant_notice(attrs)
        assert runtime.baser.results.get(keys=(creder.said,)) == result
        assert runtime.baser.pending.get(keys=(creder.said,)) is None
