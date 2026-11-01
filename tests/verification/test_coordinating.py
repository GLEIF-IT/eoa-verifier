"""verification/test_coordinating.py."""

from unittest.mock import patch

from hio.base import tyming
from keri.db import dbing

from eoa_verifier.persistence.basing import VerifierBaser
from eoa_verifier.persistence.reading import ApplicationReader
from eoa_verifier.persistence.records import VerificationRecord, VerificationResult
from eoa_verifier.persistence.writing import ApplicationWriter
from eoa_verifier.receiving.grants import GrantNotificationDoer
from eoa_verifier.verification.constants import ASSOCIATION_SCHEMA
from eoa_verifier.verification.coordinating import VerificationCoordinator
from eoa_verifier.verification.errors import MissingCredentialArtifactsError
from eoa_verifier.verification.worker import EoaVerifierDoer
from tests.support.issuers import candidate, signed_notice
from tests.support.services import entered_service, verification_service


def test_active_waiting_budget_and_manual_retry_survive_restart(tmp_path):
    """Restart neither loses a dispatch nor resets its cooldown/attempt budget."""
    with dbing.openLMDB(
        cls=VerifierBaser, name="phases", headDirPath=str(tmp_path), temp=False
    ) as baser:
        ApplicationWriter(baser).enqueue_verification(VerificationRecord("a", "first"))
        verification = verification_service(baser).next_verification(now=100)
        assert verification.attempts == 1 and baser.pending.cntAll() == 0
        baser.close()
        baser.reopen()
        verification = verification_service(baser).next_verification(now=100)
        assert verification.attempts == 2  # Interrupted dispatch consumes an attempt.
        verification_service(baser).defer_verification(
            verification, reason="RPC unavailable", next_attempt_at=105
        )
        assert not ApplicationWriter(baser).enqueue_verification(
            VerificationRecord("a", "duplicate")
        )
        baser.close()
        baser.reopen()
        assert verification_service(baser).next_verification(now=104) is None
        verification = verification_service(baser).next_verification(now=105)
        assert verification.attempts == 3 and verification.grantSaid == "first"
        verification_service(baser).defer_verification(
            verification, reason="RPC unavailable", next_attempt_at=110
        )
        assert ApplicationReader(baser).verification_progress("a")[0] == "dead-letter"
        assert verification_service(baser).next_verification(now=1000) is None
        assert not ApplicationWriter(baser).enqueue_verification(
            VerificationRecord("a", "duplicate")
        )
        verification_service(baser).retry("a")
        verification = verification_service(baser).next_verification(now=1000)
        assert verification.attempts == 1
        verification_service(baser).finish(
            VerificationResult("a", "rejected", "bad proof")
        )
        assert verification_service(baser).next_verification(now=1001) is None
        assert not ApplicationWriter(baser).enqueue_verification(
            VerificationRecord("a", "duplicate")
        )


def test_busy_worker_and_waiting_do_not_schedule_other_active_work():
    """A single in-flight check and persistent waiting allow fresh evidence its turn."""
    with dbing.openLMDB(cls=VerifierBaser) as baser:
        for said in ("a", "b"):
            ApplicationWriter(baser).enqueue_verification(VerificationRecord(said, ""))
        clock = tyming.Tymist()
        worker = EoaVerifierDoer(rpc_url="http://unused", chain_id=31337)
        coordinator = VerificationCoordinator(
            service=verification_service(
                baser, association_schema=ASSOCIATION_SCHEMA, clock=lambda: clock.tyme
            ),
            eoa_verifier=worker,
        )
        coordinator.activeCredSaid = "busy"
        with patch.object(
            coordinator.service, "next_verification", side_effect=AssertionError
        ):
            coordinator.process_ready()
        coordinator.activeCredSaid = None
        with (
            patch.object(coordinator.service.evidence, "grant_candidate"),
            patch(
                "eoa_verifier.verification.verifying.verify_association",
                side_effect=MissingCredentialArtifactsError("missing"),
            ) as verify,
        ):
            coordinator.process_ready()
            assert verify.call_count == 1
            coordinator.process_ready()
            assert verify.call_count == 2
            for _ in range(5):
                coordinator.process_ready()
            assert verify.call_count == 2
            clock.tick(coordinator.service.retry_delay)
            coordinator.process_ready()
            assert verify.call_count == 3
            coordinator.process_ready()
            assert verify.call_count == 4
            assert baser.waiting.get(keys=("a",)).reason == "missing"


def test_rpc_retry_and_success_move_only_on_completion():
    """Cues move active work to waiting or acceptance; completed history is inert."""
    with dbing.openLMDB(cls=VerifierBaser) as baser:
        ApplicationWriter(baser).enqueue_verification(VerificationRecord("a", "first"))
        verification_service(baser).next_verification(now=0)
        worker = EoaVerifierDoer(rpc_url="http://unused", chain_id=31337)
        coordinator = VerificationCoordinator(
            service=verification_service(
                baser, association_schema=ASSOCIATION_SCHEMA, clock=lambda: 0
            ),
            eoa_verifier=worker,
        )
        coordinator.activeCredSaid = "a"
        worker.cues.append({"kin": "retry", "said": "a", "error": "RPC unavailable"})
        coordinator.process_results()
        assert baser.waiting.get(keys=("a",)).reason == "RPC unavailable"
        assert baser.verifying.cntAll() == 0 and baser.results.cntAll() == 0
        verification_service(baser).next_verification(now=5)
        coordinator.activeCredSaid = "a"
        observation = {"wallet": "wallet", "accountObservation": {"chainId": 31337}}
        worker.cues.append({"kin": "verified", "said": "a", "eoaResult": observation})
        with (
            patch.object(coordinator.service.evidence, "grant_candidate"),
            patch("eoa_verifier.verification.verifying.verify_association"),
        ):
            coordinator.process_results()
        assert ApplicationReader(baser).verification_progress("a") == (None, None)
        assert baser.results.get(keys=("a",)).eoaResult == observation
        assert ApplicationReader(baser).acceptance().associationSaid == "a"


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
        grants.service.native.notifier.add({"r": "/exn/ipex/grant", **attrs})
        grants.service.process_one()
        pending = runtime.baser.pending.get(keys=(creder.said,))
        assert pending is not None
        assert runtime.baser.results.get(keys=(creder.said,)) is None
        assert runtime.rgy.reger.creds.get(keys=(creder.said,)) is None
        assert runtime.rgy.reger.saved.get(keys=(creder.said,)) is None
        grants.service.native.notifier.add({"r": "/exn/ipex/grant", **attrs})
        grants.service.process_one()
        assert runtime.baser.pending.get(keys=(creder.said,)) == pending
        coordinator.process_ready()
        result = runtime.baser.results.get(keys=(creder.said,))
        assert result.status == "rejected"
        assert "unexpected schema" in result.reason
        assert runtime.baser.pending.get(keys=(creder.said,)) is None
        grants.service.native.notifier.add({"r": "/exn/ipex/grant", **attrs})
        grants.service.process_one()
        assert runtime.baser.results.get(keys=(creder.said,)) == result
        assert runtime.baser.pending.get(keys=(creder.said,)) is None


def test_completion_requires_an_active_attempt():
    """Ready work cannot skip its durable claim, including through direct callers."""
    import pytest

    with dbing.openLMDB(cls=VerifierBaser) as baser:
        ApplicationWriter(baser).enqueue_verification(VerificationRecord("a", "grant"))
        with pytest.raises(ValueError, match="active verification"):
            verification_service(baser).finish(VerificationResult("a", "verified"))
        assert baser.pending.get(keys=("a",)) is not None
        assert baser.results.cntAll() == 0
