"""Coordinator scheduling, dispatch and result correlation."""

from unittest.mock import patch

import pytest
from hio.base import tyming
from keri.db import dbing

from eoa_verifier.persistence.associations import AssociationReader
from eoa_verifier.persistence.basing import VerifierBaser
from eoa_verifier.persistence.records import VerificationRecord
from eoa_verifier.persistence.verification import VerificationReader, VerificationWriter
from eoa_verifier.verification.constants import ASSOCIATION_SCHEMA
from eoa_verifier.verification.coordinating import VerificationCoordinator
from eoa_verifier.verification.errors import MissingCredentialArtifactsError
from eoa_verifier.verification.worker import WalletCheckDoer
from tests.support.issuers import candidate, signed_notice
from tests.support.persistence import enqueue_verification
from tests.support.services import entered_service, verification_service


def test_busy_worker_and_waiting_do_not_schedule_other_active_work():
    """A single in-flight check and persistent waiting allow fresh evidence its turn."""
    with dbing.openLMDB(cls=VerifierBaser) as baser:
        for said in ("a", "b"):
            enqueue_verification(baser, VerificationRecord(said, ""))
        clock = tyming.Tymist()
        worker = WalletCheckDoer(rpc_url="http://unused", chain_id=31337)
        coordinator = VerificationCoordinator(
            service=verification_service(
                baser, association_schema=ASSOCIATION_SCHEMA, clock=lambda: clock.tyme
            ),
            wallet_doer=worker,
        )
        coordinator.activeCredSaid = "busy"
        with patch.object(
            coordinator.service, "next_verifying", side_effect=AssertionError
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
        enqueue_verification(baser, VerificationRecord("a", "first"))
        verificationService = verification_service(baser)
        verificationService.start_pending(verificationService.next_pending())
        worker = WalletCheckDoer(rpc_url="http://unused", chain_id=31337)
        coordinator = VerificationCoordinator(
            service=verification_service(
                baser, association_schema=ASSOCIATION_SCHEMA, clock=lambda: 0
            ),
            wallet_doer=worker,
        )
        coordinator.activeCredSaid = "a"
        worker.cues.append({"kin": "retry", "said": "a", "error": "RPC unavailable"})
        coordinator.process_results()
        assert baser.waiting.get(keys=("a",)).reason == "RPC unavailable"
        assert baser.verifying.cntAll() == 0 and baser.results.cntAll() == 0
        verificationService.clock = lambda: 5
        verificationService.retry_waiting(verificationService.next_waiting())
        coordinator.activeCredSaid = "a"
        observation = {"wallet": "wallet", "accountObservation": {"chainId": 31337}}
        worker.cues.append({"kin": "verified", "said": "a", "eoaResult": observation})
        with (
            patch.object(coordinator.service.evidence, "grant_candidate"),
            patch("eoa_verifier.verification.verifying.verify_association"),
        ):
            coordinator.process_results()
        assert VerificationReader(baser).progress("a") == (None, None)
        assert baser.results.get(keys=("a",)).eoaResult == observation
        assert AssociationReader(baser).acceptance().associationSaid == "a"


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
        coordinator = next(
            d for d in runtime.doers if isinstance(d, VerificationCoordinator)
        )
        sad = candidate()
        sad["s"] = LE_SCHEMA
        creder = serdering.SerderACDC(sad=sad, makify=True)
        sender = hby.makeHab(name="sender")
        grant_said = signed_notice(runtime, sender, creder.sad)
        attrs = {"d": grant_said}
        runtime.notifier.add({"r": "/exn/ipex/grant", **attrs})
        runtime.grant_replay.process_one()
        pending = runtime.baser.pending.get(keys=(creder.said,))
        assert pending is not None
        assert runtime.baser.results.get(keys=(creder.said,)) is None
        assert runtime.rgy.reger.creds.get(keys=(creder.said,)) is None
        assert runtime.rgy.reger.saved.get(keys=(creder.said,)) is None
        runtime.notifier.add({"r": "/exn/ipex/grant", **attrs})
        runtime.grant_replay.process_one()
        assert runtime.baser.pending.get(keys=(creder.said,)) == pending
        coordinator.process_ready()
        result = runtime.baser.results.get(keys=(creder.said,))
        assert result.status == "rejected"
        assert "unexpected schema" in result.reason
        assert runtime.baser.pending.get(keys=(creder.said,)) is None
        runtime.notifier.add({"r": "/exn/ipex/grant", **attrs})
        runtime.grant_replay.process_one()
        assert runtime.baser.results.get(keys=(creder.said,)) == result
        assert runtime.baser.pending.get(keys=(creder.said,)) is None


@pytest.mark.parametrize("phase", ["verifying", "waiting"])
@pytest.mark.parametrize("budget", [2, 3])
def test_exhausted_phase_consumes_only_one_scheduler_turn(phase, budget):
    """Dead-lettering one exhausted item must not charge the next queued item."""
    with dbing.openLMDB(cls=VerifierBaser) as baser:
        writer = VerificationWriter(baser)
        exhausted = VerificationRecord("a", "first", attempts=3)
        other = VerificationRecord("b", "second")
        enqueue_verification(baser, exhausted)
        enqueue_verification(baser, other)
        if phase == "verifying":
            writer.pending_to_verifying(exhausted, exhausted)
        elif phase == "waiting":
            writer.pending_to_verifying(exhausted, exhausted)
            writer.verifying_to_waiting(exhausted, exhausted)
        service = verification_service(baser, clock=lambda: 10, max_attempts=budget)
        # Reads do not charge attempts or consume a phase, even when all are queried.
        assert service.next_verifying() == (exhausted if phase == "verifying" else None)
        assert service.next_waiting() == (exhausted if phase == "waiting" else None)
        assert service.next_pending() == other
        assert getattr(baser, phase).get(keys=("a",)) == exhausted
        worker = WalletCheckDoer(rpc_url="http://unused", chain_id=31337)
        coordinator = VerificationCoordinator(service=service, wallet_doer=worker)
        coordinator.process_ready()
        assert baser.verification_dead.get(keys=("a",)).attempts == 3
        assert baser.pending.get(keys=("b",)) == other
        assert not worker.msgs
