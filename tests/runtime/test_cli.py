"""Public CLI options and offline recovery against the selected persistent application store."""

import pytest

from eoa_verifier.runtime.cli import main
from tests.support.persistence import enqueue_verification
from tests.support.services import verification_service


def test_cli_documents_network_options_and_rejects_missing_config(capsys):
    """Help lists network options; starting without required configuration exits with an error."""
    with pytest.raises(SystemExit) as caught:
        main(["server", "start", "--help"])
    assert caught.value.code == 0
    help_text = capsys.readouterr().out
    assert "--chain-id" in help_text and "--rpc-url" in help_text
    assert "--webhook-backoff-cap" in help_text
    with pytest.raises(SystemExit) as missing:
        main(["server", "start"])
    assert missing.value.code == 2


def test_retry_verification_command_uses_persistent_phase(tmp_path):
    """The operator command renews only an exhausted candidate's retry budget."""
    from keri.db import dbing

    from eoa_verifier.persistence.basing import VerifierBaser
    from eoa_verifier.persistence.records import VerificationRecord

    with dbing.openLMDB(
        cls=VerifierBaser, name="operator", headDirPath=str(tmp_path), temp=False
    ) as baser:
        enqueue_verification(baser, VerificationRecord("candidate", "grant"))
        verificationService = verification_service(baser)
        verification = verificationService.start_pending(
            verificationService.next_pending()
        )
        verification_service(baser).defer_verification(
            verification, reason="RPC unavailable", next_attempt_at=5, max_attempts=1
        )
    arguments = [
        "retry-verification",
        "candidate",
        "--name",
        "operator",
        "--head-dir",
        str(tmp_path),
    ]
    assert main(arguments) == 0
    with dbing.openLMDB(
        cls=VerifierBaser, name="operator", headDirPath=str(tmp_path), temp=False
    ) as baser:
        assert baser.verification_dead.cntAll() == 0
        assert baser.pending.get(keys=("candidate",)).attempts == 0
    assert main(arguments) == 1  # Already resumed; no second budget reset.


def test_start_passes_validated_operator_settings(config, monkeypatch):
    """Map every startup option to typed runtime input without opening service resources."""
    from dataclasses import replace

    from eoa_verifier.runtime import cli

    configs = []
    monkeypatch.setattr(cli, "run_service", configs.append)
    arguments = [
        "server",
        "start",
        "--trusted-geda-aid",
        config.trusted_geda_aid,
        "--rpc-url",
        "http://localhost:8546",
        "--chain-id",
        "5",
        "--name",
        "operator",
        "--base",
        "isolated",
        "--head-dir",
        config.head_dir,
        "--alias",
        "signer",
        "--host",
        "0.0.0.0",
        "--http-port",
        "8888",
        "--passcode",
        "fixture-only",
        "--incept-file",
        "inception.json",
        "--webhook-url",
        "https://receiver.example/hook",
        "--webhook-oobi",
        "https://receiver.example/oobi/signer",
        "--webhook-timeout",
        "12",
        "--webhook-interval",
        "2",
        "--webhook-backoff-base",
        "3",
        "--webhook-backoff-cap",
        "30",
        "--webhook-max-attempts",
        "4",
    ]
    assert main(arguments) == 0
    assert configs == [
        replace(
            config,
            rpc_url="http://localhost:8546",
            chain_id=5,
            name="operator",
            base="isolated",
            alias="signer",
            host="0.0.0.0",
            http_port=8888,
            passcode="fixture-only",
            incept_file="inception.json",
            webhook_url="https://receiver.example/hook",
            webhook_oobi="https://receiver.example/oobi/signer",
            webhook_timeout=12.0,
            webhook_interval=2.0,
            webhook_backoff_base=3.0,
            webhook_backoff_cap=30.0,
            webhook_max_attempts=4,
        )
    ]


@pytest.mark.parametrize("phase", ["delivery", "grant", "acceptance"])
def test_retry_commands_resume_only_selected_dead_letter(tmp_path, phase):
    """Use real named persistent storage; preserve unrelated dead letters and consumed nonces."""
    from keri.db import dbing

    from eoa_verifier.persistence.basing import VerifierBaser
    from eoa_verifier.persistence.records import (
        AcceptedNonce,
        Delivery,
        DeliveryReference,
        DestinationSchedule,
        GrantReplayRecord,
        VerificationResult,
    )

    options = dict(
        cls=VerifierBaser,
        name="operator",
        base="ops",
        headDirPath=str(tmp_path),
        temp=False,
    )
    delivery = Delivery(
        "credential:1",
        "credential",
        "https://receiver.example/hook",
        '{"eventId":"credential:1"}',
        attempts=3,
        blocked=True,
        error="stopped",
    )
    result = VerificationResult("candidate", "verified")
    with dbing.openLMDB(**options) as baser:
        baser.outbox.put(keys=(delivery.eventId,), val=delivery)
        baser.delivery_dead.put(
            keys=(delivery.eventId,), val=DeliveryReference(delivery.eventId)
        )
        baser.destinations.put(
            keys=(delivery.destination,), val=DestinationSchedule(2, 5000.0)
        )
        baser.grant_dead.put(
            keys=("notice",),
            val=GrantReplayRecord(
                "notice", {"d": "grant"}, attempts=3, reason="stopped"
            ),
        )
        baser.acceptance_dead.put(keys=("candidate",), val=result)
        baser.results.put(keys=("candidate",), val=result)
        baser.accepted_nonces.put(keys=("consumed",), val=AcceptedNonce("owner"))
    identifier = {
        "delivery": delivery.eventId,
        "grant": "notice",
        "acceptance": "candidate",
    }[phase]
    arguments = [
        f"retry-{phase}",
        identifier,
        "--name",
        "operator",
        "--base",
        "ops",
        "--head-dir",
        str(tmp_path),
    ]
    assert main(arguments) == 0
    with dbing.openLMDB(**options) as baser:
        assert baser.delivery_dead.cntAll() == (phase != "delivery")
        assert baser.grant_dead.cntAll() == (phase != "grant")
        assert baser.acceptance_dead.cntAll() == (phase != "acceptance")
        assert baser.results.get(keys=("candidate",)) == result
        assert baser.accepted_nonces.get(keys=("consumed",)) == AcceptedNonce("owner")
        assert baser.destinations.get(
            keys=(delivery.destination,)
        ) == DestinationSchedule(2, 5000.0)
        if phase == "delivery":
            resumedDelivery = baser.outbox.get(keys=(delivery.eventId,))
            assert (
                resumedDelivery.body == delivery.body
                and resumedDelivery.destination == delivery.destination
            )
            assert resumedDelivery.attempts == 0 and not resumedDelivery.blocked
            assert (
                baser.delivery_ready.get(keys=(delivery.eventId,)).eventId
                == delivery.eventId
            )
        elif phase == "grant":
            grantRecord = baser.grant_waiting.get(keys=("notice",))
            assert (
                grantRecord.attempts == grantRecord.nextAttemptAt == 0
                and grantRecord.reason == ""
            )
        else:
            assert baser.accepting.get(keys=("candidate",)) == result
    assert main(arguments) == 1  # A completed retry cannot silently reset work again.


def test_invalid_startup_does_not_enter_runtime(config, monkeypatch, capsys):
    """Reject bad typed configuration before the runtime can acquire stores or sockets."""
    from eoa_verifier.runtime import cli

    configs = []
    monkeypatch.setattr(cli, "run_service", configs.append)
    assert (
        main(
            [
                "server",
                "start",
                "--trusted-geda-aid",
                config.trusted_geda_aid,
                "--rpc-url",
                config.rpc_url,
                "--chain-id",
                "0",
            ]
        )
        == 1
    )
    assert configs == []
    assert "positive chain ID" in capsys.readouterr().err
