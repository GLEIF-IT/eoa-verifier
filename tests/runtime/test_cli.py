"""runtime/test_cli.py."""

import pytest

from eoa_verifier.runtime.cli import main


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
    from eoa_verifier.persistence.records import PendingVerification

    with dbing.openLMDB(
        cls=VerifierBaser, name="operator", headDirPath=str(tmp_path), temp=False
    ) as baser:
        baser.enqueue(PendingVerification("candidate", "grant"))
        work = baser.next_verification(now=0)
        baser.defer_verification(
            work, reason="RPC unavailable", next_attempt_at=5, max_attempts=1
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
