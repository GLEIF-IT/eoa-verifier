"""Resource lifetime, store reopening and the standalone CLI boundary."""

from unittest.mock import patch

import pytest
from falcon.testing import TestClient
from keri.app import indirecting

from eoa_verifier.cli import main
from eoa_verifier.serving import run_service, setup_service


def test_identity_progress_and_terminal_duplicates_survive_reopen(config):
    runtime = setup_service(config)
    aid = runtime.hab.pre
    try:
        directors = [
            d for d in runtime.doers if isinstance(d, indirecting.MailboxDirector)
        ]
        assert len(directors) == 1
        assert TestClient(runtime.app).simulate_get("/health").json == {"ok": True}
        for state in ("verifying", "awaiting_artifacts", "failed", "verified"):
            work = runtime.baser.start_verification(
                association_said=state, grant_said="first"
            )
            if state == "verified":
                runtime.baser.complete_verification(work)
            else:
                getattr(runtime.baser, f"mark_{state}")(work, "retained")
    finally:
        runtime.close()
    runtime = setup_service(config)
    try:
        assert runtime.hab.pre == aid
        for state in ("verifying", "awaiting_artifacts", "failed", "verified"):
            work = runtime.baser.start_verification(
                association_said=state, grant_said="duplicate"
            )
            assert (work.state, work.grantSaid, work.failureReason) == (
                state,
                "first",
                "" if state == "verified" else "retained",
            )
    finally:
        runtime.close()


def test_setup_failure_releases_all_previously_opened_stores(config):
    with (
        patch(
            "eoa_verifier.serving.oobiing.Oobiery",
            side_effect=RuntimeError("setup failure"),
        ),
        pytest.raises(RuntimeError, match="setup failure"),
    ):
        setup_service(config)
    # A leaked LMDB handle makes this reopen fail in the same process.
    runtime = setup_service(config)
    runtime.close()


def test_run_unwinds_on_scheduler_failure(config):
    with (
        patch(
            "eoa_verifier.serving.doing.Doist.do",
            side_effect=RuntimeError("scheduler failure"),
        ),
        pytest.raises(RuntimeError, match="scheduler failure"),
    ):
        run_service(config)
    runtime = setup_service(config)
    runtime.close()


def test_cli_has_no_posting_options_and_requires_network(capsys):
    with pytest.raises(SystemExit) as caught:
        main(["server", "start", "--help"])
    assert caught.value.code == 0
    help_text = capsys.readouterr().out
    assert "--chain-id" in help_text and "--rpc-url" in help_text
    assert "posting" not in help_text and "registry" not in help_text


def test_failed_work_cannot_complete(config):
    runtime = setup_service(config)
    try:
        work = runtime.baser.start_verification(
            association_said="test", grant_said="grant"
        )
        runtime.baser.mark_failed(work, "invalid")
        with pytest.raises(ValueError, match="unfinished"):
            runtime.baser.complete_verification(work)
    finally:
        runtime.close()


def test_forged_said_cannot_create_verification_work(config):
    from types import SimpleNamespace

    from native_helpers import candidate

    from eoa_verifier.receiving.grants import GrantNotificationDoer, InvalidGrantError

    association = candidate()
    association["u"] = "tampered after SAID computation"
    runtime = setup_service(config)
    try:
        grants = next(d for d in runtime.doers if isinstance(d, GrantNotificationDoer))
        # Stub envelope lookup only; the production native ACDC validator must
        # reject the claimed identity before parsing or writing any work.
        with (
            patch(
                "eoa_verifier.receiving.grants.exchanging.cloneMessage",
                return_value=(SimpleNamespace(ked={"e": {"acdc": association}}), {}),
            ),
            pytest.raises(InvalidGrantError),
        ):
            grants.process_grant_notice({"d": "grant"})
        assert runtime.baser.get_verification(association["d"]) is None
    finally:
        runtime.close()
