"""Resource lifetime, store reopening and the standalone CLI boundary."""

from contextlib import ExitStack
from unittest.mock import patch

import pytest

from eoa_verifier.cli import main
from eoa_verifier.serving import run_service
from native_helpers import running_service


def test_setup_failure_releases_all_previously_opened_stores(config):
    """Inject late setup failure; reopening the same paths detects leaked LMDB handles."""
    with (
        patch(
            "eoa_verifier.serving.oobiing.Oobiery",
            side_effect=RuntimeError("setup failure"),
        ),
        pytest.raises(RuntimeError, match="setup failure"),
    ):
        with running_service(config):
            pass
    # A leaked LMDB handle makes this reopen fail in the same process.
    with running_service(config):
        pass


def test_run_unwinds_on_scheduler_failure(config):
    """Inject scheduler entry failure and prove the service still closes its stores."""
    with (
        patch(
            "eoa_verifier.serving.doing.Doist.do",
            side_effect=RuntimeError("scheduler failure"),
        ),
        pytest.raises(RuntimeError, match="scheduler failure"),
    ):
        run_service(config)
    with running_service(config):
        pass


def test_cli_has_no_posting_options_and_requires_network(capsys):
    """Inspect argparse help for the verifier network boundary without starting a service."""
    with pytest.raises(SystemExit) as caught:
        main(["server", "start", "--help"])
    assert caught.value.code == 0
    help_text = capsys.readouterr().out
    assert "--chain-id" in help_text and "--rpc-url" in help_text
    assert "posting" not in help_text and "registry" not in help_text


def test_forged_said_cannot_create_verification_work(config):
    """Stub EXN lookup only; native ACDC decoding must reject tampering before persistence."""
    from types import SimpleNamespace

    from native_helpers import candidate

    from eoa_verifier.receiving.grants import GrantNotificationDoer, InvalidGrantError

    association = candidate()
    association["u"] = "tampered after SAID computation"
    lifetime = ExitStack()
    runtime = lifetime.enter_context(running_service(config))
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
        assert runtime.baser.pending.get(keys=(association["d"],)) is None
    finally:
        lifetime.close()


@pytest.mark.parametrize("mode", ["complete", "cancel", "exception", "partial-enter"])
def test_service_owns_children_before_stores(config, mode):
    """Every HIO exit path stops children while stores remain open and closes HTTP once."""
    from hio.base import doing
    from hio.core import http
    from unittest.mock import Mock
    from eoa_verifier.serving import VerifierService

    stopped = []

    class Child(doing.Doer):
        def exit(self):
            assert service.baser.opened and service.hby.db.opened
            stopped.append(True)

    class BrokenEntry(doing.Doer):
        def enter(self, *, temp=None):
            raise RuntimeError("entry failure")

    class Service(VerifierService):
        def _open(self):
            super()._open()
            self.server = next(
                d.server for d in self.doers if isinstance(d, http.ServerDoer)
            )
            self.server.close = Mock(wraps=self.server.close)
            self.doers.append(Child())
            if mode == "partial-enter":
                self.doers.append(BrokenEntry())

        def recur(self, tyme):
            if mode == "exception":
                raise RuntimeError("child lifetime failure")
            if mode == "complete":
                return True
            return super().recur(tyme)

    service = Service(config)
    scheduler = doing.Doist(tock=0.01, limit=0.02)
    if mode in ("exception", "partial-enter"):
        with pytest.raises(RuntimeError, match="failure"):
            scheduler.do(doers=[service])
    else:
        scheduler.do(doers=[service])
    assert stopped == [True]
    assert not service.baser.opened and not service.hby.db.opened
    assert not service.server.servant.opened
    assert service.server.close.call_count == 1
    with running_service(config) as reopened:
        assert reopened.hab.pre == service.hab.pre


@pytest.mark.parametrize("mode", ["cancel", "partial-enter", "remove"])
def test_cleanup_failure_still_stops_siblings_before_stores(config, mode):
    """A failed child finalizer cannot strand siblings or close their stores early."""
    from hio.base import doing
    from eoa_verifier.serving import VerifierService

    stopped = []

    class Borrower(doing.Doer):
        def exit(self):
            assert service.baser.opened and service.hby.db.opened
            stopped.append("borrower")

    class Broken(doing.Doer):
        def exit(self):
            assert service.baser.opened
            stopped.append("broken")
            raise RuntimeError("cleanup failure")

    class BrokenEntry(doing.Doer):
        def enter(self, *, temp=None):
            raise ValueError("entry failure")

    borrower, broken = Borrower(), Broken()

    class Service(VerifierService):
        def _open(self):
            super()._open()
            self.doers.extend([borrower, broken])
            if mode == "partial-enter":
                self.doers.append(BrokenEntry())

    service = Service(config)
    scheduler = doing.Doist(doers=[service], tock=0.01, limit=0.02)
    try:
        with pytest.raises(ExceptionGroup, match="Service cleanup failed") as caught:
            if mode == "remove":
                scheduler.enter()
                try:
                    service.remove([borrower, broken])
                finally:
                    assert service.baser.opened and service.hby.db.opened
            else:
                scheduler.do()
        assert len(caught.value.exceptions) == 1
        assert str(caught.value.exceptions[0]) == "cleanup failure"
        if mode == "partial-enter":
            assert str(caught.value.__context__) == "entry failure"
    finally:
        scheduler.exit()
    assert stopped == ["broken", "borrower"]
    assert not service.baser.opened and not service.hby.db.opened
    with running_service(config) as reopened:
        assert reopened.hab.pre == service.hab.pre
