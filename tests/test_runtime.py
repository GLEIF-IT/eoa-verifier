"""Resource lifetime, store reopening and the standalone CLI boundary."""

from unittest.mock import patch

import pytest

from eoa_verifier.cli import main
from eoa_verifier.serving import run_service
from native_helpers import entered_service, verifier_service


@pytest.mark.parametrize("failure", ["configing.openCF", "oobiing.Oobiery"])
def test_setup_failure_releases_all_previously_opened_stores(config, failure):
    """Inject late setup failure; reopening the same paths detects leaked LMDB handles."""
    with (
        patch(
            f"eoa_verifier.serving.{failure}",
            side_effect=RuntimeError("setup failure"),
        ),
        pytest.raises(RuntimeError, match="setup failure"),
    ):
        run_service(config)
    # A leaked LMDB handle makes this reopen fail in the same process.
    with entered_service(config):
        pass


def test_cli_documents_network_options_and_rejects_missing_config(capsys):
    """Help lists network options; starting without required configuration exits with an error."""
    with pytest.raises(SystemExit) as caught:
        main(["server", "start", "--help"])
    assert caught.value.code == 0
    help_text = capsys.readouterr().out
    assert "--chain-id" in help_text and "--rpc-url" in help_text
    with pytest.raises(SystemExit) as missing:
        main(["server", "start"])
    assert missing.value.code == 2


@pytest.mark.parametrize("mode", ["cancel", "partial-enter"])
def test_children_stop_before_borrowed_stores_close(config, mode):
    """Cancellation and partial entry stop children before stores close."""
    from hio.base import doing
    from hio.core import http
    from eoa_verifier.serving import VerifierService

    stopped = []

    class Child(doing.Doer):
        """Record shutdown while the stores borrowed by a child are still usable."""

        def exit(self):
            assert service.baser.opened and service.hby.db.opened
            stopped.append(True)

    class BrokenEntry(doing.Doer):
        """Fail after earlier siblings entered, exercising native HIO unwinding."""

        def enter(self, *, temp=None):
            raise RuntimeError("entry failure")

    class Service(VerifierService):
        """Append lifecycle probes to otherwise normal application wiring."""

        def __init__(self, *args, **kwa):
            super().__init__(*args, **kwa)
            self.server = next(
                d.server for d in self.doers if isinstance(d, http.ServerDoer)
            )
            self.doers.append(Child())
            if mode == "partial-enter":
                self.doers.append(BrokenEntry())

    with (
        patch("eoa_verifier.serving.VerifierService", Service),
        verifier_service(config) as service,
    ):
        scheduler = doing.Doist(tock=0.01, limit=0.02)
        if mode == "partial-enter":
            with pytest.raises(RuntimeError, match="failure"):
                scheduler.do(doers=[service])
        else:
            scheduler.do(doers=[service])
        assert service.baser.opened and service.hby.db.opened
    assert stopped == [True]
    assert not service.baser.opened and not service.hby.db.opened
    assert not service.server.servant.opened
    with entered_service(config) as reopened:
        assert reopened.hab.pre == service.hab.pre


def test_cleanup_failure_still_stops_siblings_before_stores(config):
    """A failed finalizer must not strand siblings or close their stores early."""
    from hio.base import doing

    stopped = []

    class Borrower(doing.Doer):
        """Record that the surviving sibling closes before the outer stores."""

        def exit(self):
            assert service.baser.opened and service.hby.db.opened
            stopped.append(True)

    class Broken(doing.Doer):
        """Raise from a finalizer to exercise the service’s sibling-cleanup loop."""

        def exit(self):
            raise RuntimeError("cleanup failure")

    with pytest.raises(ExceptionGroup, match="Service cleanup failed") as caught:
        with entered_service(config) as service:
            service.extend([Borrower(), Broken()])

    assert stopped == [True]
    assert [str(error) for error in caught.value.exceptions] == ["cleanup failure"]
    assert not service.baser.opened and not service.hby.db.opened
