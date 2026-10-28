"""Resource lifetime, store reopening and the standalone CLI boundary."""

from dataclasses import replace
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
    assert "--webhook-backoff-cap" in help_text
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


def test_webhook_timings_reach_sender_and_reject_invalid_config(config):
    """Operational settings reach the one sender; invalid delays fail before opening resources."""
    configured = replace(
        config,
        webhook_url="http://127.0.0.1:9999/hook",
        webhook_aid=config.trusted_geda_aid,
        webhook_timeout=7,
        webhook_interval=2,
        webhook_backoff_base=3,
        webhook_backoff_cap=20,
    )
    with verifier_service(configured) as service:
        assert (
            service.sender.timeout,
            service.sender.interval,
            service.sender.backoff_base,
            service.sender.backoff_cap,
        ) == (7, 2, 3, 20)
    with pytest.raises(ValueError, match="positive"):
        replace(configured, webhook_interval=0)
    with pytest.raises(ValueError, match="at least"):
        replace(configured, webhook_backoff_cap=1)


def test_saved_verification_keeps_its_trust_scope_when_enabling_delivery(config):
    """Restart may enable delivery, but cannot reinterpret saved results under another root/chain."""
    from keri import core
    from eoa_verifier.basing import VerificationResult

    with entered_service(config) as service:
        # Isolate storage policy: native verification itself is covered by test_native.
        service.baser.results.put(keys=("saved",), val=VerificationResult("saved", "verified"))
    delivery = replace(config, webhook_url="http://127.0.0.1:9999/hook",
                       webhook_aid=config.trusted_geda_aid)
    with entered_service(delivery) as reopened:
        assert reopened.sender is not None
        assert reopened.baser.results.get(keys=("saved",)).outcome == "verified"
    for changed in (
        replace(delivery, trusted_geda_aid=core.Signer().verfer.qb64),
        replace(delivery, chain_id=1),
    ):
        with pytest.raises(ValueError, match="another GEDA root or chain"):
            with verifier_service(changed):
                pass
    with entered_service(delivery) as reopened:
        assert reopened.baser.results.get(keys=("saved",)).outcome == "verified"


def test_unscoped_saved_results_are_preserved_and_refused(config):
    """Old stores lack proof of their verification policy; do not silently adopt them."""
    from eoa_verifier.basing import VerificationResult

    with entered_service(config) as service:
        service.baser.results.put(keys=("saved",), val=VerificationResult("saved", "verified"))
        service.baser.scope.rem(keys=("verification",))
    with pytest.raises(ValueError, match="unscoped results"):
        with verifier_service(config):
            pass
    from keri.db import dbing
    from eoa_verifier.basing import VerifierBaser

    with dbing.openLMDB(cls=VerifierBaser, name=config.name, base=config.base,
                       headDirPath=config.head_dir, temp=False) as store:
        assert store.results.get(keys=("saved",)).outcome == "verified"
