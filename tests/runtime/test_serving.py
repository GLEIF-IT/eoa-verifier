"""runtime/test_serving.py."""

from dataclasses import replace
from unittest.mock import patch

import pytest
from keri.app import indirecting, storing

from eoa_verifier.receiving.directing import Receiver
from eoa_verifier.runtime.serving import run_service
from tests.support.services import entered_service, verifier_service


@pytest.mark.parametrize("failure", ["configing.openCF", "oobiing.Oobiery"])
def test_setup_failure_releases_all_previously_opened_stores(config, failure):
    """Inject late setup failure; reopening the same paths detects leaked LMDB handles."""
    with (
        patch(
            f"eoa_verifier.runtime.serving.{failure}",
            side_effect=RuntimeError("setup failure"),
        ),
        pytest.raises(RuntimeError, match="setup failure"),
    ):
        run_service(config)
    # A leaked LMDB handle makes this reopen fail in the same process.
    with entered_service(config):
        pass


@pytest.mark.parametrize("mode", ["cancel", "partial-enter"])
def test_children_stop_before_borrowed_stores_close(config, mode):
    """Cancellation and partial entry stop children before stores close."""
    from hio.base import doing
    from hio.core import http

    from eoa_verifier.runtime.serving import VerifierService

    stopped = []

    class Child(doing.Doer):
        """Record shutdown while the stores borrowed by a child are still usable."""

        def exit(self):
            assert service.baser.opened and service.hby.db.opened
            stopped.append(True)

    class BrokenEntry(doing.Doer):
        """Fail after earlier siblings entered, exercising HIO unwinding."""

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
        patch("eoa_verifier.runtime.serving.VerifierService", Service),
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
        webhook_url="http://127.0.0.1:9999/hook?memo=a+b&path=%2F",
        webhook_aid=config.trusted_geda_aid,
        webhook_timeout=7,
        webhook_interval=2,
        webhook_backoff_base=3,
        webhook_backoff_cap=20,
    )
    with verifier_service(configured) as service:
        assert (
            service.sender.service.transport.timeout,
            service.sender.service.interval,
            service.sender.service.backoff_base,
            service.sender.service.backoff_cap,
        ) == (7, 2, 3, 20)
    with pytest.raises(ValueError, match="positive"):
        replace(configured, webhook_interval=0)
    with pytest.raises(ValueError, match="at least"):
        replace(configured, webhook_backoff_cap=1)


def test_enabling_delivery_preserves_results_without_config_warning(config, caplog):
    """Delivery options do not change the recorded trust/network settings."""
    from eoa_verifier.persistence.records import VerificationResult

    with entered_service(config) as service:
        service.baser.results.put(
            keys=("saved",), val=VerificationResult("saved", "verified")
        )
    delivery = replace(
        config,
        webhook_url="http://127.0.0.1:9999/hook",
        webhook_aid=config.trusted_geda_aid,
    )
    with entered_service(delivery) as reopened:
        assert reopened.sender is not None
        assert reopened.baser.results.get(keys=("saved",)).status == "verified"
    assert "startup settings changed" not in caplog.text


@pytest.mark.parametrize("field", ["trusted_geda_aid", "chain_id"])
def test_changed_config_warns_and_reopens_without_reset(config, caplog, field):
    """Changed settings become the baseline; results and consumed nonces survive."""
    from keri import core

    from eoa_verifier.persistence.records import AcceptedNonce, VerificationResult

    result = VerificationResult("saved", "verified")
    nonce = AcceptedNonce("saved")
    with entered_service(config) as service:
        service.baser.results.put(keys=("saved",), val=result)
        service.baser.accepted_nonces.put(keys=("nonce",), val=nonce)
    assert "startup settings changed" not in caplog.text
    value = core.Signer().verfer.qb64 if field == "trusted_geda_aid" else 1
    changed = replace(config, **{field: value})
    with entered_service(changed) as service:
        assert service.baser.results.get(keys=("saved",)) == result
        assert service.baser.accepted_nonces.get(keys=("nonce",)) == nonce
    assert "Verifier startup settings changed" in caplog.text
    assert str(getattr(config, field)) in caplog.text
    assert str(value) in caplog.text
    assert caplog.records[-1].levelname == "WARNING"
    caplog.clear()
    with entered_service(changed):
        pass
    assert "startup settings changed" not in caplog.text
    with entered_service(config):
        pass
    assert "Verifier startup settings changed" in caplog.text


def test_missing_config_baseline_does_not_reject_saved_results(config, caplog):
    """A missing advisory record is initialized without auditing retained history."""
    from eoa_verifier.persistence.records import VerificationResult

    with entered_service(config) as service:
        service.baser.results.put(
            keys=("saved",), val=VerificationResult("saved", "verified")
        )
        service.baser.scope.rem(keys=("verification",))
    with entered_service(config) as reopened:
        assert reopened.baser.results.get(keys=("saved",)).status == "verified"
        assert (
            reopened.baser.scope.get(keys=("verification",)).chainId == config.chain_id
        )
    assert "startup settings changed" not in caplog.text


def test_runtime_has_one_receiver_and_no_mailbox(config):
    """Compose one shared parser owner without opening or scheduling a mailbox."""
    with patch(
        "keri.app.storing.Mailboxer", side_effect=AssertionError("mailbox opened")
    ):
        with entered_service(config) as service:
            receivers = [d for d in service.doers if isinstance(d, Receiver)]
            assert len(receivers) == 1
            assert not any(
                isinstance(
                    d,
                    (
                        indirecting.MailboxDirector,
                        indirecting.Poller,
                        storing.Respondant,
                    ),
                )
                for d in service.doers
            )
            assert service.parser is receivers[0].parser
