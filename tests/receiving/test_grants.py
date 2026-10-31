"""receiving/test_grants.py."""

from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from eoa_verifier.receiving.grants import GrantNotificationDoer
from tests.support.issuers import candidate, signed_notice
from tests.support.services import entered_service


@pytest.mark.parametrize("kind", ["accepted", "malformed", "unrelated"])
def test_consumed_notification_removes_note_and_signal(config, kind):
    """Use real Noter storage to prove success, bad input and unrelated notices clean all records."""
    lifetime = ExitStack()
    runtime = lifetime.enter_context(entered_service(config))
    try:
        grants = next(d for d in runtime.doers if isinstance(d, GrantNotificationDoer))
        attrs = {"r": "/exn/ipex/grant", "d": "grant"}
        if kind == "unrelated":
            attrs["r"] = "/exn/ipex/offer"
        grants.notifier.add(attrs)
        noter = grants.notifier.noter
        notice, _ = noter.getNotes()[0]
        association = candidate()
        if kind == "malformed":
            association["u"] = "invalid SAID"
        # Replace envelope lookup only; KERIpy decoding and persistence are real.
        with patch(
            "eoa_verifier.receiving.grants.exchanging.cloneMessage",
            return_value=(SimpleNamespace(ked={"e": {"acdc": association}}), {}),
        ):
            grants.process_notes()
        assert noter.getNotes() == []
        assert noter.nidx.get(keys=(notice.rid,)) is None
        assert noter.ncigs.get(keys=(notice.rid,)) is None
        assert (runtime.baser.pending.get(keys=(association["d"],)) is not None) == (
            kind == "accepted"
        )
    finally:
        lifetime.close()


@pytest.mark.parametrize("boundary", ["parser", "storage"])
def test_internal_failure_preserves_notification(config, boundary):
    """Inject parser/storage errors after valid decoding and prove the KERIpy notice remains retryable."""
    lifetime = ExitStack()
    runtime = lifetime.enter_context(entered_service(config))
    try:
        grants = next(d for d in runtime.doers if isinstance(d, GrantNotificationDoer))
        grants.notifier.add({"r": "/exn/ipex/grant", "d": "grant"})
        notice, _ = grants.notifier.noter.getNotes()[0]
        association = candidate()
        target, method = (
            (grants.parser, "onceParsator")
            if boundary == "parser"
            else (runtime.baser, "enqueue")
        )
        # Include an embed stream only when exercising the parser boundary.
        with (
            patch(
                "eoa_verifier.receiving.grants.exchanging.cloneMessage",
                return_value=(
                    SimpleNamespace(ked={"e": {"acdc": association}}),
                    {"acdc": bytearray()} if boundary == "parser" else {},
                ),
            ),
            patch.object(target, method, side_effect=ValueError("internal failure")),
            pytest.raises(ValueError, match="internal failure"),
        ):
            grants.process_notes()
        assert grants.notifier.noter.get(notice.rid)[0].raw == notice.raw
        assert runtime.baser.pending.get(keys=(association["d"],)) is None
    finally:
        lifetime.close()


def test_missing_grant_retains_notification_until_available(config):
    """An absent EXN leaves its persisted notification available for a later attempt."""
    lifetime = ExitStack()
    runtime = lifetime.enter_context(entered_service(config))
    try:
        grants = next(d for d in runtime.doers if isinstance(d, GrantNotificationDoer))
        grants.notifier.add({"r": "/exn/ipex/grant", "d": "missing"})
        notice, _ = grants.notifier.noter.getNotes()[0]
        grants.process_notes()
        assert grants.notifier.noter.get(notice.rid)[0].raw == notice.raw
    finally:
        lifetime.close()


@pytest.mark.parametrize("bad", ["empty", "truncated"])
def test_signed_bad_embed_is_consumed_and_valid_work_progresses(config, bad):
    """A malformed body or incomplete frame is consumed; later work and restart still progress."""
    from keri.app import habbing

    lifetime = ExitStack()
    runtime = lifetime.enter_context(entered_service(config))
    try:
        grants = next(d for d in runtime.doers if isinstance(d, GrantNotificationDoer))
        embedded = candidate()
        attachments = b""
        if bad == "empty":
            embedded = {}
        else:
            attachments = b"-IAB"
        with habbing.openHby(name="sender", temp=True) as hby:
            sender = hby.makeHab(name="sender")
            signed_notice(runtime, grants, sender, embedded, attachments)
            # A real HIO sibling must get its turn after intake returns.
            from hio.base import doing

            ticks = []

            class Heartbeat(doing.Doer):
                def recur(self, tyme):
                    ticks.append(tyme)
                    return True

            scheduler = doing.Doist(tock=0.01, limit=0.02)
            scheduler.do(doers=[grants, Heartbeat()])
            assert ticks and grants.notifier.noter.getNotes() == []
            good = candidate()
            signed_notice(runtime, grants, sender, good)
            grants.process_notes()
            assert runtime.baser.pending.get(keys=(good["d"],)) is not None
        lifetime.close()
        lifetime = ExitStack()
        runtime = lifetime.enter_context(entered_service(config))
        grants = next(d for d in runtime.doers if isinstance(d, GrantNotificationDoer))
        assert grants.notifier.noter.getNotes() == []
    finally:
        lifetime.close()


def test_notice_pages_advance_past_retained_work(config):
    """Real KERIpy storage retains early notices without starving later work or siblings."""
    from hio.base import doing

    lifetime = ExitStack()
    runtime = lifetime.enter_context(entered_service(config))
    try:
        grants = next(d for d in runtime.doers if isinstance(d, GrantNotificationDoer))
        for i in range(65):
            grants.notifier.add({"r": "/exn/ipex/grant", "d": f"missing-{i}"})
        grants.notifier.add({"r": "/unrelated", "d": "last"})
        counts = []

        class Heartbeat(doing.Doer):
            def recur(self, tyme):
                counts.append(grants.notifier.noter.getNoteCnt())
                return len(counts) == 3

        with patch.object(
            grants, "process_grant_notice", wraps=grants.process_grant_notice
        ) as process:
            doing.Doist(tock=0.01, limit=0.03).do(doers=[grants, Heartbeat()])
            assert process.call_count <= 3 * 32
        assert counts[-1] < counts[0]
        assert grants.notifier.noter.getNoteCnt() == 65
    finally:
        lifetime.close()
