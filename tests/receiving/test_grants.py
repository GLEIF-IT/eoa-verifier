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
def test_internal_failure_preserves_active_handoff(config, boundary):
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
        assert runtime.baser.grant_active.get(keys=("receiver",)).noticeId == notice.rid
        assert runtime.baser.pending.get(keys=(association["d"],)) is None
    finally:
        lifetime.close()


def test_missing_grant_waits_durably_without_blocking_native_notices(config):
    """An absent EXN leaves its persisted notification available for a later attempt."""
    lifetime = ExitStack()
    runtime = lifetime.enter_context(entered_service(config))
    try:
        grants = next(d for d in runtime.doers if isinstance(d, GrantNotificationDoer))
        grants.notifier.add({"r": "/exn/ipex/grant", "d": "missing"})
        notice, _ = grants.notifier.noter.getNotes()[0]
        grants.process_notes()
        assert runtime.baser.grant_waiting.get(keys=(notice.rid,)).attempts == 1
        assert grants.notifier.noter.getNoteCnt() == 0
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


def test_one_notice_per_turn_and_bounded_missing_material(config):
    """A missing Grant leaves the native queue; later notices and HIO siblings progress."""
    from hio.base import doing

    with entered_service(config) as runtime:
        grants = next(d for d in runtime.doers if isinstance(d, GrantNotificationDoer))
        grants.clock = lambda: 100
        grants.notifier.add({"r": "/exn/ipex/grant", "d": "missing"})
        grants.notifier.add({"r": "/unrelated", "d": "later"})
        counts = []

        class Heartbeat(doing.Doer):
            def recur(self, tyme):
                counts.append(grants.notifier.noter.getNoteCnt())
                return len(counts) == 3

        doing.Doist(tock=0.01, limit=0.03).do(doers=[grants, Heartbeat()])
        assert counts[:2] == [1, 0]
        assert runtime.baser.grant_waiting.cntAll() == 1
        for now in (105, 110):
            grants.clock = lambda now=now: now
            grants.process_notes()
        assert runtime.baser.grant_waiting.cntAll() == 0
        assert runtime.baser.grant_dead.cntAll() == 1
        key, work = next(runtime.baser.grant_dead.getItemIter())
        assert work.attempts == 3 and "missing" in work.reason
        runtime.baser.retry_grant(work.noticeId)
        assert runtime.baser.grant_dead.cntAll() == 0
        assert runtime.baser.grant_waiting.get(keys=key).attempts == 0


def test_interrupted_handoff_reopens_without_native_notice(config):
    """A removed native notice is recoverable entirely from the application's active phase."""
    with entered_service(config) as runtime:
        grants = next(d for d in runtime.doers if isinstance(d, GrantNotificationDoer))
        grants.notifier.add({"r": "/exn/ipex/grant", "d": "missing"})
        with (
            patch.object(
                grants, "process_grant_notice", side_effect=RuntimeError("interrupted")
            ),
            pytest.raises(RuntimeError),
        ):
            grants.process_notes()
        assert grants.notifier.noter.getNoteCnt() == 0
        work = runtime.baser.grant_active.get(keys=("receiver",))
        assert work.attempts == 1
    with entered_service(config) as runtime:
        grants = next(d for d in runtime.doers if isinstance(d, GrantNotificationDoer))
        grants.process_notes()
        assert runtime.baser.grant_active.cntAll() == 0
        assert runtime.baser.grant_waiting.get(keys=(work.noticeId,)).attempts == 2
