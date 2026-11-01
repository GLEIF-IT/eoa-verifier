"""receiving/test_grants.py."""

from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from eoa_verifier.persistence.writing import ApplicationWriter
from eoa_verifier.receiving.grants import GrantNotificationDoer, IpexGrantAdapter
from tests.support.issuers import candidate, signed_notice
from tests.support.services import entered_service


@pytest.mark.parametrize("kind", ["accepted", "malformed", "unrelated"])
def test_consumed_notification_removes_note_and_signal(config, kind):
    """Use real Noter storage to prove success, bad input and unrelated notices clean all records."""
    lifetime = ExitStack()
    runtime = lifetime.enter_context(entered_service(config))
    try:
        attrs = {"r": "/exn/ipex/grant", "d": "grant"}
        if kind == "unrelated":
            attrs["r"] = "/exn/ipex/offer"
        runtime.notifier.add(attrs)
        noter = runtime.notifier.noter
        notice, _ = noter.getNotes()[0]
        association = candidate()
        if kind == "malformed":
            association["u"] = "invalid SAID"
        # Replace envelope lookup only; KERIpy decoding and persistence are real.
        with patch(
            "eoa_verifier.receiving.grants.exchanging.cloneMessage",
            return_value=(SimpleNamespace(ked={"e": {"acdc": association}}), {}),
        ):
            runtime.grant_replay.process_one()
        assert noter.getNotes() == []
        assert noter.nidx.get(keys=(notice.rid,)) is None
        assert noter.ncigs.get(keys=(notice.rid,)) is None
        assert (runtime.baser.pending.get(keys=(association["d"],)) is not None) == (
            kind == "accepted"
        )
    finally:
        lifetime.close()


@pytest.mark.parametrize("boundary", ["parser", "storage"])
def test_internal_failure_preserves_active_grant_record(config, boundary):
    """Inject parser/storage errors after valid decoding and prove the KERIpy notice remains retryable."""
    lifetime = ExitStack()
    runtime = lifetime.enter_context(entered_service(config))
    try:
        runtime.notifier.add({"r": "/exn/ipex/grant", "d": "grant"})
        notice, _ = runtime.notifier.noter.getNotes()[0]
        association = candidate()
        target, method = (
            (runtime.parser, "onceParsator")
            if boundary == "parser"
            else (ApplicationWriter, "complete_grant")
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
            runtime.grant_replay.process_one()
        assert runtime.baser.grant_active.get(keys=("receiver",)).noticeId == notice.rid
        assert runtime.baser.pending.get(keys=(association["d"],)) is None
    finally:
        lifetime.close()


def test_missing_grant_waits_durably_without_blocking_keripy_notices(config):
    """An absent EXN leaves its persisted notification available for a later attempt."""
    lifetime = ExitStack()
    runtime = lifetime.enter_context(entered_service(config))
    try:
        runtime.notifier.add({"r": "/exn/ipex/grant", "d": "missing"})
        notice, _ = runtime.notifier.noter.getNotes()[0]
        runtime.grant_replay.process_one()
        assert runtime.baser.grant_waiting.get(keys=(notice.rid,)).attempts == 1
        assert runtime.notifier.noter.getNoteCnt() == 0
    finally:
        lifetime.close()


@pytest.mark.parametrize("bad", ["empty", "truncated"])
def test_signed_bad_embed_is_consumed_and_valid_work_progresses(config, bad):
    """A malformed body or incomplete frame is consumed; later work and restart still progress."""
    from keri.app import habbing

    lifetime = ExitStack()
    runtime = lifetime.enter_context(entered_service(config))
    try:
        embedded = candidate()
        attachments = b""
        if bad == "empty":
            embedded = {}
        else:
            attachments = b"-IAB"
        with habbing.openHby(name="sender", temp=True) as hby:
            sender = hby.makeHab(name="sender")
            signed_notice(runtime, sender, embedded, attachments)
            # A real HIO sibling must get its turn after intake returns.
            from hio.base import doing

            ticks = []

            class Heartbeat(doing.Doer):
                def recur(self, tyme):
                    ticks.append(tyme)
                    return True

            scheduler = doing.Doist(tock=0.01, limit=0.02)
            scheduler.do(
                doers=[GrantNotificationDoer(runtime.grant_replay), Heartbeat()]
            )
            assert ticks and runtime.notifier.noter.getNotes() == []
            good = candidate()
            signed_notice(runtime, sender, good)
            runtime.grant_replay.process_one()
            assert runtime.baser.pending.get(keys=(good["d"],)) is not None
        lifetime.close()
        lifetime = ExitStack()
        runtime = lifetime.enter_context(entered_service(config))
        assert runtime.notifier.noter.getNotes() == []
    finally:
        lifetime.close()


def test_one_notice_per_turn_and_bounded_missing_material(config):
    """A missing Grant leaves the KERIpy queue; later notices and HIO siblings progress."""
    from hio.base import doing

    with entered_service(config) as runtime:
        runtime.grant_replay.clock = lambda: 100
        runtime.notifier.add({"r": "/exn/ipex/grant", "d": "missing"})
        runtime.notifier.add({"r": "/unrelated", "d": "later"})
        counts = []

        class Heartbeat(doing.Doer):
            def recur(self, tyme):
                counts.append(runtime.notifier.noter.getNoteCnt())
                return len(counts) == 3

        doing.Doist(tock=0.01, limit=0.03).do(
            doers=[GrantNotificationDoer(runtime.grant_replay), Heartbeat()]
        )
        assert counts[:2] == [1, 0]
        assert runtime.baser.grant_waiting.cntAll() == 1
        for now in (105, 110):
            runtime.grant_replay.clock = lambda now=now: now
            runtime.grant_replay.process_one()
        assert runtime.baser.grant_waiting.cntAll() == 0
        assert runtime.baser.grant_dead.cntAll() == 1
        key, grantRecord = next(runtime.baser.grant_dead.getItemIter())
        assert grantRecord.attempts == 3 and "missing" in grantRecord.reason
        runtime.grant_replay.retry(grantRecord.noticeId)
        assert runtime.baser.grant_dead.cntAll() == 0
        assert runtime.baser.grant_waiting.get(keys=key).attempts == 0


def test_interrupted_grant_record_reopens_without_keripy_notice(config):
    """A removed KERIpy notice is recoverable entirely from the application's active phase."""
    with entered_service(config) as runtime:
        runtime.notifier.add({"r": "/exn/ipex/grant", "d": "missing"})
        with (
            patch.object(
                IpexGrantAdapter, "replay", side_effect=RuntimeError("interrupted")
            ),
            pytest.raises(RuntimeError),
        ):
            runtime.grant_replay.process_one()
        assert runtime.notifier.noter.getNoteCnt() == 0
        grantRecord = runtime.baser.grant_active.get(keys=("receiver",))
        assert grantRecord.attempts == 1
    with entered_service(config) as runtime:
        runtime.grant_replay.process_one()
        assert runtime.baser.grant_active.cntAll() == 0
        assert (
            runtime.baser.grant_waiting.get(keys=(grantRecord.noticeId,)).attempts == 2
        )


def test_completion_rollback_preserves_active_grant(config):
    """Failure after enqueue aborts both writes, so restart can safely replay."""
    from eoa_verifier.persistence.records import GrantReplayRecord, VerificationRecord

    with entered_service(config) as runtime:
        record = GrantReplayRecord("notice", {}, attempts=1)
        runtime.baser.grant_active.pin(keys=("receiver",), val=record)
        env = runtime.baser.env

        class Transaction:
            def __enter__(self):
                self.txn = env.begin(write=True)
                return self

            def __exit__(self, kind, value, traceback):
                self.txn.abort() if kind else self.txn.commit()

            def get(self, *args, **kwa):
                return self.txn.get(*args, **kwa)

            def put(self, *args, **kwa):
                return self.txn.put(*args, **kwa)

            def delete(self, *args, **kwa):
                raise RuntimeError("after enqueue")

        with (
            patch.object(
                runtime.baser, "env", SimpleNamespace(begin=lambda **kwa: Transaction())
            ),
            pytest.raises(RuntimeError, match="after enqueue"),
        ):
            ApplicationWriter(runtime.baser).complete_grant(
                record, VerificationRecord("cred", "grant")
            )
        assert runtime.baser.pending.get(keys=("cred",)) is None
        assert runtime.baser.grant_active.get(keys=("receiver",)) == record
