"""Notification lifecycle using native storage and targeted failure injection."""

from types import SimpleNamespace
from contextlib import ExitStack
from unittest.mock import patch

import pytest
from native_helpers import candidate

from eoa_verifier.receiving.grants import GrantNotificationDoer
from native_helpers import entered_service


@pytest.mark.parametrize("kind", ["accepted", "malformed", "unrelated"])
def test_consumed_notification_removes_all_native_records(config, kind):
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
        # Replace envelope lookup only; native decoding and persistence are real.
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
    """Inject parser/storage errors after valid decoding and prove the native notice remains retryable."""
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


def signed_notice(runtime, grants, sender, embedded, attachments=b""):
    """Deliver an actual signed opening Grant through native EXN authentication."""
    from keri.core import coring, parsing, serdering
    from keri.peer import exchanging
    from keri.vc import protocoling

    exn, _ = exchanging.exchange(
        route="/ipex/grant",
        sender=sender.pre,
        recipient=runtime.hab.pre,
        payload={"m": "intake regression"},
    )
    sad = dict(exn.sad)
    sad["e"] = coring.Saider.saidify(sad={"d": "", "acdc": embedded})[1]
    exn = serdering.SerderKERI(sad=sad, makify=True)
    stream = sender.endorse(exn, last=False, pipelined=False)
    if attachments:
        from keri import core, kering

        pathed = coring.Pather(path=["e", "acdc"]).qb64b + attachments
        stream += (
            core.Counter(
                core.Codens.PathedMaterialGroup,
                count=len(pathed) // 4,
                gvrsn=kering.Vrsn_1_0,
            ).qb64b
            + pathed
        )
    exc = exchanging.Exchanger(hby=runtime.hby, handlers=[])
    protocoling.loadHandlers(hby=runtime.hby, exc=exc, notifier=grants.notifier)
    runtime.hby.psr.parse(ims=bytearray(sender.makeOwnEvent(sn=0)))
    parsing.Parser(kvy=runtime.hby.kvy, exc=exc).parse(ims=bytearray(stream))
    assert any(n.attrs["d"] == exn.said for n, _ in grants.notifier.noter.getNotes())
    return exn.said


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
    """Real native storage retains early notices without starving later work or siblings."""
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


def test_wrong_schema_is_coordinator_rejection_without_native_acceptance(config):
    """A real signed Grant supplies rejection evidence, never native acceptance."""
    from keri.app import habbing
    from keri.core import serdering

    from eoa_verifier.verification.constants import LE_SCHEMA
    from eoa_verifier.verification.coordinating import PresentationVerifierDoer

    with (
        entered_service(config) as runtime,
        habbing.openHby(name="sender", temp=True) as hby,
    ):
        grants = next(d for d in runtime.doers if isinstance(d, GrantNotificationDoer))
        coordinator = next(
            d for d in runtime.doers if isinstance(d, PresentationVerifierDoer)
        )
        sad = candidate()
        sad["s"] = LE_SCHEMA
        creder = serdering.SerderACDC(sad=sad, makify=True)
        sender = hby.makeHab(name="sender")
        grant_said = signed_notice(runtime, grants, sender, creder.sad)
        attrs = {"d": grant_said}
        grants.process_grant_notice(attrs)
        pending = runtime.baser.pending.get(keys=(creder.said,))
        assert pending is not None
        assert runtime.baser.results.get(keys=(creder.said,)) is None
        assert runtime.rgy.reger.creds.get(keys=(creder.said,)) is None
        assert runtime.rgy.reger.saved.get(keys=(creder.said,)) is None
        grants.process_grant_notice(attrs)
        assert runtime.baser.pending.get(keys=(creder.said,)) == pending
        coordinator.process_ready()
        result = runtime.baser.results.get(keys=(creder.said,))
        assert result.outcome == "rejected"
        assert "unexpected schema" in result.reason
        assert runtime.baser.pending.get(keys=(creder.said,)) is None
        grants.process_grant_notice(attrs)
        assert runtime.baser.results.get(keys=(creder.said,)) == result
        assert runtime.baser.pending.get(keys=(creder.said,)) is None
