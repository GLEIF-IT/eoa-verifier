"""Notification lifecycle using native storage and targeted failure injection."""

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from native_helpers import candidate

from eoa_verifier.receiving.grants import GrantNotificationDoer
from eoa_verifier.serving import setup_service


@pytest.mark.parametrize("kind", ["accepted", "malformed", "unrelated"])
def test_consumed_notification_removes_all_native_records(config, kind):
    """Use real Noter storage to prove success, bad input and unrelated notices clean all records."""
    runtime = setup_service(config)
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
        assert (runtime.baser.get_verification(association["d"]) is not None) == (
            kind == "accepted"
        )
    finally:
        runtime.close()


@pytest.mark.parametrize("boundary", ["parser", "storage"])
@pytest.mark.parametrize("error", [ValueError, KeyError, TypeError])
def test_internal_failure_preserves_notification(config, boundary, error):
    """Inject parser/storage errors after valid decoding and prove the native notice remains retryable."""
    runtime = setup_service(config)
    try:
        grants = next(d for d in runtime.doers if isinstance(d, GrantNotificationDoer))
        grants.notifier.add({"r": "/exn/ipex/grant", "d": "grant"})
        notice, _ = grants.notifier.noter.getNotes()[0]
        association = candidate()
        target, method = (
            (grants.parser, "parseOne")
            if boundary == "parser"
            else (runtime.baser, "start_verification")
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
            patch.object(target, method, side_effect=error("internal failure")),
            pytest.raises(error, match="internal failure"),
        ):
            grants.process_notes()
        assert grants.notifier.noter.get(notice.rid)[0].raw == notice.raw
        assert runtime.baser.get_verification(association["d"]) is None
    finally:
        runtime.close()


def test_missing_grant_retains_notification_until_available(config):
    """An actual absent EXN leaves its persisted notification untouched for later native delivery."""
    runtime = setup_service(config)
    try:
        grants = next(d for d in runtime.doers if isinstance(d, GrantNotificationDoer))
        grants.notifier.add({"r": "/exn/ipex/grant", "d": "missing"})
        notice, _ = grants.notifier.noter.getNotes()[0]
        grants.process_notes()
        assert grants.notifier.noter.get(notice.rid)[0].raw == notice.raw
    finally:
        runtime.close()
