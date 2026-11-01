"""Atomic association status, nonce and event persistence."""

from unittest.mock import patch

import pytest

from tests.support.acceptance import (
    accept_verified_result,
    revocation_service,
)


def test_failed_acceptance_rolls_back_status_and_event(verified_store):
    """A failure after the status write leaves only the completed verification result."""
    baser = verified_store
    with (
        patch.object(
            baser.outbox, "serializer", side_effect=RuntimeError("write failed")
        ),
        pytest.raises(RuntimeError),
    ):
        accept_verified_result(baser)
    assert baser.associations.get(keys=("association",)) is None
    assert baser.accepted_nonces.cntAll() == 0
    assert list(baser.outbox.getItemIter()) == []
    assert baser.results.get(keys=("association",)).status == "verified"
    assert accept_verified_result(baser).status == "accepted"


@pytest.mark.parametrize("revocation", [False, True])
def test_status_and_event_write_failure_aborts_entire_transition(
    verified_store, revocation
):
    """Fail after the outbox write and prove status, event and nonce remain atomic."""
    from types import SimpleNamespace

    baser = verified_store
    previous = accept_verified_result(baser) if revocation else None
    env = baser.env

    class Transaction:
        """Delegate a real transaction and interrupt immediately after its outbox write."""
        def __enter__(self):
            """Open a real test-owned LMDB write transaction and return this wrapper."""
            self.txn = env.begin(write=True)
            return self

        def __exit__(self, kind, value, traceback):
            """Abort on an exception or commit on normal exit, preserving real LMDB atomicity."""
            self.txn.abort() if kind else self.txn.commit()

        def __getattr__(self, name):
            """Delegate unmodified transaction operations to the underlying LMDB transaction."""
            return getattr(self.txn, name)

        def put(self, *args, **kwa):
            """Perform the real put, then interrupt after an outbox mutation so all writes must roll back."""
            result = self.txn.put(*args, **kwa)
            if kwa.get("db") == baser.outbox.sdb:
                raise RuntimeError("after event write")
            return result

    def begin(**kwa):
        """Wrap write transactions for fault injection and leave ordinary readers unchanged."""
        return Transaction() if kwa.get("write") else env.begin(**kwa)

    with (
        patch.object(baser, "env", SimpleNamespace(begin=begin)),
        pytest.raises(RuntimeError, match="after event write"),
    ):
        if revocation:
            revocation_service(baser).apply_revocation("association")
        else:
            accept_verified_result(baser)
    assert baser.associations.get(keys=("association",)) == previous
    assert baser.accepted_nonces.cntAll() == int(revocation)
    assert baser.outbox.cntAll() == int(revocation)
    assert baser.delivery_ready.cntAll() == int(revocation)
    assert baser.accepting.cntAll() == int(not revocation)
