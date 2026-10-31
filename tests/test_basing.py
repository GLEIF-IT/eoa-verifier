"""Real LMDB atomic completion, duplicate and restart boundaries."""

from unittest.mock import patch

import pytest
from keri.db import dbing
from eoa_verifier.basing import PendingVerification, VerificationResult, VerifierBaser


def test_duplicates_completion_and_restart(tmp_path):
    """Retain first Grants, results and waiting information across reopen."""
    baser = VerifierBaser(name="work", headDirPath=str(tmp_path), temp=False)
    try:
        work = PendingVerification("a", "first")
        assert baser.enqueue(work)
        baser.note_pending("a", "missing source")
        assert not baser.enqueue(PendingVerification("a", "duplicate"))
        baser.enqueue(PendingVerification("b", "first"))
        result = VerificationResult(
            "b",
            "verified",
            eoaResult={"wallet": "wallet", "accountObservation": {"chainId": 31337}},
        )
        baser.finish(result)
        baser.finish(result)
        with pytest.raises(ValueError, match="conflicting"):
            baser.finish(VerificationResult("b", "rejected", "wrong"))
        assert not baser.enqueue(PendingVerification("b", "duplicate"))
        baser.close()
        baser.reopen()
        assert baser.pending.get(keys=("a",)) == PendingVerification(
            "a", "first", "missing source"
        )
        assert baser.pending.get(keys=("b",)) is None
        assert baser.results.get(keys=("b",)) == result
    finally:
        baser.close()


def test_completion_rollback_after_result_write():
    """A failure deleting pending work rolls back the result written in the same transaction."""
    with dbing.openLMDB(cls=VerifierBaser) as baser:
        work = PendingVerification("a", "first")
        baser.enqueue(work)
        real_env = baser.env

        class FailingTransaction:
            """Delegate commit/abort to LMDB, injecting failure only at pending deletion."""

            def __enter__(self):
                self.txn = real_env.begin(write=True)
                self.txn.__enter__()
                return self

            def __exit__(self, *args):
                return self.txn.__exit__(*args)

            def get(self, *args, **kwa):
                return self.txn.get(*args, **kwa)

            def put(self, *args, **kwa):
                return self.txn.put(*args, **kwa)

            def delete(self, *args, **kwa):
                raise RuntimeError("between writes")

        class FailingEnvironment:
            """Supply the transaction fault without changing LMDB commit semantics."""

            def begin(self, **kwa):
                return FailingTransaction()

        with (
            patch.object(baser, "env", FailingEnvironment()),
            pytest.raises(RuntimeError, match="between writes"),
        ):
            baser.finish(VerificationResult("a", "verified"))
        assert baser.pending.get(keys=("a",)) == work
        assert baser.results.get(keys=("a",)) is None
        baser.finish(VerificationResult("a", "rejected", "invalid proof"))
        assert baser.pending.get(keys=("a",)) is None
        assert baser.results.get(keys=("a",)).reason == "invalid proof"


def test_replay_pruning_pages_past_live_claims_after_restart(tmp_path):
    """Bound each scan, retain live nonces and resume past them after reopening LMDB."""
    with dbing.openLMDB(
        cls=VerifierBaser, name="replay", headDirPath=str(tmp_path), temp=False
    ) as baser:
        for nonce, expiry in (("a", 100), ("b", 200), ("c", 100), ("d", 100)):
            assert baser.claim_nonce("peer", nonce, expiry, now=99)

        # Only a and b are scanned: live b must not block expired c and d later.
        assert baser.prune_replay_claims(100, limit=2) == 1
        assert baser.replay_claims.cntAll() == 3
        baser.close()
        baser.reopen()
        assert baser.prune_replay_claims(100, limit=2) == 2
        assert baser.replay_claims.cntAll() == 1
        assert baser.replay_claims.get(keys=("peer", "b")).expiresAt == 200
        # The cursor wraps; the remaining live claim is still protected.
        assert baser.prune_replay_claims(100, limit=2) == 0
        assert not baser.claim_nonce("peer", "b", 200, now=100)
