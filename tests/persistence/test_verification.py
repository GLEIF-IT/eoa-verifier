"""Atomic verification completion rolls back all prepared writes."""

from unittest.mock import patch

import pytest
from keri.db import dbing

from eoa_verifier.persistence.basing import VerifierBaser
from eoa_verifier.persistence.records import (
    VerificationRecord,
    VerificationResult,
)
from tests.support.persistence import enqueue_verification
from tests.support.services import verification_service


def test_completion_rollback_after_result_write():
    """A failure deleting pending work rolls back the result written in the same transaction."""
    with dbing.openLMDB(cls=VerifierBaser) as baser:
        verification = VerificationRecord("a", "first")
        enqueue_verification(baser, verification)
        verificationService = verification_service(baser)
        verification = verificationService.start_pending(
            verificationService.next_pending()
        )
        real_env = baser.env

        class FailingTransaction:
            """Delegate commit/abort to LMDB, injecting failure only at pending deletion."""

            def __enter__(self):
                """Enter a real LMDB write transaction and expose the fault-injecting wrapper."""
                self.txn = real_env.begin(write=True)
                self.txn.__enter__()
                return self

            def __exit__(self, *args):
                """Let the real transaction commit or abort according to the propagated exception."""
                return self.txn.__exit__(*args)

            def get(self, *args, **kwa):
                """Delegate reads to the real write transaction."""
                return self.txn.get(*args, **kwa)

            def put(self, *args, **kwa):
                """Store the prepared result in the real transaction before the later failure."""
                return self.txn.put(*args, **kwa)

            def delete(self, *args, **kwa):
                """Interrupt phase deletion so the preceding result write must abort with it."""
                raise RuntimeError("between writes")

        class FailingEnvironment:
            """Supply the transaction fault without changing LMDB commit semantics."""

            def begin(self, **kwa):
                """Supply the real-transaction fault wrapper at the writer entry point."""
                return FailingTransaction()

        with (
            patch.object(baser, "env", FailingEnvironment()),
            pytest.raises(RuntimeError, match="between writes"),
        ):
            verification_service(baser).finish(VerificationResult("a", "verified"))
        assert baser.verifying.get(keys=("a",)) == verification
        assert baser.results.get(keys=("a",)) is None
        assert baser.accepting.cntAll() == 0
        verification_service(baser).finish(
            VerificationResult("a", "rejected", "invalid proof")
        )
        assert baser.pending.get(keys=("a",)) is None
        assert baser.results.get(keys=("a",)).reason == "invalid proof"
