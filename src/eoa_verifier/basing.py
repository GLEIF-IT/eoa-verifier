"""Persist unfinished verification and completed results independently of native evidence."""

from dataclasses import dataclass, field
from itertools import islice

from keri.db import dbing, koming


@dataclass
class PendingVerification:
    """Unfinished initial verification; membership in pending is the only workflow state."""

    associationSaid: str
    grantSaid: str
    reason: str = ""


@dataclass
class VerificationResult:
    """Completed initial check, not application acceptance, ownership or endorsement."""

    associationSaid: str
    outcome: str  # Workflow-selected verified or rejected outcome.
    reason: str = ""
    verified: dict = field(
        default_factory=dict
    )  # Wallet and initial account observation.


@dataclass
class MessageReceipt:
    """Durable transport nonce claim, independent of application-event deduplication."""

    expires: int


class VerifierBaser(dbing.LMDBer):
    """Own pending/results integrity and transport replay claims; make no verification decisions."""

    TailDirPath = "eoa-verifier/db"
    AltTailDirPath = ".eoa-verifier/db"
    TempPrefix = "eoa_verifier_db_"

    def reopen(self, **kwa):
        """Open the two verification tables and independent transport replay table."""
        super().reopen(**kwa)
        self.pending = koming.Komer(
            db=self, subkey="pending.", schema=PendingVerification
        )
        self.results = koming.Komer(
            db=self, subkey="results.", schema=VerificationResult
        )
        self.messages = koming.Komer(db=self, subkey="message.", schema=MessageReceipt)
        return self.env

    def enqueue(self, work):
        """Insert new unfinished work once; completed or pending duplicates return False."""
        key = work.associationSaid.encode()
        with self.env.begin(write=True) as txn:
            if txn.get(key, db=self.results.sdb) is not None:
                return False
            return txn.put(
                key, self.pending.serializer(work), db=self.pending.sdb, overwrite=False
            )

    def note_pending(self, said, reason):
        """Update only waiting information, preserving identity and the first Grant reference."""
        key = said.encode()
        with self.env.begin(write=True) as txn:
            raw = txn.get(key, db=self.pending.sdb)
            if raw is None:
                raise ValueError("pending work is absent")
            work = self.pending.deserializer(raw)
            if work.reason != reason:
                work.reason = reason
                txn.put(key, self.pending.serializer(work), db=self.pending.sdb)

    def finish(self, result):
        """Atomically insert a result and remove pending work; reject conflicting completion.

        The workflow chooses the outcome. Identical repeat completion is harmless;
        a missing pending record cannot be completed for the first time. Serialization
        or storage failure aborts the whole transaction, leaving pending recoverable.
        """
        key = result.associationSaid.encode()
        with self.env.begin(write=True) as txn:
            existing = txn.get(key, db=self.results.sdb)
            if existing is not None:
                if self.results.deserializer(existing) != result:
                    raise ValueError("conflicting verification result")
                return
            if txn.get(key, db=self.pending.sdb) is None:
                raise ValueError("pending work is absent")
            txn.put(key, self.results.serializer(result), db=self.results.sdb)
            txn.delete(key, db=self.pending.sdb)

    def pending_batch(self, *, after="", limit=32):
        """Copy a bounded page strictly after the SAID; close its cursor before returning."""
        with self.env.begin(db=self.pending.sdb) as txn:
            with txn.cursor() as cursor:
                if not cursor.set_range(after.encode()):
                    return []
                if after and cursor.key() == after.encode():
                    if not cursor.next():
                        return []
                return [
                    self.pending.deserializer(raw)
                    for _, raw in islice(cursor.iternext(), limit)
                ]

    def claim_message(self, peer, nonce, expires):
        """Insert a peer/nonce replay claim once, after authentication; return False on replay."""
        return self.messages.put(keys=(peer, nonce), val=MessageReceipt(expires))
