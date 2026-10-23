"""Persist initial verification progress independently of native evidence."""

from dataclasses import dataclass
from itertools import islice

from keri.db import dbing, koming

# Unfinished: required locally accepted native evidence is missing.
STATE_AWAITING_ARTIFACTS = "awaiting_artifacts"
# Unfinished: ready, in flight, or waiting to retry an initial RPC observation.
STATE_VERIFYING = "verifying"
# Terminal initial-check success; not application acceptance or endorsement.
STATE_VERIFIED = "verified"
# Terminal initial-check rejection based on available evidence.
STATE_FAILED = "failed"


@dataclass
class VerificationWork:
    """Persisted initial-verification progress, keyed by association ACDC SAID.

    This is not native evidence or application acceptance. In particular, verified
    means initial checks completed; it does not imply outbox delivery or endorsement.
    The record deliberately does not store the worker's account observation.
    """

    # Exact ACDC SAID; the sole work-table key.
    associationSaid: str
    # One of the persisted state strings above; no time-based validity implied.
    state: str = STATE_VERIFYING
    # First native Grant EXN SAID, used to recover immutable candidate bytes.
    grantSaid: str = ""
    # Last rejection or waiting reason; cleared on successful completion.
    failureReason: str = ""


@dataclass
class MessageReceipt:
    """Durable transport nonce claim, independent of application-event deduplication."""

    expires: int  # Signed UTC expiry; a claim does not establish application success.


class VerifierBaser(dbing.LMDBer):
    """Own initial work and transport replay records alongside native KERI stores.

    Rows survive restart and are rediscovered by the coordinator. Except for the
    completion guard, transition methods trust their caller's selection of work;
    this class does not enforce a general state machine.
    """

    # Primary relative store path under the native configured root.
    TailDirPath = "eoa-verifier/db"
    # Native fallback relative path when the primary root is unavailable.
    AltTailDirPath = ".eoa-verifier/db"
    # Prefix for native disposable store directories.
    TempPrefix = "eoa_verifier_db_"

    def reopen(self, **kwa):
        """Open the LMDB environment and its SAID-keyed work table; return the environment."""
        super().reopen(**kwa)
        # Komer serializes VerificationWork rows under one association-SAID key.
        self.verifications = koming.Komer(
            db=self, subkey="verification.", schema=VerificationWork
        )
        # Insert-only peer/attempt claims; independent of event acceptance.
        self.messages = koming.Komer(db=self, subkey="message.", schema=MessageReceipt)
        return self.env

    def get_verification(self, said):
        """Return a deserialized work record for the exact association SAID, or None."""
        return self.verifications.get(keys=(said,))

    def _pin_verification(self, work):
        """Insert or replace the row keyed by work.associationSaid; return the same object."""
        self.verifications.pin(keys=(work.associationSaid,), val=work)
        return work

    def start_verification(self, *, association_said, grant_said):
        """Return existing work unchanged, or insert a verifying record for a new SAID.

        Duplicate Grants retain the first grantSaid, progress and failure reason,
        including terminal states. Neither candidate bytes nor evidence are stored here.
        """
        existing = self.get_verification(association_said)
        return (
            existing
            if existing is not None
            else self._pin_verification(
                VerificationWork(associationSaid=association_said, grantSaid=grant_said)
            )
        )

    def complete_verification(self, work):
        """Reload and complete a stored verifying record, clearing its failure reason.

        Raise ValueError for missing or non-verifying work. Return None; the supplied
        object is used only for its SAID and is not mutated.
        """
        current = self.get_verification(work.associationSaid)
        if current is None or current.state != STATE_VERIFYING:
            raise ValueError("only unfinished verification can complete")
        current.state, current.failureReason = STATE_VERIFIED, ""
        self._pin_verification(current)

    def mark_verifying(self, work, reason=""):
        """Mutate work to verifying with the supplied reason, replace its row and return it."""
        work.state, work.failureReason = STATE_VERIFYING, reason
        return self._pin_verification(work)

    def mark_awaiting_artifacts(self, work, reason):
        """Mutate and persist missing-evidence status only if state or reason changed.

        Return the supplied work object. The caller must select unfinished work;
        this method itself does not reject a terminal input.
        """
        if work.state != STATE_AWAITING_ARTIFACTS or work.failureReason != reason:
            work.state, work.failureReason = STATE_AWAITING_ARTIFACTS, reason
            self._pin_verification(work)
        return work

    def mark_failed(self, work, reason):
        """Mutate work to failed with the reason, replace its row and return it."""
        work.state, work.failureReason = STATE_FAILED, reason
        return self._pin_verification(work)

    def verification_batch(self, *, after="", limit=32):
        """Return at most limit records in key order, strictly after the supplied SAID.

        An empty after starts at the first key; an empty result means the caller may
        wrap on its next turn. limit must be a nonnegative integer. Include terminal
        rows so examination is bounded even with a long history. The transaction and
        cursor close before return, allowing mutations and HIO yields between pages.
        """
        with self.env.begin(db=self.verifications.sdb) as txn:
            with txn.cursor() as cursor:
                if not cursor.set_range(after.encode()):
                    return []
                if after and cursor.key() == after.encode():
                    if not cursor.next():
                        return []
                return [
                    self.verifications.deserializer(raw)
                    for _, raw in islice(cursor.iternext(), limit)
                ]

    def claim_message(self, peer, nonce, expires):
        """Insert a peer/nonce replay claim once; return False if already recorded.

        Call only after authentication. Native put is insert-only and persists
        across restart. Application retries use fresh nonces and stable event IDs.
        """
        return self.messages.put(keys=(peer, nonce), val=MessageReceipt(expires))
