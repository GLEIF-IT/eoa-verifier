"""Explicit fixture preparation through the production Grant completion boundary."""

from eoa_verifier.persistence.grants import GrantWriter
from eoa_verifier.persistence.records import GrantReplayRecord


def enqueue_verification(baser, verification):
    """Prepare an active fixture Grant and complete it using the real atomic writer.

    Return whether this call inserted pending work. Duplicate assertions observe
    the actual result, not a copy of production deduplication rules.
    """
    key = (verification.associationSaid,)
    previous = baser.pending.get(keys=key)
    record = GrantReplayRecord(f"fixture-{verification.associationSaid}", {})
    writer = GrantWriter(baser)
    writer.start(record)
    writer.complete(record, verification)
    return previous is None and baser.pending.get(keys=key) == verification
