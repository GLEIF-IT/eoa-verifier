"""Verification persistence: bounded reads and explicit atomic writes."""

from .queues import due_key, due_record, first_record


class VerificationReader:
    """Borrow the open store for verification persistence only."""

    def __init__(self, baser):
        """Borrow the application's already-open store."""
        self._db = baser

    def verifying(self, cred_said=None):
        """Return one identified verifying record or the interrupted phase head."""
        return (
            self._db.verifying.get(keys=(cred_said,))
            if cred_said is not None
            else first_record(self._db.verifying)
        )

    def waiting(self, cred_said=None):
        """Return one waiting record or the earliest indexed retry, even if future."""
        return (
            self._db.waiting.get(keys=(cred_said,))
            if cred_said is not None
            else due_record(self._db.verification_due, self._db.waiting)
        )

    def pending(self, cred_said=None):
        """Return one pending record or the queue head."""
        return (
            self._db.pending.get(keys=(cred_said,))
            if cred_said is not None
            else first_record(self._db.pending)
        )

    def dead(self, cred_said):
        """Return an identified verification dead letter."""
        return self._db.verification_dead.get(keys=(cred_said,))

    def result(self, cred_said):
        """Return the immutable result for one candidate."""
        return self._db.results.get(keys=(cred_said,))

    def progress(self, cred_said):
        """Read the stored phase of one candidate without scheduling work."""
        for phase, record in (
            ("pending", self.pending(cred_said)),
            ("verifying", self.verifying(cred_said)),
            ("waiting", self.waiting(cred_said)),
            ("dead-letter", self.dead(cred_said)),
        ):
            if record is not None:
                return phase, record
        return None, None


class VerificationWriter:
    """Borrow the open store for verification persistence only."""

    def __init__(self, baser):
        """Borrow the application's already-open store."""
        self._db = baser

    def pending_to_verifying(self, previous, record):
        """Move pending to verifying with a prepared charged attempt."""
        db = self._db
        key = record.associationSaid.encode()
        expected = db.pending.serializer(previous)
        raw = db.verifying.serializer(record)
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.pending.sdb) != expected:
                raise ValueError("verification source is absent or changed")
            txn.delete(key, db=db.pending.sdb)
            txn.put(key, raw, db=db.verifying.sdb)

    def resume_verifying(self, previous, record):
        """Replace interrupted verifying work with its prepared next attempt."""
        db = self._db
        key = record.associationSaid.encode()
        expected = db.verifying.serializer(previous)
        raw = db.verifying.serializer(record)
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.verifying.sdb) != expected:
                raise ValueError("verification source is absent or changed")
            txn.put(key, raw, db=db.verifying.sdb)

    def waiting_to_verifying(self, previous, record):
        """Move waiting to verifying and remove its due index."""
        db = self._db
        key = record.associationSaid.encode()
        expected = db.waiting.serializer(previous)
        raw = db.verifying.serializer(record)
        old_due = due_key(previous.nextAttemptAt, previous.associationSaid)
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.waiting.sdb) != expected:
                raise ValueError("verification source is absent or changed")
            txn.delete(key, db=db.waiting.sdb)
            txn.delete(old_due, db=db.verification_due.sdb)
            txn.put(key, raw, db=db.verifying.sdb)

    def verifying_to_waiting(self, previous, record):
        """Move verifying to waiting with a prepared retry deadline."""
        db = self._db
        key = record.associationSaid.encode()
        expected = db.verifying.serializer(previous)
        raw = db.waiting.serializer(record)
        new_due = due_key(record.nextAttemptAt, record.associationSaid)
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.verifying.sdb) != expected:
                raise ValueError("verification source is absent or changed")
            txn.delete(key, db=db.verifying.sdb)
            txn.put(key, raw, db=db.waiting.sdb)
            txn.put(new_due, key, db=db.verification_due.sdb)

    def verifying_to_dead(self, previous, record):
        """Move failed or interrupted verifying work to verification_dead."""
        db = self._db
        key = record.associationSaid.encode()
        expected = db.verifying.serializer(previous)
        raw = db.verification_dead.serializer(record)
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.verifying.sdb) != expected:
                raise ValueError("verification source is absent or changed")
            txn.delete(key, db=db.verifying.sdb)
            txn.put(key, raw, db=db.verification_dead.sdb)

    def waiting_to_dead(self, previous, record):
        """Move exhausted waiting work to verification_dead and remove its deadline."""
        db = self._db
        key = record.associationSaid.encode()
        expected = db.waiting.serializer(previous)
        raw = db.verification_dead.serializer(record)
        old_due = due_key(previous.nextAttemptAt, previous.associationSaid)
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.waiting.sdb) != expected:
                raise ValueError("verification source is absent or changed")
            txn.delete(key, db=db.waiting.sdb)
            txn.delete(old_due, db=db.verification_due.sdb)
            txn.put(key, raw, db=db.verification_dead.sdb)

    def dead_to_pending(self, previous, record):
        """Move corrected verification_dead work to pending with a reset budget."""
        db = self._db
        key = record.associationSaid.encode()
        expected = db.verification_dead.serializer(previous)
        raw = db.pending.serializer(record)
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.verification_dead.sdb) != expected:
                raise ValueError("verification source is absent or changed")
            txn.delete(key, db=db.verification_dead.sdb)
            txn.put(key, raw, db=db.pending.sdb)

    def complete_verified(self, result):
        """Commit result and acceptance obligation and remove verifying work atomically."""
        db = self._db
        key, raw = result.associationSaid.encode(), db.results.serializer(result)
        acceptance_raw = db.accepting.serializer(result)
        with db.env.begin(write=True) as txn:
            existing = txn.get(key, db=db.results.sdb)
            if existing is not None:
                if existing != raw:
                    raise ValueError("conflicting verification result")
                return
            if txn.get(key, db=db.verifying.sdb) is None:
                raise ValueError("active verification is absent")
            txn.put(key, raw, db=db.results.sdb)
            txn.put(key, acceptance_raw, db=db.accepting.sdb)
            txn.delete(key, db=db.verifying.sdb)

    def complete_rejected(self, result):
        """Commit rejected result and remove verifying work atomically."""
        db = self._db
        key, raw = result.associationSaid.encode(), db.results.serializer(result)
        with db.env.begin(write=True) as txn:
            existing = txn.get(key, db=db.results.sdb)
            if existing is not None:
                if existing != raw:
                    raise ValueError("conflicting verification result")
                return
            if txn.get(key, db=db.verifying.sdb) is None:
                raise ValueError("active verification is absent")
            txn.put(key, raw, db=db.results.sdb)
            txn.delete(key, db=db.verifying.sdb)
