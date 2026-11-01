"""Bounded, detached application reads; no query consumes or schedules work."""


def first_record(table):
    """Copy and decode a phase head before closing its short-lived reader."""
    with table.db.env.begin(db=table.sdb) as txn, txn.cursor() as cursor:
        return table.deserializer(bytes(cursor.value())) if cursor.first() else None


def due_record(schedule, waiting):
    """Return the earliest waiting record without applying clock policy or deleting it."""
    with schedule.db.env.begin() as txn, txn.cursor(db=schedule.sdb) as cursor:
        if not cursor.first():
            return None
        record = waiting.deserializer(txn.get(bytes(cursor.value()), db=waiting.sdb))
    if record is None:
        raise ValueError("retry schedule has no waiting work")
    return record


class ApplicationReader:
    """Expose detached records to services while keeping LMDB handles private."""

    def __init__(self, baser):
        """Borrow the application's already-open store."""
        self._db = baser

    def active_grant(self):
        """Return the receiver's interrupted Grant, if any."""
        return self._db.grant_active.get(keys=("receiver",))

    def waiting_grant(self):
        """Return the earliest indexed Grant, including one whose deadline is future."""
        return due_record(self._db.grant_due, self._db.grant_waiting)

    def dead_grant(self, notice_id):
        """Return one identified Grant dead letter."""
        return self._db.grant_dead.get(keys=(notice_id,))

    def verification(self, phase, cred_said=None):
        """Return a point record or phase head; waiting heads follow the due index."""
        tables = {
            "pending": self._db.pending,
            "verifying": self._db.verifying,
            "waiting": self._db.waiting,
            "dead-letter": self._db.verification_dead,
        }
        table = tables[phase]
        if cred_said is not None:
            return table.get(keys=(cred_said,))
        if phase == "waiting":
            return due_record(self._db.verification_due, table)
        return first_record(table)

    def verification_result(self, cred_said):
        """Return the immutable result for one candidate."""
        return self._db.results.get(keys=(cred_said,))

    def verification_progress(self, cred_said):
        """Read the stored phase of one candidate without scheduling work."""
        for phase in ("pending", "verifying", "waiting", "dead-letter"):
            record = self.verification(phase, cred_said)
            if record is not None:
                return phase, record
        return None, None

    def acceptance(self, cred_said=None, *, dead=False):
        """Return one identified acceptance or its active phase head."""
        table = self._db.acceptance_dead if dead else self._db.accepting
        return table.get(keys=(cred_said,)) if cred_said else first_record(table)

    def association(self, cred_said):
        """Return detached accepted/rejected/revoked application status."""
        return self._db.associations.get(keys=(cred_said,))

    def delivery(self, event_id):
        """Return an immutable event and its current delivery progress."""
        return self._db.outbox.get(keys=(event_id,))

    def nonce_claim(self, issuer, nonce):
        """Read a claim by canonical key; consistency with its owner is service policy."""
        from .keys import nonce_key

        key = nonce_key(issuer, nonce)
        with self._db.env.begin() as txn:
            return self._db.accepted_nonces.deserializer(
                txn.get(key, db=self._db.accepted_nonces.sdb)
            )

    def nonce_page(self, after=None, limit=128):
        """Detach at most limit historical claims; never yield with a reader open."""
        return record_page(self._db.accepted_nonces, after, limit)

    def association_page(self, after=None, limit=128):
        """Detach a bounded historical status page for the stopped-service audit."""
        return record_page(self._db.associations, after, limit)

    def scope(self):
        """Read the persisted trust/network policy binding."""
        return self._db.scope.get(keys=("verification",))

    def has_history(self):
        """Check history existence from heads, without counting every stored record."""
        return any(
            first_record(table) is not None
            for table in (self._db.results, self._db.associations, self._db.outbox)
        )


def record_page(table, after, limit):
    """Copy bounded key/record pairs and release the cursor before returning."""
    records = []
    with table.db.env.begin(db=table.sdb) as txn, txn.cursor() as cursor:
        found = cursor.first() if after is None else cursor.set_range(after)
        if found and after is not None and bytes(cursor.key()) == after:
            found = cursor.next()
        while found and len(records) < limit:
            records.append(
                (bytes(cursor.key()), table.deserializer(bytes(cursor.value())))
            )
            found = cursor.next()
    return records
