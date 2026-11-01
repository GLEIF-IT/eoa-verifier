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

    def active_verification(self, cred_said=None):
        """Return one identified verifying record or the interrupted phase head."""
        return (
            self._db.verifying.get(keys=(cred_said,))
            if cred_said is not None
            else first_record(self._db.verifying)
        )

    def waiting_verification(self, cred_said=None):
        """Return one waiting record or the earliest indexed retry, even if future."""
        return (
            self._db.waiting.get(keys=(cred_said,))
            if cred_said is not None
            else due_record(self._db.verification_due, self._db.waiting)
        )

    def pending_verification(self, cred_said=None):
        """Return one pending record or the queue head."""
        return (
            self._db.pending.get(keys=(cred_said,))
            if cred_said is not None
            else first_record(self._db.pending)
        )

    def dead_verification(self, cred_said):
        """Return an identified verification dead letter."""
        return self._db.verification_dead.get(keys=(cred_said,))

    def verification_result(self, cred_said):
        """Return the immutable result for one candidate."""
        return self._db.results.get(keys=(cred_said,))

    def verification_progress(self, cred_said):
        """Read the stored phase of one candidate without scheduling work."""
        for phase, record in (
            ("pending", self.pending_verification(cred_said)),
            ("verifying", self.active_verification(cred_said)),
            ("waiting", self.waiting_verification(cred_said)),
            ("dead-letter", self.dead_verification(cred_said)),
        ):
            if record is not None:
                return phase, record
        return None, None

    def acceptance(self, cred_said=None):
        """Return an identified accepting record or the phase head."""
        return (
            self._db.accepting.get(keys=(cred_said,))
            if cred_said is not None
            else first_record(self._db.accepting)
        )

    def dead_acceptance(self, cred_said):
        """Return one acceptance dead letter."""
        return self._db.acceptance_dead.get(keys=(cred_said,))

    def association(self, cred_said):
        """Return detached accepted/rejected/revoked application status."""
        return self._db.associations.get(keys=(cred_said,))

    def delivery(self, event_id):
        """Return an immutable event and its current delivery progress."""
        return self._db.outbox.get(keys=(event_id,))

    def scope(self):
        """Read the persisted trust/network policy binding."""
        return self._db.scope.get(keys=("verification",))

    def has_history(self):
        """Check history existence from heads, without counting every stored record."""
        return any(
            first_record(table) is not None
            for table in (self._db.results, self._db.associations, self._db.outbox)
        )

    def active_delivery_reference(self):
        """Read the sender's interrupted delivery reference."""
        return self._db.delivery_active.get(keys=("sender",))

    def ready_delivery_reference(self):
        """Read the ready delivery head without consuming it."""
        return first_record(self._db.delivery_ready)

    def dead_delivery_reference(self, event_id):
        """Read one identified delivery dead letter."""
        return self._db.delivery_dead.get(keys=(event_id,))

    def destination_schedule(self, destination):
        """Return a detached destination pacing/backoff record."""
        return self._db.destinations.get(keys=(destination,))
