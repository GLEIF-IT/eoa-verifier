"""Associations persistence: bounded reads and explicit atomic writes."""

from .queues import first_record


class NonceConflict(Exception):
    """Another acceptance owns the permanent nonce; the write set was aborted."""


class AssociationReader:
    """Read detached associations records from a borrowed, open VerifierBaser.

    Point reads and phase-head reads close their LMDB readers before returning.
    Missing point keys return None. No read claims work, applies retry policy or
    keeps a transaction alive while the caller makes a decision.
    """

    def __init__(self, baser):
        """Borrow the application's already-open store."""
        self._db = baser

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


class AssociationWriter:
    """Persist prepared associations records through explicit atomic transitions.

    The caller selects the outcome and supplies typed records before entry. Each
    operation serializes its write set before opening one short write transaction;
    no network I/O or scheduler yield occurs inside it. Methods taking previous
    compare that expected record with stored bytes and raise ValueError on a
    changed/missing source, aborting the write set. The caller owns the open store.
    """

    def __init__(self, baser):
        """Borrow the application's already-open store."""
        self._db = baser

    def acceptance_to_dead(self, previous, record):
        """Move accepting to acceptance_dead with a prepared diagnostic."""
        db = self._db
        key = record.associationSaid.encode()
        expected = db.accepting.serializer(previous)
        raw = db.acceptance_dead.serializer(record)
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.accepting.sdb) != expected:
                raise ValueError("acceptance source is absent or changed")
            txn.delete(key, db=db.accepting.sdb)
            txn.put(key, raw, db=db.acceptance_dead.sdb)

    def dead_to_acceptance(self, previous, record):
        """Move corrected acceptance_dead back to accepting."""
        db = self._db
        key = record.associationSaid.encode()
        expected = db.acceptance_dead.serializer(previous)
        raw = db.accepting.serializer(record)
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.acceptance_dead.sdb) != expected:
                raise ValueError("acceptance source is absent or changed")
            txn.delete(key, db=db.acceptance_dead.sdb)
            txn.put(key, raw, db=db.accepting.sdb)

    def accept(self, status, nonce):
        """Commit nonce ownership and accepted status without delivery.

        False means this SAID already has status. NonceConflict aborts all writes.
        """
        from .keys import nonce_key
        from .records import AcceptedNonce

        db = self._db
        key, raw = status.associationSaid.encode(), db.associations.serializer(status)
        claim_key = nonce_key(nonce)
        claim_raw = db.accepted_nonces.serializer(AcceptedNonce(status.associationSaid))
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.associations.sdb) is not None:
                return False
            if not txn.put(
                claim_key, claim_raw, db=db.accepted_nonces.sdb, overwrite=False
            ):
                raise NonceConflict()
            txn.put(key, raw, db=db.associations.sdb)
            txn.delete(key, db=db.accepting.sdb)
        return True

    def accept_and_queue(self, status, nonce, delivery, reference, schedule):
        """Commit nonce ownership and accepted status with its ready event.

        False means this SAID already has status. NonceConflict aborts all writes.
        """
        from .keys import nonce_key
        from .records import AcceptedNonce

        db = self._db
        key, raw = status.associationSaid.encode(), db.associations.serializer(status)
        claim_key = nonce_key(nonce)
        claim_raw = db.accepted_nonces.serializer(AcceptedNonce(status.associationSaid))
        event_key, event_raw = delivery.eventId.encode(), db.outbox.serializer(delivery)
        ref_raw = db.delivery_ready.serializer(reference)
        schedule_key, schedule_raw = (
            delivery.destination.encode(),
            db.destinations.serializer(schedule),
        )
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.associations.sdb) is not None:
                return False
            if not txn.put(
                claim_key, claim_raw, db=db.accepted_nonces.sdb, overwrite=False
            ):
                raise NonceConflict()
            txn.put(key, raw, db=db.associations.sdb)
            txn.put(event_key, event_raw, db=db.outbox.sdb)
            txn.put(event_key, ref_raw, db=db.delivery_ready.sdb)
            txn.put(schedule_key, schedule_raw, db=db.destinations.sdb, overwrite=False)
            txn.delete(key, db=db.accepting.sdb)
        return True

    def reject_nonce(self, status):
        """Save nonce-reuse rejection and remove accepting; never write a nonce or event."""
        db = self._db
        key, raw = status.associationSaid.encode(), db.associations.serializer(status)
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.associations.sdb) is not None:
                return False
            txn.put(key, raw, db=db.associations.sdb)
            txn.delete(key, db=db.accepting.sdb)
        return True

    def rev(self, previous, status):
        """Replace accepted status with revoked status without delivery."""
        db = self._db
        key = status.associationSaid.encode()
        expected, raw = (
            db.associations.serializer(previous),
            db.associations.serializer(status),
        )
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.associations.sdb) != expected:
                raise ValueError("association changed before revocation")
            txn.put(key, raw, db=db.associations.sdb)

    def rev_and_queue(self, previous, status, delivery, reference):
        """Replace accepted status with revoked status and its ready revocation event."""
        db = self._db
        key = status.associationSaid.encode()
        expected, raw = (
            db.associations.serializer(previous),
            db.associations.serializer(status),
        )
        event_key, event_raw = delivery.eventId.encode(), db.outbox.serializer(delivery)
        ref_raw = db.delivery_ready.serializer(reference)
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.associations.sdb) != expected:
                raise ValueError("association changed before revocation")
            txn.put(key, raw, db=db.associations.sdb)
            txn.put(event_key, event_raw, db=db.outbox.sdb)
            txn.put(event_key, ref_raw, db=db.delivery_ready.sdb)
