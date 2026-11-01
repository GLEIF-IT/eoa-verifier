"""Delivery persistence: bounded reads and explicit atomic writes."""

from .queues import first_record


class DeliveryReader:
    """Borrow the open store for delivery persistence only."""

    def __init__(self, baser):
        """Borrow the application's already-open store."""
        self._db = baser

    def delivery(self, event_id):
        """Return an immutable event and its current delivery progress."""
        return self._db.outbox.get(keys=(event_id,))

    def active_ref(self):
        """Read the sender's interrupted delivery reference."""
        return self._db.delivery_active.get(keys=("sender",))

    def ready_ref(self):
        """Read the ready delivery head without consuming it."""
        return first_record(self._db.delivery_ready)

    def dead_ref(self, event_id):
        """Read one identified delivery dead letter."""
        return self._db.delivery_dead.get(keys=(event_id,))

    def schedule(self, destination):
        """Return a detached destination pacing/backoff record."""
        return self._db.destinations.get(keys=(destination,))


class DeliveryWriter:
    """Borrow the open store for delivery persistence only."""

    def __init__(self, baser):
        """Borrow the application's already-open store."""
        self._db = baser

    def ready_to_active(self, reference):
        """Move the expected ready reference to the single active sender slot."""
        db = self._db
        key, raw = reference.eventId.encode(), db.delivery_ready.serializer(reference)
        active_raw = db.delivery_active.serializer(reference)
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.delivery_ready.sdb) != raw:
                raise ValueError("ready delivery changed")
            if txn.get(b"sender", db=db.delivery_active.sdb) is not None:
                raise ValueError("sender already has active delivery")
            txn.put(b"sender", active_raw, db=db.delivery_active.sdb)
            txn.delete(key, db=db.delivery_ready.sdb)

    def record_attempt(self, previous, delivery, schedule):
        """Persist charged outbox progress and request-start pacing before HTTP."""
        db = self._db
        key = delivery.eventId.encode()
        expected, raw = db.outbox.serializer(previous), db.outbox.serializer(delivery)
        schedule_key, schedule_raw = (
            delivery.destination.encode(),
            db.destinations.serializer(schedule),
        )
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.outbox.sdb) != expected:
                raise ValueError("delivery changed before completion")
            txn.put(key, raw, db=db.outbox.sdb)
            txn.put(schedule_key, schedule_raw, db=db.destinations.sdb)

    def defer(self, previous, delivery, schedule):
        """Persist retry progress and cooldown, retaining the active reference."""
        db = self._db
        key = delivery.eventId.encode()
        expected, raw = db.outbox.serializer(previous), db.outbox.serializer(delivery)
        schedule_key, schedule_raw = (
            delivery.destination.encode(),
            db.destinations.serializer(schedule),
        )
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.outbox.sdb) != expected:
                raise ValueError("delivery changed before completion")
            txn.put(key, raw, db=db.outbox.sdb)
            txn.put(schedule_key, schedule_raw, db=db.destinations.sdb)

    def ack(self, previous, delivery, schedule, reference):
        """Persist authenticated ACK progress and remove the matching ready/active references."""
        db = self._db
        key = delivery.eventId.encode()
        expected, raw = db.outbox.serializer(previous), db.outbox.serializer(delivery)
        schedule_key, schedule_raw = (
            delivery.destination.encode(),
            db.destinations.serializer(schedule),
        )
        active_raw = db.delivery_active.serializer(reference)
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.outbox.sdb) != expected:
                raise ValueError("delivery changed before completion")
            txn.put(key, raw, db=db.outbox.sdb)
            txn.put(schedule_key, schedule_raw, db=db.destinations.sdb)
            txn.delete(key, db=db.delivery_ready.sdb)
            if txn.get(b"sender", db=db.delivery_active.sdb) == active_raw:
                txn.delete(b"sender", db=db.delivery_active.sdb)

    def dead_letter(self, previous, delivery, schedule, reference):
        """Persist failed progress and move matching ready/active references to delivery_dead."""
        db = self._db
        key = delivery.eventId.encode()
        expected, raw = db.outbox.serializer(previous), db.outbox.serializer(delivery)
        schedule_key, schedule_raw = (
            delivery.destination.encode(),
            db.destinations.serializer(schedule),
        )
        active_raw = db.delivery_active.serializer(reference)
        dead_raw = db.delivery_dead.serializer(reference)
        with db.env.begin(write=True) as txn:
            if txn.get(key, db=db.outbox.sdb) != expected:
                raise ValueError("delivery changed before completion")
            txn.put(key, raw, db=db.outbox.sdb)
            txn.put(schedule_key, schedule_raw, db=db.destinations.sdb)
            txn.delete(key, db=db.delivery_ready.sdb)
            if txn.get(b"sender", db=db.delivery_active.sdb) == active_raw:
                txn.delete(b"sender", db=db.delivery_active.sdb)
            txn.put(key, dead_raw, db=db.delivery_dead.sdb)

    def dead_to_ready(self, previous, delivery, reference):
        """Save a prepared reset and move its expected dead reference back to ready."""
        db = self._db
        key, raw = delivery.eventId.encode(), db.outbox.serializer(delivery)
        expected = db.outbox.serializer(previous)
        dead_raw = db.delivery_dead.serializer(reference)
        ready_raw = db.delivery_ready.serializer(reference)
        with db.env.begin(write=True) as txn:
            if (
                txn.get(key, db=db.delivery_dead.sdb) != dead_raw
                or txn.get(key, db=db.outbox.sdb) != expected
            ):
                raise ValueError("dead-letter delivery changed")
            txn.put(key, raw, db=db.outbox.sdb)
            txn.put(key, ready_raw, db=db.delivery_ready.sdb)
            txn.delete(key, db=db.delivery_dead.sdb)
