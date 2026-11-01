"""Focused durable webhook receiver. No association selection or contract effects."""

import argparse
import json
import signal
from pathlib import Path
from urllib.parse import urlsplit

import falcon
from hio.base import doing
from hio.core import http
from keri.app import habbing, oobiing
from keri.db import basing, subing
from keri.end import ending
from keri.help import helping

from eoa_verifier.delivery.authing import AuthenticationError, HttpSignatures
from eoa_verifier.delivery.keys import ServiceKeys
from eoa_verifier.runtime.oobing import OobiClienter


class StatusEventStore:
    """Borrow a KERIpy database for durable fixture status events."""

    def __init__(self, db):
        """Bind disjoint non-duplicate event, attempt and control subdatabases."""
        # Event ID -> exact UTF-8 JSON body; retain bytes for duplicate/conflict checks.
        self.events = subing.Suber(db=db, subkey="fixture.events.")
        # Event ID -> decimal authenticated attempt count, committed with event bytes.
        self.attempts = subing.Suber(db=db, subkey="fixture.attempts.")
        # "dropped" -> "true": persistent sentinel for one deliberate post-commit ACK loss.
        self.control = subing.Suber(db=db, subkey="fixture.control.")

    def event_json(self, event_id):
        """Return the retained status-event JSON string for one event ID."""
        return self.events.get(keys=(event_id,))

    def attempt_count(self, event_id):
        """Read the number of authenticated delivery attempts already committed."""
        return int(self.attempts.get(keys=(event_id,)) or "0")

    def record_event(self, event_id, statusEventJson, count, previousJson):
        """Commit prepared immutable event bytes and the attempt count together."""
        key, raw, count_raw = (
            event_id.encode(),
            statusEventJson.encode(),
            str(count).encode(),
        )
        expected = previousJson.encode() if previousJson is not None else None
        with self.events.db.env.begin(write=True) as txn:
            if txn.get(key, db=self.events.sdb) != expected:
                raise StatusEventConflict("status event changed before save")
            txn.put(key, raw, db=self.events.sdb, overwrite=False)
            txn.put(key, count_raw, db=self.attempts.sdb)

    def stored_events(self):
        """Detach fixture diagnostics before HTTP response construction."""
        storedEvents = []
        with (
            self.events.db.env.begin() as txn,
            txn.cursor(db=self.events.sdb) as cursor,
        ):
            for key, raw in cursor:
                storedEvents.append(
                    {
                        "eventId": bytes(key).decode(),
                        "body": bytes(raw).decode(),
                        "attempts": int(
                            txn.get(bytes(key), db=self.attempts.sdb) or b"0"
                        ),
                    }
                )
        return storedEvents

    def drop_ack_once(self):
        """Persist the fixture's deliberate first-ACK loss, separately from status-event commit."""
        return self.control.put(keys=("dropped",), val="true")


class StatusEventConflict(ValueError):
    """An event ID was reused with different bytes or changed during storage."""


class StatusEventService:
    """Apply the fixture's narrow immutable status-event storage operation."""

    def __init__(self, store):
        """Borrow status-event storage; authentication and ACK fault injection stay outside."""
        self.store = store

    def receive(self, statusEventBytes):
        """Validate one event ID, persist identical bytes/count, and return its ID."""
        try:
            statusEvent = json.loads(statusEventBytes)
            event_id = statusEvent["eventId"]
            if not isinstance(event_id, str) or not event_id:
                raise ValueError("missing event ID")
            statusEventJson = statusEventBytes.decode()
        except (ValueError, KeyError, TypeError) as exc:
            raise ValueError("invalid fixture event") from exc
        previousJson = self.store.event_json(event_id)
        if previousJson is not None and previousJson != statusEventJson:
            raise StatusEventConflict("conflicting event bytes")
        count = self.store.attempt_count(event_id) + 1
        self.store.record_event(event_id, statusEventJson, count, previousJson)
        return event_id

    def stored_events(self):
        """Return detached diagnostics without changing stored events."""
        return self.store.stored_events()


class Receiver:
    """Authenticate exact producer bytes and acknowledge only durable status-event storage."""

    def __init__(
        self,
        auth,
        status_event_service,
        target,
        *,
        verifier_aid,
        producer_ready,
        drop_ack=None,
    ):
        """Borrow authentication/status-event operations and an optional post-commit fault."""
        self.verifier_aid, self.producer_ready = verifier_aid, producer_ready
        self.auth, self.status_event_service, self.target, self.drop_ack = (
            auth,
            status_event_service,
            target,
            drop_ack,
        )

    def on_post(self, req, rep):
        """Commit immutable event bytes before signing the storage response."""
        parsed = urlsplit(self.target)
        relative = parsed.path + ("?" + parsed.query if parsed.query else "")
        if req.relative_uri != relative:
            raise falcon.HTTPBadRequest(description="unexpected signed target")
        if not self.producer_ready():
            raise falcon.HTTPServiceUnavailable(
                description="producer OOBI is not ready", retry_after=1
            )
        statusEventBytes = req.bounded_stream.read()
        try:
            self.auth.verify(
                method="POST",
                expected_aid=self.verifier_aid,
                target=self.target,
                body=statusEventBytes,
                headers=req.headers,
            )
        except AuthenticationError as exc:
            raise falcon.HTTPUnauthorized(description=str(exc)) from exc
        try:
            event_id = self.status_event_service.receive(statusEventBytes)
        except StatusEventConflict as exc:
            raise falcon.HTTPConflict(description=str(exc)) from exc
        except ValueError as exc:
            raise falcon.HTTPBadRequest(description=str(exc)) from exc
        if self.drop_ack is not None and self.drop_ack():
            raise falcon.HTTPServiceUnavailable(
                description="fixture dropped post-commit ACK"
            )
        ackBytes = json.dumps({"eventId": event_id, "stored": True}).encode()
        headers = self.auth.sign(
            method="POST",
            target=self.target,
            body=ackBytes,
        )
        rep.data = ackBytes
        rep.set_headers(headers)

    def on_get(self, req, rep):
        """Expose retained status-event JSON strings and attempt counts for qualification."""
        rep.media = self.status_event_service.stored_events()


def main():
    """Own receiver Habery and HIO listener for one explicitly prepared run."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    args = parser.parse_args()
    root = Path(args.root)
    config = json.loads((root / "run.json").read_text())
    with habbing.openHby(
        name="receiver", headDirPath=str(root / "receiver"), temp=False
    ) as hby:
        hab = hby.habByName("receiver")
        url = config["verifierUrl"] + "/oobi/" + config["verifierAid"]
        hby.db.roobi.rem(keys=(url,))
        hby.db.oobis.pin(keys=(url,), val=basing.OobiRecord(date=helping.nowIso8601()))
        resolver = oobiing.Oobiery(hby=hby, clienter=OobiClienter())
        store = StatusEventStore(hby.db)
        auth = HttpSignatures(
            keys=ServiceKeys(hab),
        )
        app = falcon.App()
        app.add_route("/oobi/{aid}", ending.OOBIEnd(hby=hby))
        app.add_route(
            "/hook",
            Receiver(
                auth,
                StatusEventService(store),
                config["webhookUrl"],
                verifier_aid=config["verifierAid"],
                producer_ready=lambda: config["verifierAid"] in hby.kevers,
                drop_ack=store.drop_ack_once if config["dropAck"] else None,
            ),
        )
        server = http.Server(host="127.0.0.1", port=config["receiverPort"], app=app)
        doing.Doist(real=True, tock=0.01).do(
            doers=[http.ServerDoer(server=server), *resolver.doers]
        )


def shutdown(signum, frame):
    """Unwind the receiver context and scheduler on owned termination."""
    raise KeyboardInterrupt


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, shutdown)
    try:
        main()
    except KeyboardInterrupt:
        pass
