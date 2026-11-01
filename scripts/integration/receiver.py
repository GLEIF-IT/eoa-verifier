"""Focused durable webhook receiver. No association selection or contract effects."""

import argparse
import json
import signal
from pathlib import Path
from urllib.parse import urlsplit

import falcon
from hio.base import doing
from hio.core import http
from keri.app import habbing
from keri.db import subing

from eoa_verifier.delivery.authing import AuthenticationError, ServiceAuthenticator
from eoa_verifier.delivery.keys import ServiceKeys


class StatusEventStore:
    """Borrow a KERIpy database for durable fixture status events and replay claims."""

    def __init__(self, db):
        """Bind disjoint non-duplicate event, attempt and control subdatabases."""
        self.events = subing.Suber(db=db, subkey="fixture.events.")
        self.replays = subing.Suber(db=db, subkey="fixture.replays.")
        self.attempts = subing.Suber(db=db, subkey="fixture.attempts.")
        self.control = subing.Suber(db=db, subkey="fixture.control.")

    def claim_nonce(self, peer, nonce, expires_at):
        """Use LMDB no-overwrite insertion for one authentication replay claim."""
        return self.replays.put(keys=(peer, nonce), val=str(expires_at))

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

    def __init__(self, auth, status_event_service, target, *, drop_ack=None):
        """Borrow authentication/status-event operations and an optional post-commit fault."""
        self.auth, self.status_event_service, self.target, self.drop_ack = (
            auth,
            status_event_service,
            target,
            drop_ack,
        )

    def on_post(self, req, rep):
        """Commit immutable event bytes before signing an attempt-bound ACK."""
        parsed = urlsplit(self.target)
        relative = parsed.path + ("?" + parsed.query if parsed.query else "")
        if req.relative_uri != relative:
            raise falcon.HTTPBadRequest(description="unexpected signed target")
        statusEventBytes = req.bounded_stream.read()
        try:
            requestAuth = self.auth.verify(
                method="POST",
                target=self.target,
                action="status",
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
        headers, _ = self.auth.sign(
            method="POST",
            target=self.target,
            action="ack",
            body=ackBytes,
            request=requestAuth.reference,
            status=200,
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
        hby.psr.parse(ims=bytearray((root / "verifier.cesr").read_bytes()))
        store = StatusEventStore(hby.db)
        auth = ServiceAuthenticator(
            keys=ServiceKeys(hab),
            claim_nonce=store.claim_nonce,
            peer_aid=config["verifierAid"],
        )
        app = falcon.App()
        app.add_route(
            "/hook",
            Receiver(
                auth,
                StatusEventService(store),
                config["webhookUrl"],
                drop_ack=store.drop_ack_once if config["dropAck"] else None,
            ),
        )
        server = http.Server(host="127.0.0.1", port=config["receiverPort"], app=app)
        doing.Doist(real=True, tock=0.01).do(doers=[http.ServerDoer(server=server)])


def shutdown(signum, frame):
    """Unwind the receiver context and scheduler on owned termination."""
    raise KeyboardInterrupt


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, shutdown)
    try:
        main()
    except KeyboardInterrupt:
        pass
