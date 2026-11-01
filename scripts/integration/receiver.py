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


class ReceiptStore:
    """Borrow a KERIpy database for durable fixture receipts and replay claims."""

    def __init__(self, db):
        """Bind disjoint non-duplicate receipt, attempt and control subdatabases."""
        self.events = subing.Suber(db=db, subkey="fixture.events.")
        self.replays = subing.Suber(db=db, subkey="fixture.replays.")
        self.attempts = subing.Suber(db=db, subkey="fixture.attempts.")
        self.control = subing.Suber(db=db, subkey="fixture.control.")

    def claim_nonce(self, peer, nonce, expires_at):
        """Use LMDB no-overwrite insertion for one authentication replay claim."""
        return self.replays.put(keys=(peer, nonce), val=str(expires_at))

    def receipt(self, event_id):
        """Return exact retained bytes as text for one event ID."""
        return self.events.get(keys=(event_id,))

    def attempt_count(self, event_id):
        """Read the number of authenticated receipt attempts already committed."""
        return int(self.attempts.get(keys=(event_id,)) or "0")

    def save_receipt(self, event_id, text, count, previous):
        """Commit prepared immutable event bytes and the attempt count together."""
        key, raw, count_raw = event_id.encode(), text.encode(), str(count).encode()
        expected = previous.encode() if previous is not None else None
        with self.events.db.env.begin(write=True) as txn:
            if txn.get(key, db=self.events.sdb) != expected:
                raise ReceiptConflict("receipt changed before save")
            txn.put(key, raw, db=self.events.sdb, overwrite=False)
            txn.put(key, count_raw, db=self.attempts.sdb)

    def receipts(self):
        """Detach fixture diagnostics before HTTP response construction."""
        rows = []
        with (
            self.events.db.env.begin() as txn,
            txn.cursor(db=self.events.sdb) as cursor,
        ):
            for key, raw in cursor:
                rows.append(
                    {
                        "eventId": bytes(key).decode(),
                        "body": bytes(raw).decode(),
                        "attempts": int(
                            txn.get(bytes(key), db=self.attempts.sdb) or b"0"
                        ),
                    }
                )
        return rows

    def drop_ack_once(self):
        """Persist the fixture's deliberate first-ACK loss, separately from receipt commit."""
        return self.control.put(keys=("dropped",), val="true")


class ReceiptConflict(ValueError):
    """An event ID was reused with different bytes or changed during receipt."""


class ReceiptService:
    """Apply the fixture's narrow immutable-event receipt operation."""

    def __init__(self, store):
        """Borrow receipt storage; authentication and ACK fault injection stay outside."""
        self.store = store

    def receive(self, body):
        """Validate one event ID, persist identical bytes/count, and return its ID."""
        try:
            payload = json.loads(body)
            event_id = payload["eventId"]
            if not isinstance(event_id, str) or not event_id:
                raise ValueError("missing event ID")
            text = body.decode()
        except (ValueError, KeyError, TypeError) as exc:
            raise ValueError("invalid fixture event") from exc
        previous = self.store.receipt(event_id)
        if previous is not None and previous != text:
            raise ReceiptConflict("conflicting event bytes")
        count = self.store.attempt_count(event_id) + 1
        self.store.save_receipt(event_id, text, count, previous)
        return event_id

    def receipts(self):
        """Return detached diagnostics without changing receipt state."""
        return self.store.receipts()


class Receiver:
    """Authenticate exact producer bytes and acknowledge only a durable receipt."""

    def __init__(self, auth, receipts, target, *, drop_ack=None):
        """Borrow authentication/receipt operations and an optional post-commit fault."""
        self.auth, self.receipts, self.target, self.drop_ack = (
            auth,
            receipts,
            target,
            drop_ack,
        )

    def on_post(self, req, rep):
        """Commit immutable event bytes before signing an attempt-bound ACK."""
        parsed = urlsplit(self.target)
        relative = parsed.path + ("?" + parsed.query if parsed.query else "")
        if req.relative_uri != relative:
            raise falcon.HTTPBadRequest(description="unexpected signed target")
        body = req.bounded_stream.read()
        try:
            requestAuth = self.auth.verify(
                method="POST",
                target=self.target,
                action="status",
                body=body,
                headers=req.headers,
            )
        except AuthenticationError as exc:
            raise falcon.HTTPUnauthorized(description=str(exc)) from exc
        try:
            key = self.receipts.receive(body)
        except ReceiptConflict as exc:
            raise falcon.HTTPConflict(description=str(exc)) from exc
        except ValueError as exc:
            raise falcon.HTTPBadRequest(description=str(exc)) from exc
        if self.drop_ack is not None and self.drop_ack():
            raise falcon.HTTPServiceUnavailable(
                description="fixture dropped post-commit ACK"
            )
        ack = json.dumps({"eventId": key, "stored": True}).encode()
        headers, _ = self.auth.sign(
            method="POST",
            target=self.target,
            action="ack",
            body=ack,
            request=requestAuth.reference,
            status=200,
        )
        rep.data = ack
        rep.set_headers(headers)

    def on_get(self, req, rep):
        """Expose retained receipt bytes and attempt counts for qualification."""
        rep.media = self.receipts.receipts()


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
        store = ReceiptStore(hby.db)
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
                ReceiptService(store),
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
