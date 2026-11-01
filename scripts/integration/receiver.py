"""Focused durable webhook receiver. No association selection or contract effects."""

import argparse
import json
import signal
from urllib.parse import urlsplit
from pathlib import Path
import falcon
from hio.base import doing
from hio.core import http
from keri.app import habbing
from keri.db import subing
from eoa_verifier.delivery.authing import ServiceAuthenticator, AuthenticationError


class ReceiptStore:
    """Borrow a native database for durable fixture receipts and replay claims."""

    def __init__(self, db):
        """Bind disjoint non-duplicate receipt, attempt and control subdatabases."""
        self.events = subing.Suber(db=db, subkey="fixture.events.")
        self.replays = subing.Suber(db=db, subkey="fixture.replays.")
        self.attempts = subing.Suber(db=db, subkey="fixture.attempts.")
        self.control = subing.Suber(db=db, subkey="fixture.control.")

    def claim_nonce(self, peer, nonce, expires_at):
        """Use native no-overwrite insertion for one authentication replay claim."""
        return self.replays.put(keys=(peer, nonce), val=str(expires_at))


class Receiver:
    """Authenticate exact producer bytes and acknowledge only a durable receipt."""

    def __init__(self, auth, store, target, drop):
        """Borrow auth/store; target is the signed URL, drop loses the first ACK."""
        self.auth, self.store, self.target, self.drop = auth, store, target, drop

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
            payload = json.loads(body)
            key = payload["eventId"]
            if not isinstance(key, str) or not key:
                raise ValueError("missing event ID")
        except (ValueError, KeyError, TypeError) as exc:
            raise falcon.HTTPBadRequest(description="invalid fixture event") from exc
        text = body.decode()
        previous = self.store.events.get(keys=(key,))
        if previous is not None and previous != text:
            raise falcon.HTTPConflict(description="conflicting event bytes")
        self.store.events.put(
            keys=(key,), val=text
        )  # Native synchronous commit precedes ACK.
        count = int(self.store.attempts.get(keys=(key,)) or "0") + 1
        self.store.attempts.pin(keys=(key,), val=str(count))
        if self.drop and self.store.control.put(keys=("dropped",), val="true"):
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
        rep.media = [
            {
                "eventId": keys[0],
                "body": value,
                "attempts": int(self.store.attempts.get(keys=keys)),
            }
            for keys, value in self.store.events.getItemIter()
        ]


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
            hab=hab, baser=store, peer_aid=config["verifierAid"]
        )
        app = falcon.App()
        app.add_route(
            "/hook", Receiver(auth, store, config["webhookUrl"], config["dropAck"])
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
