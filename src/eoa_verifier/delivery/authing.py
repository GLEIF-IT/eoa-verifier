"""Authenticate trusted HTTP context and consume its replay nonce before success."""

import secrets
from dataclasses import dataclass

from keri import kering
from keri.core import coring
from keri.end import ending
from keri.help import helping

from .signatures import (
    CONTEXT,
    FIELDS,
    LABEL,
    AuthenticationError,
    _path,
    body_digest,
    read_signature,
    signature_base,
)


@dataclass(frozen=True)
class AuthenticatedMessage:
    """Verified transport identity; never a claim of durable application acceptance."""

    peer: str  # Configured peer AID whose locally accepted key verified the message.
    nonce: str  # Unique attempt ID; later ACKs must identify this exact attempt.
    digest: str  # Digest of the exact body bytes, for request/ACK correlation.

    @property
    def reference(self):
        """Return the attempt/body reference to cover in an authenticated ACK."""
        return f"{self.nonce}:{self.digest}"


class ServiceAuthenticator:
    """Sign and authenticate messages with a KERIpy habitat and one trusted peer.

    Borrow the habitat/key-state database and replay store; own no network tasks.
    Only locally accepted current single-key, threshold-one transferable AIDs are
    supported. Rotation uses verified KERI key-state updates, never an arbitrary header key.
    """

    def __init__(self, *, keys, claim_nonce, peer_aid, lifetime=60):
        """Configure peer trust and maximum message lifetime in seconds.

        claim_nonce atomically owns durable transport replay claims. The lifetime is transport validity only;
        it does not limit accepted associations. KERIpy UTC clock supplies wall time.
        """
        self.keys, self.claim_nonce, self.peer_aid = keys, claim_nonce, peer_aid
        self.lifetime = lifetime
        if (
            coring.Prefixer(qb64=peer_aid).qb64 != peer_aid
            or type(lifetime) is not int
            or lifetime <= 0
        ):
            raise ValueError("peer AID and positive message lifetime are required")

    def sign(self, *, method, target, action, body, request="", status=0):
        """Return signed headers and an attempt reference for these exact body bytes.

        For an ACK, action is 'ack', request is the authenticated request reference
        and status is its actual HTTP response status. Every invocation uses a new
        nonce, including retries of the same immutable application event.
        """
        self.keys.key(self.keys.aid)
        nonce = secrets.token_hex(16)
        digest = body_digest(body)
        headers = {
            "content-digest": digest,
            "content-type": "application/json",
            "eoa-target": target,
            "eoa-audience": self.peer_aid,
            "eoa-action": action,
            "eoa-request": request,
            "eoa-status": str(status),
        }
        signed, cigar = self.keys.sign(
            LABEL,
            method,
            _path(target),
            headers,
            fields=FIELDS,
            expires=int(helping.nowUTC().timestamp()) + self.lifetime,
            nonce=nonce,
            keyid=self.keys.aid,
            context=CONTEXT,
            alg="ed25519",
        )
        headers.update({k.lower(): v for k, v in signed.items()})
        headers.update(
            {
                k.lower(): v
                for k, v in ending.signature(
                    [
                        ending.Signage(
                            markers={LABEL: cigar},
                            indexed=False,
                            signer=self.keys.aid,
                            ordinal=None,
                            digest=None,
                            kind=None,
                        )
                    ]
                ).items()
            }
        )
        return headers, AuthenticatedMessage(self.keys.aid, nonce, digest)

    def verify(self, *, method, target, action, body, headers, request="", status=0):
        """Authenticate expected HTTP context and atomically claim its nonce; return identity.

        Pass the actual response status when checking an ACK and the original
        request reference. method and target must describe the actual HTTP request (including query),
        matched by the caller to its configured destination; action is the expected
        operation. Never obtain these expected values from signature headers.
        Rejected messages do not reserve nonces. Replay claims survive reopening;
        application retries must be newly signed. No network refresh occurs here.
        Returns AuthenticatedMessage; invalid context, signature or replay raises
        AuthenticationError. A successful claim precedes application persistence,
        so an application failure requires a newly signed delivery attempt.
        """
        lowered, inp, sig = read_signature(
            headers,
            peer_aid=self.peer_aid,
            lifetime=self.lifetime,
            now=int(helping.nowUTC().timestamp()),
        )
        try:
            expected = {
                "content-digest": body_digest(body),
                "content-type": "application/json",
                "eoa-target": target,
                "eoa-audience": self.keys.aid,
                "eoa-action": action,
                "eoa-request": request,
                "eoa-status": str(status),
            }
            if any(lowered[k] != value for k, value in expected.items()):
                raise AuthenticationError("body, target or operation mismatch")
            if not self.keys.key(self.peer_aid).verify(
                sig.markers[LABEL].raw,
                signature_base(inp, method, target, expected),
            ):
                raise AuthenticationError("signature does not verify")
        except (KeyError, TypeError, ValueError, kering.KeriError) as exc:
            raise AuthenticationError(str(exc)) from exc
        if not self.claim_nonce(self.peer_aid, inp.nonce, inp.expires):
            raise AuthenticationError("message replay")
        return AuthenticatedMessage(
            self.peer_aid, inp.nonce, expected["content-digest"]
        )
