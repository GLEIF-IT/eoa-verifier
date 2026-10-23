"""Native KERI HTTP signatures for one configured service peer.

This is transport authentication only. Callers retain exact body bytes and supply
trusted expected HTTP context; authentication does not commit application effects.
"""

import base64
import hashlib
import secrets
from dataclasses import dataclass
from urllib.parse import urlsplit

from keri import kering
from keri.core import coring
from keri.end import ending
from keri.help import helping

# Exact native signature profile; changing coverage requires peer coordination.
FIELDS = (
    "@method",
    "@path",
    "content-digest",
    "content-type",
    "eoa-target",
    "eoa-audience",
    "eoa-action",
    "eoa-request",
    "eoa-status",
)
# Native signature label and context distinguish this service transport profile.
LABEL = "sig0"
CONTEXT = "eoa-verifier/v1"


class AuthenticationError(ValueError):
    """The message cannot be authenticated for its expected peer and operation."""


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


def body_digest(body):
    """Return the SHA-256 Content-Digest field for exact bytes, without JSON rewriting."""
    return "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"


def _path(target):
    """Return the HTTP path/query of an absolute configured target; reject fragments."""
    parts = urlsplit(target)
    if parts.scheme not in ("http", "https") or not parts.netloc or parts.fragment:
        raise ValueError("target must be an absolute HTTP URL without a fragment")
    return (parts.path or "/") + ("?" + parts.query if parts.query else "")


class ServiceAuthenticator:
    """Sign and authenticate messages with a native habitat and one trusted peer.

    Borrow the habitat/key-state database and replay store; own no network tasks.
    Only locally accepted current single-key, threshold-one transferable AIDs are
    supported. Rotation uses native key-state updates, never an arbitrary header key.
    """

    def __init__(self, *, hab, baser, peer_aid, lifetime=60):
        """Configure peer trust and maximum message lifetime in seconds.

        baser owns durable replay claims. The lifetime is transport validity only;
        it does not limit accepted associations. Native UTC supplies wall time.
        """
        self.hab, self.baser, self.peer_aid = hab, baser, peer_aid
        self.lifetime = lifetime
        if (
            coring.Prefixer(qb64=peer_aid).qb64 != peer_aid
            or type(lifetime) is not int
            or lifetime <= 0
        ):
            raise ValueError("peer AID and positive message lifetime are required")

    def _key(self, aid):
        """Read the supported native current key or reject unavailable/unsupported state."""
        try:
            kever = self.hab.db.kevers[aid]
        except KeyError as exc:
            raise AuthenticationError("peer key state is unavailable") from exc
        if (
            not kever.prefixer.transferable
            or len(kever.verfers) != 1
            or kever.tholder.sith != "1"
            or kever.verfers[0].code != coring.MtrDex.Ed25519
        ):
            raise AuthenticationError(
                "service AID must have one transferable signing key at threshold one"
            )
        return kever.verfers[0]

    def sign(self, *, method, target, action, body, request="", status=0):
        """Return signed headers and an attempt reference for these exact body bytes.

        For an ACK, action is 'ack', request is the authenticated request reference
        and status is its actual HTTP response status. Every invocation uses a new
        nonce, including retries of the same immutable application event.
        """
        self._key(self.hab.pre)
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
        signed, cigar = ending.siginput(
            LABEL,
            method,
            _path(target),
            headers,
            fields=FIELDS,
            hab=self.hab,
            expires=int(helping.nowUTC().timestamp()) + self.lifetime,
            nonce=nonce,
            keyid=self.hab.pre,
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
                            signer=self.hab.pre,
                            ordinal=None,
                            digest=None,
                            kind=None,
                        )
                    ]
                ).items()
            }
        )
        return headers, AuthenticatedMessage(self.hab.pre, nonce, digest)

    def _read_signature(self, headers):
        """Decode one native signature and enforce peer/profile/message-time constraints.

        Return normalized headers, parsed input and signature. Malformed data raises
        AuthenticationError; no replay state is claimed at this boundary.
        """
        try:
            lowered = {k.lower(): v for k, v in headers.items()}
            if len(lowered) != len(headers):
                raise AuthenticationError("duplicate header names")
            inputs = ending.desiginput(lowered["signature-input"].encode())
            signatures = ending.designature(lowered["signature"])
            if len(inputs) != 1 or len(signatures) != 1:
                raise AuthenticationError("one signature is required")
            inp, sig = inputs[0], signatures[0]
            if (
                inp.name != LABEL
                or tuple(inp.fields) != FIELDS
                or inp.keyid != self.peer_aid
                or inp.context != CONTEXT
                or inp.alg != "ed25519"
                or sig.signer != self.peer_aid
                or sig.indexed
                or set(sig.markers) != {LABEL}
                or sig.kind != "CESR"
                or not isinstance(sig.markers[LABEL], coring.Cigar)
            ):
                raise AuthenticationError("untrusted peer or signature profile")
            now = int(helping.nowUTC().timestamp())
            if (
                type(inp.created) is not int
                or type(inp.expires) is not int
                or not inp.created <= now < inp.expires
                or not 0 < inp.expires - inp.created <= self.lifetime
                or not isinstance(inp.nonce, str)
                or len(inp.nonce) != 32
                or any(c not in "0123456789abcdef" for c in inp.nonce)
            ):
                raise AuthenticationError("invalid message lifetime or nonce")
            return lowered, inp, sig
        except (KeyError, TypeError, ValueError, kering.KeriError) as exc:
            raise AuthenticationError(str(exc)) from exc

    def verify(self, *, method, target, action, body, headers, request="", status=0):
        """Authenticate expected HTTP context and atomically claim its nonce; return identity.

        Pass the actual response status when checking an ACK and the original
        request reference. method and target must describe the actual HTTP request (including query),
        matched by the caller to its configured destination; action is the expected
        operation. Never obtain these expected values from signature headers.
        Rejected messages do not reserve nonces. Replay claims survive reopening;
        application retries must be newly signed. No network refresh occurs here.
        """
        lowered, inp, sig = self._read_signature(headers)
        try:
            expected = {
                "content-digest": body_digest(body),
                "content-type": "application/json",
                "eoa-target": target,
                "eoa-audience": self.hab.pre,
                "eoa-action": action,
                "eoa-request": request,
                "eoa-status": str(status),
            }
            if any(lowered[k] != value for k, value in expected.items()):
                raise AuthenticationError("body, target or operation mismatch")
            if not self._key(self.peer_aid).verify(
                sig.markers[LABEL].raw,
                self._signature_base(inp, method, target, expected),
            ):
                raise AuthenticationError("signature does not verify")
        except (KeyError, TypeError, ValueError, kering.KeriError) as exc:
            raise AuthenticationError(str(exc)) from exc
        if not self.baser.claim_message(self.peer_aid, inp.nonce, inp.expires):
            raise AuthenticationError("message replay")
        return AuthenticatedMessage(
            self.peer_aid, inp.nonce, expected["content-digest"]
        )

    @staticmethod
    def _signature_base(inp, method, target, expected):
        """Rebuild the exact pinned KERIpy siginput base for native signature verification.

        Preserve its field and parameter spelling/order; this narrow compatibility
        function is not a general RFC 9421 canonicalizer.
        """
        values = {"@method": method, "@path": _path(target), **expected}
        lines = [f'"{field}": {values[field].strip()}' for field in FIELDS]
        params = (
            f"({' '.join(FIELDS)});created={inp.created};expires={inp.expires}"
            f";nonce={inp.nonce};keyid={inp.keyid};context={CONTEXT};alg=ed25519"
        )
        lines.append(f'"@signature-params: {params}"')
        return "\n".join(lines).encode()

    def sign_ack(self, received, *, method, target, body):
        """Sign an HTTP 200 ACK after the caller durably accepts the application event.

        received must be the authenticated request identity returned by verify.
        This helper does not commit that event or create its application payload.
        """
        if received.peer != self.peer_aid:
            raise AuthenticationError("ACK request is not from the configured peer")
        return self.sign(
            method=method,
            target=target,
            action="ack",
            body=body,
            request=received.reference,
            status=200,
        )

    def verify_ack(self, sent, *, method, target, body, headers, status):
        """Authenticate a successful ACK for this exact sent attempt/body.

        Reject even signed non-200 responses. The future delivery worker remains
        responsible for validating the application ACK payload before completion.
        """
        if status != 200 or sent.peer != self.hab.pre:
            raise AuthenticationError("not a successful ACK for this sender")
        return self.verify(
            method=method,
            target=target,
            action="ack",
            body=body,
            headers=headers,
            request=sent.reference,
            status=status,
        )
