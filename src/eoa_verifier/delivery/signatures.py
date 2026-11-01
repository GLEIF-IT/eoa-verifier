"""Pure decoding and canonicalization for the pinned KERI HTTP signature profile."""

import base64
import hashlib
from urllib.parse import urlsplit

from keri import kering
from keri.core import coring
from keri.end import ending

# Exact KERIpy HTTP signature profile; changing coverage requires peer coordination.
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
# HTTP signature label and context distinguish this service transport profile.
LABEL = "sig0"
CONTEXT = "eoa-verifier/v1"


class AuthenticationError(ValueError):
    """The message cannot be authenticated for its expected peer and operation."""


def body_digest(body):
    """Return the SHA-256 Content-Digest field for exact bytes, without JSON rewriting."""
    return "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"


def _path(target):
    """Return the HTTP path/query of an absolute configured target; reject fragments."""
    parts = urlsplit(target)
    if parts.scheme not in ("http", "https") or not parts.netloc or parts.fragment:
        raise ValueError("target must be an absolute HTTP URL without a fragment")
    return (parts.path or "/") + ("?" + parts.query if parts.query else "")


def read_signature(headers, *, peer_aid, lifetime, now):
    """Decode one KERI AID signature and enforce peer/profile/message-time constraints.

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
            or inp.keyid != peer_aid
            or inp.context != CONTEXT
            or inp.alg != "ed25519"
            or sig.signer != peer_aid
            or sig.indexed
            or set(sig.markers) != {LABEL}
            or sig.kind != "CESR"
            or not isinstance(sig.markers[LABEL], coring.Cigar)
        ):
            raise AuthenticationError("untrusted peer or signature profile")
        if (
            type(inp.created) is not int
            or type(inp.expires) is not int
            or not inp.created <= now < inp.expires
            or not 0 < inp.expires - inp.created <= lifetime
            or not isinstance(inp.nonce, str)
            or len(inp.nonce) != 32
            or any(c not in "0123456789abcdef" for c in inp.nonce)
        ):
            raise AuthenticationError("invalid message lifetime or nonce")
        return lowered, inp, sig
    except (KeyError, TypeError, ValueError, kering.KeriError) as exc:
        raise AuthenticationError(str(exc)) from exc


def signature_base(inp, method, target, expected):
    """Rebuild the exact pinned KERIpy siginput base for KERI AID signature verification.

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
