"""Small KERIpy HTTP signature profile over method, path and exact body bytes.

Signature-Input.keyid identifies the signer. Signature verification has no
persistence effects; application event IDs own duplicate handling.
"""

import base64
import hashlib
from urllib.parse import urlsplit

from keri import kering
from keri.core import coring
from keri.end import ending

# Ordered coverage used by both siginput construction and verification.
FIELDS = ("@method", "@path", "content-digest")
# Single CESR signature marker shared with the pinned KERIpy HTTP profile.
LABEL = "sig0"


class AuthenticationError(ValueError):
    """The supplied signature or locally accepted signing key is invalid."""


def body_digest(body):
    """Return the RFC 9530 SHA-256 Content-Digest value for exact body bytes.

    Format the raw digest as standard base64 in sha-256=:...:. This is an HTTP
    representation digest, not a CESR SAID; include it in the signed input.
    """
    return "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"


def request_path(target):
    """Extract the HTTP path; origin and query are outside signature coverage."""
    return urlsplit(target).path or "/"


def read_signature(headers):
    """Decode the fixed KERIpy profile, rejecting partial or malformed signatures."""
    try:
        lowered = {k.lower(): value for k, value in headers.items()}
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
            or not isinstance(inp.keyid, str)
            or not inp.keyid
            or inp.alg != "ed25519"
            or type(inp.created) is not int
            or inp.expires is not None
            or inp.nonce is not None
            or inp.context is not None
            or sig.signer not in (None, inp.keyid)
            or sig.indexed
            or set(sig.markers) != {LABEL}
            or sig.kind != "CESR"
            or not isinstance(sig.markers[LABEL], coring.Cigar)
        ):
            raise AuthenticationError("invalid signature profile")
        if coring.Prefixer(qb64=inp.keyid).qb64 != inp.keyid:
            raise AuthenticationError("invalid signer AID")
        return lowered, inp, sig.markers[LABEL]
    except (KeyError, TypeError, ValueError, IndexError, kering.KeriError) as exc:
        raise AuthenticationError(str(exc)) from exc


def signature_base(inp, method, path, digest):
    """Reproduce pinned KERIpy siginput encoding, not a general RFC canonicalizer."""
    values = {"@method": method, "@path": path, "content-digest": digest}
    lines = [f'"{field}": {ending.normalize(values[field])}' for field in FIELDS]
    params = f"({' '.join(FIELDS)});created={inp.created};keyid={inp.keyid};alg=ed25519"
    lines.append(f'"@signature-params: {params}"')
    return "\n".join(lines).encode()
