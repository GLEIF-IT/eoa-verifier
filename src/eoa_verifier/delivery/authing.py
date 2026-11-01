"""Sign HTTP content and verify optional signatures without transport state."""

from keri.end import ending

from .signatures import (
    FIELDS,
    LABEL,
    AuthenticationError,
    body_digest,
    read_signature,
    request_path,
    signature_base,
)


class HttpSignatures:
    """Borrow accepted KERI keys; never discover peers or persist replay claims."""

    def __init__(self, keys):
        """Use an existing service identity and its locally accepted key state."""
        self.keys = keys

    def sign(self, *, method, target, body):
        """Return headers signing exact bytes; no destination identity is needed."""
        self.keys.key(self.keys.aid)
        headers = {
            "content-digest": body_digest(body),
            "content-type": "application/json",
        }
        signed, cigar = self.keys.sign(
            LABEL,
            method,
            request_path(target),
            headers,
            fields=FIELDS,
            keyid=self.keys.aid,
            alg="ed25519",
        )
        headers.update({key.lower(): value for key, value in signed.items()})
        headers.update(
            {
                key.lower(): value
                for key, value in ending.signature(
                    [
                        ending.Signage(
                            markers={LABEL: cigar},
                            indexed=False,
                            signer=None,
                            ordinal=None,
                            digest=None,
                            kind=None,
                        )
                    ]
                ).items()
            }
        )
        return headers

    def verify(self, *, method, target, body, headers, expected_aid=None):
        """Return the verified signer AID, optionally enforcing producer authorization.

        The keyid header selects already accepted KERI key state, never a supplied
        public key or discovery URL. Repeated signatures may verify; application
        event deduplication, not transport nonce storage, controls repeated effects.
        Response callers use the initiating request's method/path, as in KERIA.
        """
        lowered, inp, cigar = read_signature(headers)
        if expected_aid is not None and inp.keyid != expected_aid:
            raise AuthenticationError("untrusted signer")
        digest = body_digest(body)
        if lowered.get("content-digest") != digest:
            raise AuthenticationError("body digest mismatch")
        key = self.keys.key(inp.keyid)
        if not key.verify(
            cigar.raw, signature_base(inp, method, request_path(target), digest)
        ):
            raise AuthenticationError("signature does not verify")
        return inp.keyid

    def verify_optional(self, *, method, target, body, headers):
        """Verify every supplied signature; unsigned responses need no KERI state."""
        if any(key.lower() in ("signature", "signature-input") for key in headers):
            return self.verify(method=method, target=target, body=body, headers=headers)
        return None
