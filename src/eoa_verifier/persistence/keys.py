"""Canonical application storage key encoding; no lifecycle or workflow policy."""

import re


def nonce_key(issuer, nonce):
    """Use Komer's ordinary issuer.nonce key; neither component contains dots."""
    if not isinstance(issuer, str) or not issuer or "." in issuer:
        raise ValueError("issuer AID is required and cannot contain a dot")
    if (
        not isinstance(nonce, str)
        or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", nonce) is None
    ):
        raise ValueError(
            "nonce must contain 1 to 128 ASCII letters, digits, underscores or hyphens"
        )
    return f"{issuer}.{nonce}".encode("ascii")
