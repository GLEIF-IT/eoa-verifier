"""Canonical application storage key encoding; no lifecycle or workflow policy."""

import re


def nonce_key(nonce):
    """Encode the exact nonce as its globally unique accepted-nonce key."""
    if (
        not isinstance(nonce, str)
        or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", nonce) is None
    ):
        raise ValueError(
            "nonce must contain 1 to 128 ASCII letters, digits, underscores or hyphens"
        )
    return nonce.encode("ascii")
