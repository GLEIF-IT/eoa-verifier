"""Canonical application storage key encoding; no lifecycle or workflow policy."""

import re


def nonce_key(nonce):
    """Return the unchanged ASCII nonce bytes used as the permanent global key.

    Require 1–128 letters, digits, underscores or hyphens; otherwise raise ValueError.
    No issuer prefix, hashing, case folding or Unicode normalization is applied.
    """
    if (
        not isinstance(nonce, str)
        or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", nonce) is None
    ):
        raise ValueError(
            "nonce must contain 1 to 128 ASCII letters, digits, underscores or hyphens"
        )
    return nonce.encode("ascii")
