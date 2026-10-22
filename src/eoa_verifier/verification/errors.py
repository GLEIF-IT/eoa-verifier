"""Distinguish missing evidence from established verification failure."""


class MissingCredentialArtifactsError(Exception):
    """Required credential, status, key, or schema evidence is unavailable."""


class VerificationError(ValueError):
    """Available evidence establishes an invalid association."""
