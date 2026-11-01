"""Authenticated transport replay claims, separate from association nonces."""


def claim_nonce(baser, peer, nonce, expires_at):
    """Atomically reserve an authenticated transport nonce without overwriting replay history."""
    from .records import ReplayClaim

    return baser.replay_claims.put(keys=(peer, nonce), val=ReplayClaim(expires_at))
