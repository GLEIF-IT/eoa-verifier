"""KERIpy key-state and signing adapter for service authentication."""

from keri.core import coring
from keri.end import ending

from .signatures import AuthenticationError


class ServiceKeys:
    """Keep mutable habitat/key-state access behind detached-key and signing operations."""

    def __init__(self, hab):
        """Borrow the service habitat; its owner controls key-store lifetime."""
        self.hab = hab

    @property
    def aid(self):
        """Return this service's current identifier prefix."""
        return self.hab.pre

    def sign(self, *args, **kwargs):
        """Use the habitat's KERIpy signer for the pinned HTTP signature input."""
        return ending.siginput(*args, hab=self.hab, **kwargs)

    def key(self, aid):
        """Read the supported current KERI key or reject unavailable/unsupported state."""
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
        return coring.Verfer(qb64=kever.verfers[0].qb64)
