"""Validate accepted nonce ownership and startup policy over detached records."""

from eoa_verifier.persistence.keys import nonce_key
from eoa_verifier.persistence.records import VerificationScope


class AssociationIntegrity:
    """Fail closed on corrupt claims or incomplete acceptance history."""

    def __init__(self, reader, writer):
        """Borrow detached read and atomic save adapters."""
        self.reader, self.writer = reader, writer

    def validate_claim(self, key, claim):
        """Require the exact claim key and a matching accepted or revoked owner."""
        try:
            if not isinstance(claim.associationSaid, str) or not claim.associationSaid:
                raise ValueError("missing accepted SAID")
            if nonce_key(claim.issuerAid, claim.nonce) != key:
                raise ValueError("claim key mismatch")
            owner = self.reader.association(claim.associationSaid)
            if (
                owner is None
                or owner.status not in ("accepted", "revoked")
                or owner.associationSaid != claim.associationSaid
                or owner.association["issuerAid"] != claim.issuerAid
            ):
                raise ValueError("claim has no accepted owner")
            return claim
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            raise ValueError("inconsistent accepted nonce claim") from exc

    def claimed_nonce(self, issuer, nonce):
        """Read and validate a competing claim after an aborted acceptance."""
        try:
            claim = self.reader.nonce_claim(issuer, nonce)
            return self.validate_claim(nonce_key(issuer, nonce), claim)
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            raise ValueError("inconsistent accepted nonce claim") from exc

    def validate_nonce_history(self):
        """Audit detached bounded pages before workers start; never infer missing claims."""
        owners, after = set(), None
        while True:
            try:
                page = self.reader.nonce_page(after)
            except (TypeError, ValueError) as exc:
                raise ValueError("inconsistent accepted nonce claim") from exc
            if not page:
                break
            for key, claim in page:
                self.validate_claim(key, claim)
                if claim.associationSaid in owners:
                    raise ValueError(
                        "multiple nonce claims for one accepted association"
                    )
                owners.add(claim.associationSaid)
            after = page[-1][0]
        after = None
        while page := self.reader.association_page(after):
            for key, status in page:
                if status.associationSaid.encode() != key:
                    raise ValueError("inconsistent association key")
                if (
                    status.status in ("accepted", "revoked")
                    and status.associationSaid not in owners
                ):
                    raise ValueError(
                        "accepted associations lack nonce history; use a fresh store"
                    )
            after = page[-1][0]

    def bind_verification_scope(self, *, trusted_geda_aid, chain_id):
        """Reject another policy or history with unknown provenance before binding."""
        scope = VerificationScope(trusted_geda_aid, chain_id, "durable-phases-v1")
        try:
            existing = self.reader.scope()
        except (TypeError, ValueError) as exc:
            raise ValueError("unsupported verifier policy; use a fresh store") from exc
        if existing is not None and existing != scope:
            raise ValueError(
                "verifier store belongs to another GEDA root, chain or acceptance policy"
            )
        if existing is None and self.reader.has_history():
            raise ValueError("verifier store has unscoped results; use separate stores")
        self.validate_nonce_history()
        self.writer.bind_scope(scope)
