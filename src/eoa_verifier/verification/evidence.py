"""Read detached credential evidence and validate KERIpy mechanisms."""

from keri import core, kering
from keri.core import coring, eventing, serdering
from keri.db import dbing
from keri.peer import exchanging

from eoa_verifier.verification.errors import (
    MissingCredentialArtifactsError,
    VerificationError,
)


class CredentialEvidence:
    """Borrow KERIpy stores; expose reconstructed credentials and copied facts."""

    def __init__(self, rgy):
        """Retain Regery access inside the KERIpy adapter, never in policy code."""
        self._rgy = rgy

    def delegator(self, aid):
        """Return the delegator prefix, using KERIpy's persisted-state read-through."""
        try:
            return self._rgy.hby.kevers[aid].delpre
        except KeyError as exc:
            raise MissingCredentialArtifactsError(
                "QVI key state is not available yet"
            ) from exc

    def grant_candidate(self, grant_said):
        """Return an ACDC decoded from a locally accepted Grant, or None if absent.

        The candidate supplies immutable bytes for inspection, not credential acceptance.
        KERIpy EXN/ACDC decoding and validation errors propagate. No network fetch occurs.
        """
        exn, _ = (
            exchanging.cloneMessage(self._rgy.hby, said=grant_said)
            if grant_said
            else (None, None)
        )
        return (
            serdering.SerderACDC(sad=exn.ked["e"]["acdc"]) if exn is not None else None
        )

    def accepted_credential(self, said: str, schema_said: str) -> serdering.SerderACDC:
        """Return a schema-checked, KERIpy-accepted credential with locally issued TEL state.

        The KERIpy saved index supplies acceptance; TEL state supplies known status.
        Missing credential/registry/status raises MissingCredentialArtifactsError;
        wrong schema/registry issuer or known revocation raises VerificationError.
        Read-through KERIpy caches support reopen. No network freshness query is made.
        """
        if self._rgy.reger.saved.get(keys=(said,)) is None:
            raise MissingCredentialArtifactsError(
                f"credential {said} is not accepted yet"
            )
        creder = self.stored_credential(said, schema_said)
        # KERIpy read-through caches reload persisted state through indexed lookup.
        # Their get() methods consult only the in-memory cache in this KERI version.
        try:
            tever = self._rgy.reger.tevers[creder.regi]
        except KeyError as exc:
            raise MissingCredentialArtifactsError(
                f"credential {said} has no registry state"
            ) from exc
        state = tever.vcState(said)
        if state is None:
            raise MissingCredentialArtifactsError(f"credential {said} has no TEL state")
        if state.et not in ("iss", "bis"):
            raise VerificationError(f"credential {said} is revoked")
        if tever.pre != creder.issuer:
            raise VerificationError("credential registry belongs to another issuer")
        return creder

    def stored_credential(
        self, said: str, schema_said: str, *, candidate=None
    ) -> serdering.SerderACDC:
        """Return schema-validated ACDC bytes for said, using candidate only if none are stored.

        Reconstruct the KERIpy Serder to validate serialization, then require the exact
        SAID and pinned schema. This does not establish KERIpy credential acceptance or TEL status.
        Missing bytes/schema raise MissingCredentialArtifactsError; identity, schema or
        serialized-data mismatches raise VerificationError (or KERIpy validation errors).
        """
        creder = self._rgy.reger.creds.get(keys=(said,))
        if creder is None:
            creder = candidate
        if creder is None:
            raise MissingCredentialArtifactsError(
                f"credential {said} is not available yet"
            )
        try:
            creder = serdering.SerderACDC(raw=creder.raw)
        except kering.ValidationError as exc:
            raise VerificationError(
                f"credential {said} has invalid serialized data"
            ) from exc
        if creder.said != said:
            raise VerificationError("candidate does not match requested association")
        if creder.schema != schema_said:
            raise VerificationError(f"credential {said} has unexpected schema")
        schema = self._rgy.hby.db.schema.get(keys=(schema_said,))
        if schema is None:
            raise MissingCredentialArtifactsError(
                f"schema {schema_said} is not available yet"
            )
        try:
            schema.verify(creder.raw)
        except kering.ValidationError as exc:
            raise VerificationError(
                f"credential {said} does not match its schema"
            ) from exc
        return creder

    def verify_witnessed_anchor(self, association):
        """Verify locally stored issuance anchoring and witness receipts; return None.

        Precondition: association passed accepted_credential, so registry/TEL state
        exists. Use KERIpy anchor and historical witness-state/signature APIs for that
        issuer event. Missing anchor/establishment/receipts raise
        MissingCredentialArtifactsError; known revocation or an unwitnessed issuer raises
        VerificationError. This reads KERI evidence, not a remote freshness guarantee.
        """
        tever = self._rgy.reger.tevers[association.regi]
        state = tever.vcState(association.said)
        if state.et not in ("iss", "bis"):
            raise VerificationError("association is revoked")
        seqner = coring.Seqner(sn=state.a["s"])
        saider = coring.Saider(qb64=state.a["d"])
        raw = self._rgy.reger.getTvt(dbing.dgKey(association.said, state.d))
        if raw is None or not tever.verifyAnchor(
            serder=serdering.SerderKERI(raw=bytes(raw)), seqner=seqner, saider=saider
        ):
            raise MissingCredentialArtifactsError(
                "association issuance anchor is unavailable"
            )
        est = self._rgy.hby.kvy.fetchEstEvent(pre=association.issuer, sn=seqner.sn)
        if est is None:
            raise MissingCredentialArtifactsError(
                "issuer establishment event is unavailable"
            )
        if not est.bn:
            raise VerificationError("association issuer has no witnessed KEL")
        wits = self._rgy.hby.kvy.fetchWitnessState(association.issuer, seqner.sn)
        anchor = self._rgy.hby.db.getEvt(dbing.dgKey(association.issuer, saider.qb64))
        wigs = self._rgy.hby.db.getWigs(dbing.dgKey(association.issuer, saider.qb64))
        _, indices = eventing.verifySigs(
            raw=bytes(anchor),
            sigers=[core.Siger(qb64b=bytes(wig)) for wig in wigs],
            verfers=[core.Verfer(qb64=wit.qb64) for wit in wits],
        )
        if len(set(indices)) < est.bn:
            raise MissingCredentialArtifactsError(
                "association anchor lacks witness receipts"
            )
