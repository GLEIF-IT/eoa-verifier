"""Verify received association credentials against accepted KERI state."""

from keri import core, kering
from keri.core import coring, eventing, serdering
from keri.db import dbing
from keri.peer import exchanging
from keri.vdr import credentialing

from eoa_verifier.verification.constants import LE_SCHEMA, QVI_SCHEMA
from eoa_verifier.verification.errors import (
    MissingCredentialArtifactsError,
    VerificationError,
)


def grant_candidate(rgy, grant_said):
    """Return an ACDC decoded from a locally accepted Grant, or None if absent.

    The candidate supplies immutable bytes for inspection, not credential acceptance.
    Native EXN/ACDC decoding and validation errors propagate. No network fetch occurs.
    """
    exn, _ = (
        exchanging.cloneMessage(rgy.hby, said=grant_said)
        if grant_said
        else (None, None)
    )
    return serdering.SerderACDC(sad=exn.ked["e"]["acdc"]) if exn is not None else None


def verify_association(
    *,
    rgy: credentialing.Regery,
    said: str,
    schema_said: str,
    trusted_geda_aid: str,
    candidate: serdering.SerderACDC | None = None,
) -> serdering.SerderACDC:
    """Return a natively accepted association after local LE/QVI trust checks.

    rgy supplies accepted credentials, schemas, TEL and issuer key state. said and
    schema_said identify the expected association; trusted_geda_aid anchors QVI
    issuance/delegation. Optional candidate bytes aid rejection while escrowed but
    cannot establish acceptance. Require untargeted I2I LE linkage, correct holders,
    nested SAIDs and witnessed issuance. Missing local artifacts raise
    MissingCredentialArtifactsError; invalid relationships/revocation raise
    VerificationError or native ValidationError. Wallet/RPC checks are separate.
    No claim is made about evidence not yet delivered to these native stores.
    """
    # Escrowed bytes are not authority. They can, however, establish that this
    # candidate names a revoked or mismatched accepted source. Acceptance is
    # still required below before any candidate can succeed.
    association = stored_credential(rgy, said, schema_said, candidate=candidate)
    if "i" in association.attrib:
        raise VerificationError("association must be untargeted")
    le_edge = association.edge["le"]
    if le_edge.get("s") != LE_SCHEMA or le_edge.get("o") != "I2I":
        raise VerificationError("association must reference its LE credential with I2I")
    le = accepted_credential(rgy, le_edge["n"], LE_SCHEMA)
    qvi_edge = le.edge["qvi"]
    if qvi_edge.get("s") != QVI_SCHEMA:
        raise VerificationError("LE edge must reference a QVI credential")
    qvi = accepted_credential(rgy, qvi_edge["n"], QVI_SCHEMA)
    if association.issuer != le.attrib["i"] or le.issuer != qvi.attrib["i"]:
        raise VerificationError(
            "credential issuer does not match source credential holder"
        )
    if qvi.issuer != trusted_geda_aid:
        raise VerificationError("QVI credential is not issued by the trusted GEDA")
    try:
        qvi_state = rgy.hby.kevers[le.issuer]
    except KeyError as exc:
        raise MissingCredentialArtifactsError(
            "QVI key state is not available yet"
        ) from exc
    if qvi_state.delpre != trusted_geda_aid:
        raise VerificationError("QVI AID is not delegated by the trusted GEDA")

    # Each nested SAID commits its own block as well as the enclosing ACDC.
    for block in (association.attrib["proof"], association.attrib, association.edge):
        if not coring.Saider(qb64=block["d"]).verify(sad=block, prefixed=True):
            raise VerificationError("association block SAID does not verify")
    association = accepted_credential(rgy, said, schema_said)
    verify_witnessed_anchor(rgy, association)
    return association


def accepted_credential(rgy, said: str, schema_said: str) -> serdering.SerderACDC:
    """Return a schema-checked, natively accepted credential with locally issued TEL state.

    The native saved index supplies acceptance; TEL state supplies known status.
    Missing credential/registry/status raises MissingCredentialArtifactsError;
    wrong schema/registry issuer or known revocation raises VerificationError.
    Read-through native caches support reopen. No network freshness query is made.
    """
    if rgy.reger.saved.get(keys=(said,)) is None:
        raise MissingCredentialArtifactsError(f"credential {said} is not accepted yet")
    creder = stored_credential(rgy, said, schema_said)
    # Native read-through caches reload persisted state through indexed lookup.
    # Their get() methods consult only the in-memory cache in this KERI version.
    try:
        tever = rgy.reger.tevers[creder.regi]
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
    rgy, said: str, schema_said: str, *, candidate=None
) -> serdering.SerderACDC:
    """Return schema-validated ACDC bytes for said, using candidate only if none are stored.

    Reconstruct the native Serder to validate serialization, then require the exact
    SAID and pinned schema. This does not establish native acceptance or TEL status.
    Missing bytes/schema raise MissingCredentialArtifactsError; identity, schema or
    serialized-data mismatches raise VerificationError (or native validation errors).
    """
    creder = rgy.reger.creds.get(keys=(said,))
    if creder is None:
        creder = candidate
    if creder is None:
        raise MissingCredentialArtifactsError(f"credential {said} is not available yet")
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
    schema = rgy.hby.db.schema.get(keys=(schema_said,))
    if schema is None:
        raise MissingCredentialArtifactsError(
            f"schema {schema_said} is not available yet"
        )
    try:
        schema.verify(creder.raw)
    except kering.ValidationError as exc:
        raise VerificationError(f"credential {said} does not match its schema") from exc
    return creder


def verify_witnessed_anchor(rgy, association):
    """Verify locally stored issuance anchoring and witness receipts; return None.

    Precondition: association passed accepted_credential, so registry/TEL state
    exists. Use native anchor and historical witness-state/signature APIs for that
    issuer event. Missing anchor/establishment/receipts raise
    MissingCredentialArtifactsError; known revocation or an unwitnessed issuer raises
    VerificationError. This reads native evidence, not a remote freshness guarantee.
    """
    tever = rgy.reger.tevers[association.regi]
    state = tever.vcState(association.said)
    if state.et not in ("iss", "bis"):
        raise VerificationError("association is revoked")
    seqner = coring.Seqner(sn=state.a["s"])
    saider = coring.Saider(qb64=state.a["d"])
    raw = rgy.reger.getTvt(dbing.dgKey(association.said, state.d))
    if raw is None or not tever.verifyAnchor(
        serder=serdering.SerderKERI(raw=bytes(raw)), seqner=seqner, saider=saider
    ):
        raise MissingCredentialArtifactsError(
            "association issuance anchor is unavailable"
        )
    est = rgy.hby.kvy.fetchEstEvent(pre=association.issuer, sn=seqner.sn)
    if est is None:
        raise MissingCredentialArtifactsError(
            "issuer establishment event is unavailable"
        )
    if not est.bn:
        raise VerificationError("association issuer has no witnessed KEL")
    wits = rgy.hby.kvy.fetchWitnessState(association.issuer, seqner.sn)
    anchor = rgy.hby.db.getEvt(dbing.dgKey(association.issuer, saider.qb64))
    wigs = rgy.hby.db.getWigs(dbing.dgKey(association.issuer, saider.qb64))
    _, indices = eventing.verifySigs(
        raw=bytes(anchor),
        sigers=[core.Siger(qb64b=bytes(wig)) for wig in wigs],
        verfers=[core.Verfer(qb64=wit.qb64) for wit in wits],
    )
    if len(set(indices)) < est.bn:
        raise MissingCredentialArtifactsError(
            "association anchor lacks witness receipts"
        )
