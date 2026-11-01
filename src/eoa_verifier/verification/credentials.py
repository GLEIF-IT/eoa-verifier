"""Credential-chain trust and profile rules over native evidence snapshots."""

from keri.core import coring, serdering

from .constants import LE_SCHEMA, QVI_SCHEMA
from .errors import VerificationError


def verify_association(
    *,
    evidence,
    said: str,
    schema_said: str,
    trusted_geda_aid: str,
    candidate: serdering.SerderACDC | None = None,
) -> serdering.SerderACDC:
    """Return a KERIpy-accepted association after local LE/QVI trust checks.

    evidence supplies detached credentials and native validation results. said and
    schema_said identify the expected association; trusted_geda_aid anchors QVI
    issuance/delegation. Optional candidate bytes aid rejection while escrowed but
    cannot establish acceptance. Require untargeted I2I LE linkage, correct holders,
    nested SAIDs and witnessed issuance. Missing local artifacts raise
    MissingCredentialArtifactsError; invalid relationships/revocation raise
    VerificationError or KERIpy ValidationError. Wallet/RPC checks are separate.
    No claim is made about evidence not yet delivered to these KERIpy stores.
    """
    # Escrowed bytes are not authority. They can, however, establish that this
    # candidate names a revoked or mismatched accepted source. Acceptance is
    # still required below before any candidate can succeed.
    association = evidence.stored_credential(said, schema_said, candidate=candidate)
    if "i" in association.attrib:
        raise VerificationError("association must be untargeted")
    le_edge = association.edge["le"]
    if le_edge.get("s") != LE_SCHEMA or le_edge.get("o") != "I2I":
        raise VerificationError("association must reference its LE credential with I2I")
    le = evidence.accepted_credential(le_edge["n"], LE_SCHEMA)
    qvi_edge = le.edge["qvi"]
    if qvi_edge.get("s") != QVI_SCHEMA:
        raise VerificationError("LE edge must reference a QVI credential")
    qvi = evidence.accepted_credential(qvi_edge["n"], QVI_SCHEMA)
    if association.issuer != le.attrib["i"] or le.issuer != qvi.attrib["i"]:
        raise VerificationError(
            "credential issuer does not match source credential holder"
        )
    if qvi.issuer != trusted_geda_aid:
        raise VerificationError("QVI credential is not issued by the trusted GEDA")
    if evidence.delegator(le.issuer) != trusted_geda_aid:
        raise VerificationError("QVI AID is not delegated by the trusted GEDA")

    # Each nested SAID commits its own block as well as the enclosing ACDC.
    for block in (association.attrib["proof"], association.attrib, association.edge):
        if not coring.Saider(qb64=block["d"]).verify(sad=block, prefixed=True):
            raise VerificationError("association block SAID does not verify")
    association = evidence.accepted_credential(said, schema_said)
    evidence.verify_witnessed_anchor(association)
    return association
