"""Construct concrete association services and seed accepted fixture status at their explicit boundaries."""

from types import SimpleNamespace

from eoa_verifier.persistence.associations import AssociationReader, AssociationWriter
from eoa_verifier.persistence.delivery import DeliveryReader
from eoa_verifier.persistence.records import VerificationRecord, VerificationResult
from eoa_verifier.persistence.verification import VerificationReader
from tests.support.persistence import enqueue_verification
from tests.support.services import verification_service

# Fixture webhook target; no HTTP is attempted by tests that only inspect the outbox.
HOOK = "https://receiver.example/hook"
# Minimal verified wallet result; not cryptographic evidence.
EOA_RESULT = {
    "wallet": "0x" + "12" * 20,
    "accountObservation": {"chainId": 31337, "observedAt": "2000-01-01T00:00:00Z"},
}


def accept_verified_result(baser):
    """Commit one known initial result with minimal association facts and target."""
    return acceptance_service(baser).accept(
        "association",
        nonce="acceptance-nonce",
        sources={"le": "le", "qvi": "qvi"},
        associationFacts={
            "issuerAid": "issuer",
            "leSaid": "le",
            "extId": "eip155:31337:0x" + "12" * 20,
            "issuanceAnchor": {"sequenceNumber": 3, "said": "anchor"},
        },
        destination="https://receiver.example/hook",
    )


def acceptance_service(baser):
    """Compose offline acceptance operations over a test-owned application store."""
    from eoa_verifier.associations.accepting import AcceptanceService

    return AcceptanceService(
        AssociationReader(baser),
        AssociationWriter(baser),
        verification_reader=VerificationReader(baser),
    )


def revocation_service(baser, rgy=None):
    """Compose idempotent revocation; KERIpy evidence is optional for direct operations."""
    from eoa_verifier.associations.evidence import AssociationEvidence
    from eoa_verifier.associations.revoking import RevocationService

    return RevocationService(
        AssociationReader(baser),
        AssociationWriter(baser),
        AssociationEvidence(rgy),
        delivery_reader=DeliveryReader(baser),
    )


def accept_chained(baser, said, *, le="le", qvi="qvi", destination=HOOK):
    """Verify and accept one association chained to the named LE and QVI credentials."""
    enqueue_verification(baser, VerificationRecord(said, "grant"))
    verification = verification_service(baser)
    verification.start_pending(verification.next_pending())
    verification.finish(VerificationResult(said, "verified", eoaResult=EOA_RESULT))
    return acceptance_service(baser).accept(
        said,
        associationFacts={"issuerAid": "issuer", "leSaid": le},
        nonce=f"{said}-nonce",
        sources={"le": le, "qvi": qvi},
        destination=destination,
    )


def chain_registry(credentials, states):
    """Return a Regery stand-in exposing only stored credentials and TEL states.

    credentials maps SAID to an edge dict; states maps SAID to its TEL ilk. Unit
    tests seed these facts; witnessed issuance belongs to the integration suite.
    """
    stored = {
        said: SimpleNamespace(
            said=said,
            regi="registry",
            issuer="issuer",
            edge=edge,
            attrib={"extId": "eip155:31337:0x" + "12" * 20},
            sad={"u": f"{said}-nonce"},
        )
        for said, edge in credentials.items()
    }

    def vc_state(said):
        """Return the seeded TEL state, or None for a credential with no TEL events."""
        return (
            SimpleNamespace(et=states[said], a={"s": 3, "d": "anchor"})
            if said in states
            else None
        )

    def lookup(keys):
        """Mirror the keyed get used for saved and creds tables."""
        return stored.get(keys[0])

    return SimpleNamespace(
        reger=SimpleNamespace(
            saved=SimpleNamespace(get=lookup),
            creds=SimpleNamespace(get=lookup),
            tevers={"registry": SimpleNamespace(vcState=vc_state)},
        )
    )
