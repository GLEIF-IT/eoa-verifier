"""Construct concrete association services and seed accepted fixture status at their explicit boundaries."""

from eoa_verifier.persistence.associations import AssociationReader, AssociationWriter
from eoa_verifier.persistence.delivery import DeliveryReader
from eoa_verifier.persistence.verification import VerificationReader


def accept_verified_result(baser):
    """Commit one known initial result with minimal association facts and target."""
    return acceptance_service(baser).accept(
        "association",
        nonce="acceptance-nonce",
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
