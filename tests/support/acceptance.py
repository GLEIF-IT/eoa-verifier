"""support/acceptance.py."""


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
        peer_aid="peer",
    )


def acceptance_service(baser):
    """Compose offline acceptance operations over a test-owned application store."""
    from eoa_verifier.associations.accepting import AcceptanceService
    from eoa_verifier.persistence.reading import ApplicationReader
    from eoa_verifier.persistence.writing import ApplicationWriter

    return AcceptanceService(ApplicationReader(baser), ApplicationWriter(baser))


def revocation_service(baser, rgy=None):
    """Compose idempotent revocation; KERIpy evidence is optional for direct operations."""
    from eoa_verifier.associations.evidence import AssociationEvidence
    from eoa_verifier.associations.revoking import RevocationService
    from eoa_verifier.persistence.reading import ApplicationReader
    from eoa_verifier.persistence.writing import ApplicationWriter

    return RevocationService(
        ApplicationReader(baser), ApplicationWriter(baser), AssociationEvidence(rgy)
    )
