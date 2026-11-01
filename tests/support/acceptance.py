"""support/acceptance.py."""


def accept_verified_result(baser):
    """Commit one known initial result with minimal association facts and target."""
    return baser.accept(
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
