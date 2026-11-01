"""Detached history reads release LMDB readers before application decisions."""

from keri.db import dbing

from eoa_verifier.persistence.basing import VerifierBaser
from eoa_verifier.persistence.reading import ApplicationReader
from eoa_verifier.persistence.records import AcceptedNonce, AssociationStatus
from tests.support.acceptance import association_integrity


def test_history_pages_detach_before_audit_and_survive_store_close():
    """Audit more than one page without a live reader or missing boundary records."""
    with dbing.openLMDB(cls=VerifierBaser) as baser:
        for index in range(129):
            said, nonce = f"credential-{index:03}", f"nonce-{index:03}"
            baser.accepted_nonces.put(
                keys=("issuer", nonce), val=AcceptedNonce("issuer", nonce, said)
            )
            baser.associations.put(
                keys=(said,),
                val=AssociationStatus(
                    said, "accepted", "", {"issuerAid": "issuer"}, {}
                ),
            )
        reader = ApplicationReader(baser)
        first = reader.nonce_page()
        second = reader.nonce_page(first[-1][0])
        assert len(first) == 128 and len(second) == 1
        assert reader.nonce_page(second[-1][0]) == []
        assert "(no active readers)" in baser.env.readers()
        association_integrity(baser).validate_nonce_history()
        assert "(no active readers)" in baser.env.readers()
    assert first[0][1].associationSaid == "credential-000"
    assert second[0][1].associationSaid == "credential-128"
