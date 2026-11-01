"""delivery/conftest.py."""

import pytest
from keri.app import habbing
from keri.db import dbing

from eoa_verifier.delivery.authing import HttpSignatures
from eoa_verifier.delivery.keys import ServiceKeys
from eoa_verifier.persistence.basing import VerifierBaser


@pytest.fixture
def peers():
    """Share accepted KERI signer keys without any transport replay database."""
    with (
        habbing.openHby(name="a", temp=True) as a,
        habbing.openHby(name="b", temp=True) as b,
    ):
        ah, bh = a.makeHab(name="a"), b.makeHab(name="b")
        a.psr.parse(ims=bytearray(bh.makeOwnEvent(sn=0)))
        b.psr.parse(ims=bytearray(ah.makeOwnEvent(sn=0)))
        yield HttpSignatures(ServiceKeys(ah)), HttpSignatures(ServiceKeys(bh))


@pytest.fixture
def outbox(tmp_path):
    """Keep real application delivery records across reopen; no credential verification is simulated."""
    with dbing.openLMDB(
        cls=VerifierBaser, name="retry", headDirPath=str(tmp_path), temp=False
    ) as baser:
        yield baser
