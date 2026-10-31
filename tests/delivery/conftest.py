"""delivery/conftest.py."""

from contextlib import ExitStack

import pytest
from keri.app import habbing
from keri.db import dbing

from eoa_verifier.delivery.authing import ServiceAuthenticator
from eoa_verifier.persistence.basing import VerifierBaser


@pytest.fixture
def peers(tmp_path):
    """Open KERIpy signer/receiver identities and isolated persistent replay stores."""
    with ExitStack() as stack:
        a = stack.enter_context(habbing.openHby(name="a", temp=True))
        b = stack.enter_context(habbing.openHby(name="b", temp=True))
        ah = a.makeHab(name="a")
        bh = b.makeHab(name="b")
        a.psr.parse(ims=bytearray(bh.makeOwnEvent(sn=0)))
        b.psr.parse(ims=bytearray(ah.makeOwnEvent(sn=0)))
        ab = stack.enter_context(dbing.openLMDB(cls=VerifierBaser, name="a", temp=True))
        bb = VerifierBaser(name="b", headDirPath=str(tmp_path), temp=False)
        stack.callback(bb.close)
        yield (
            ServiceAuthenticator(hab=ah, baser=ab, peer_aid=bh.pre),
            ServiceAuthenticator(hab=bh, baser=bb, peer_aid=ah.pre),
        )


@pytest.fixture
def outbox(tmp_path):
    """Keep real application delivery records across reopen; no credential verification is simulated."""
    with dbing.openLMDB(
        cls=VerifierBaser, name="retry", headDirPath=str(tmp_path), temp=False
    ) as baser:
        yield baser
