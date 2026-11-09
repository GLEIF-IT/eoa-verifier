"""Direct and upstream revocation policy, fan-out, replay and dead letters."""

import json
from types import SimpleNamespace

import pytest
from keri.db import dbing

from eoa_verifier.persistence.registry import VerifierReger
from tests.support.acceptance import (
    accept_chained,
    accept_verified_result,
    revocation_service,
)


@pytest.fixture
def reger(tmp_path):
    """Yield the real persistent revocation queue, without any KERIpy TEL simulation."""
    with dbing.openLMDB(
        cls=VerifierReger, name="upstream", headDirPath=str(tmp_path), temp=False
    ) as store:
        yield store


def service_for(baser, reger):
    """Compose the production revocation stages over the fixture's two stores."""
    return revocation_service(baser, SimpleNamespace(reger=reger))


def queue(reger, cred_said, tel_said="tel"):
    """Seed one accepted-TEL revocation record as VerifierReger.putTel would."""
    reger.revocations.put(keys=(cred_said,), val=tel_said)


def test_unrelated_credential_is_acknowledged_with_no_writes(verified_store, reger):
    """A credential with no association or link row changes no application table."""
    baser = verified_store
    accept_chained(baser, "first")
    service = service_for(baser, reger)
    queue(reger, "same-schema-other-credential")
    before = baser.env.info()["last_txnid"]
    service.process_one()
    assert baser.env.info()["last_txnid"] == before
    assert reger.next_revocation() is None
    assert baser.revocation_work.cntAll() == 0
    assert baser.associations.get(keys=("first",)).status == "accepted"
