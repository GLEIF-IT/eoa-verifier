"""conftest.py."""

import pytest
from keri import core
from keri.db import dbing

from eoa_verifier.persistence.basing import VerifierBaser
from eoa_verifier.persistence.records import VerificationRecord, VerificationResult
from eoa_verifier.runtime.config import ServiceConfig


@pytest.fixture
def config(tmp_path):
    """Return isolated persistent stores under tmp_path, an ephemeral listener and an unused RPC URL."""
    return ServiceConfig(
        trusted_geda_aid=core.Signer().verfer.qb64,
        rpc_url="http://127.0.0.1:1",
        chain_id=31337,
        head_dir=str(tmp_path),
        http_port=0,
    )


@pytest.fixture
def verified_store(tmp_path):
    """Yield durable initial results; these fixture facts are not cryptographic evidence."""
    with dbing.openLMDB(
        cls=VerifierBaser, name="acceptance", headDirPath=str(tmp_path), temp=False
    ) as baser:
        baser.enqueue(VerificationRecord("association", "grant"))
        baser.next_verification(now=0)
        baser.finish(
            VerificationResult(
                "association",
                "verified",
                eoaResult={
                    "wallet": "0x" + "12" * 20,
                    "accountObservation": {
                        "chainId": 31337,
                        "blockNumber": 42,
                        "blockHash": "0x" + "34" * 32,
                        "code": "0x",
                        "observedAt": "2000-01-01T00:00:00Z",
                    },
                },
            )
        )
        yield baser
