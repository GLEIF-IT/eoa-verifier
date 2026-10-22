"""Isolated service configuration shared by runtime and intake tests."""

import pytest
from keri import core

from eoa_verifier.serving import ServiceConfig


@pytest.fixture
def config(tmp_path):
    return ServiceConfig(
        trusted_geda_aid=core.Signer().verfer.qb64,
        rpc_url="http://127.0.0.1:1",
        chain_id=31337,
        head_dir=str(tmp_path),
        http_port=0,
    )
