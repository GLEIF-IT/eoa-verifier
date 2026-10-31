"""The packaged schema, proof inputs and acceptance keys share one ASCII contract."""

from importlib.resources import files

import pytest
from jsonschema import Draft7Validator
from keri.core import scheming
from keri.db import dbing

from keripy_helpers import candidate
from eoa_verifier.persistence.basing import VerifierBaser
from eoa_verifier.persistence.records import PendingVerification, VerificationResult
from eoa_verifier.verification.constants import ASSOCIATION_SCHEMA
from eoa_verifier.verification.eoa import validate_nonce


def schema():
    return scheming.Schemer(
        raw=files("eoa_verifier.verification")
        .joinpath("schema_data/external-association-v1.json")
        .read_bytes()
    )


@pytest.mark.parametrize(
    "nonce", ["x", "N" * 128, "aZ09_-", "25C89E61-21F8-4CCF-948D-46D1FBB7BAE8"]
)
def test_ascii_boundaries_are_preserved_in_schema_and_lmdb(nonce):
    contract = schema()
    assert contract.said == ASSOCIATION_SCHEMA
    credential = candidate()
    credential["u"] = (
        nonce  # Shape validation only; this mutation is not a signed proof.
    )
    Draft7Validator(contract.sed).validate(credential)
    validate_nonce(nonce)
    with dbing.openLMDB(cls=VerifierBaser) as baser:
        issuer = credential["i"]
        key = baser.nonce_key(issuer, nonce)
        assert key == f"{issuer}.{nonce}".encode("ascii")
        assert len(key) <= 173 < baser.env.max_key_size()


@pytest.mark.parametrize(
    "nonce",
    [
        "",
        "N" * 129,
        "é",
        "e\u0301",
        "😀",
        " nonce",
        "nonce ",
        "nonce.nonce",
        "nonce\n",
        "nonce\r",
        "nonce\x00",
        "nonce/",
        "nonce+",
        "nonce=",
        None,
        7,
    ],
)
def test_invalid_nonce_is_rejected_without_consumption(nonce):
    credential = candidate()
    credential["u"] = nonce
    assert not Draft7Validator(schema().sed).is_valid(credential)
    with pytest.raises(ValueError, match="nonce"):
        validate_nonce(nonce)
    with dbing.openLMDB(cls=VerifierBaser) as baser:
        baser.enqueue(PendingVerification("candidate", "grant"))
        baser.finish(
            VerificationResult(
                "candidate",
                "verified",
                eoaResult={"wallet": "wallet", "accountObservation": {}},
            )
        )
        with pytest.raises(ValueError, match="nonce"):
            baser.accept(
                "candidate", association={"issuerAid": credential["i"]}, nonce=nonce
            )
        assert (
            baser.accepted_nonces.cntAll()
            == baser.associations.cntAll()
            == baser.outbox.cntAll()
            == 0
        )
