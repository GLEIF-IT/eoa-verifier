"""verification/test_eoa.py."""

from importlib.resources import files

import pytest
from jsonschema import Draft7Validator
from keri.core import scheming

from eoa_verifier.verification.constants import ASSOCIATION_SCHEMA
from eoa_verifier.verification.eoa import validate_nonce
from tests.support.issuers import candidate


def schema():
    return scheming.Schemer(
        raw=files("eoa_verifier.verification")
        .joinpath("schema_data/external-association-v1.json")
        .read_bytes()
    )


@pytest.mark.parametrize(
    "nonce", ["x", "N" * 128, "aZ09_-", "25C89E61-21F8-4CCF-948D-46D1FBB7BAE8"]
)
def test_ascii_boundaries_are_preserved_in_schema(nonce):
    contract = schema()
    assert contract.said == ASSOCIATION_SCHEMA
    credential = candidate()
    credential["u"] = (
        nonce  # Shape validation only; this mutation is not a signed proof.
    )
    Draft7Validator(contract.sed).validate(credential)
    validate_nonce(nonce)


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
def test_invalid_nonce_is_rejected_by_schema_and_proof(nonce):
    credential = candidate()
    credential["u"] = nonce
    assert not Draft7Validator(schema().sed).is_valid(credential)
    with pytest.raises(ValueError, match="nonce"):
        validate_nonce(nonce)
