"""External-association profile conformance against the installed verifier schema."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from importlib.resources import files

import pytest
from eoa_verifier.verification.eoa import (
    build_challenge,
    ext_id_chain,
    verify_eoa_proof,
)
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import keccak
from jsonschema import Draft7Validator, ValidationError
from keri.core import coring, scheming, serdering, signing

# Owned protocol reference assets copied outside the checkout for wheel qualification.
PROTOCOL = Path(__file__).resolve().parents[2] / "protocol" / "external-association-v1"

# EOA proof/challenge vectors; the carrier schema comes from the installed package.
EOA_PROFILE = PROTOCOL / "eoa-v1"


def load(name: str) -> dict:
    """Read a named conformance JSON asset, obtaining the schema from the installed package.

    association.schema.json is a lookup label for the sole packaged schema, not
    a second authored schema. Other names refer to owned EOA-profile vectors.
    """
    if name == "association.schema.json":
        return json.loads(schema_raw())
    return json.loads((EOA_PROFILE / name).read_bytes())


def schema_raw() -> bytes:
    """Return the exact schema bytes packaged in the installed Verifier wheel."""
    return files("eoa_verifier.verification").joinpath(
        "schema_data/external-association-v1.json"
    ).read_bytes()


def test_reproduce_exact_schema_proof_and_acdc_bytes() -> None:
    """Reconstruct the published ACDC bytes and verify the schema, credential and nested block SAIDs."""
    schema = load("association.schema.json")
    association = load("association.json")
    reconstructed = serdering.SerderACDC(sad=association, makify=True)
    assert reconstructed.raw == (EOA_PROFILE / "association.json").read_bytes()
    assert (
        scheming.Schemer(raw=schema_raw()).said
        == schema["$id"]
    )
    assert (
        serdering.SerderACDC(raw=(EOA_PROFILE / "association.json").read_bytes()).said
        == association["d"]
    )
    for block in [
        association,
        association["a"],
        association["a"]["proof"],
        association["e"],
    ]:
        assert coring.Saider(qb64=block["d"]).verify(sad=block, prefixed=True)
    assert association["s"] == schema["$id"]


def test_signature_tampering_invalidates_proof_and_enclosing_acdc() -> None:
    """A changed proof signature invalidates both its block SAID and the enclosing credential SAID."""
    association = load("association.json")
    proof = association["a"]["proof"]
    proof["sig"] = "0x" + "00" * 64 + "1b"
    assert not coring.Saider(qb64=proof["d"]).verify(sad=proof, prefixed=True)
    assert not coring.Saider(qb64=association["d"]).verify(
        sad=association, prefixed=True
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "issuee",
        "lei",
        "nonce_attribute",
        "expiry",
        "oor_edge",
        "missing_proof",
        "missing_u",
        "invalid_algorithm_type",
        "wrong_tag",
        "wrong_edge_operator",
    ],
)
def test_reject_obsolete_or_incomplete_shapes(
    mutation: str,
) -> None:
    """Require the current untargeted carrier shape and reject each obsolete or missing-field mutation."""
    association = load("association.json")
    if mutation == "issuee":
        association["a"]["i"] = association["i"]
    elif mutation == "lei":
        association["a"]["LEI"] = "529900TEST"
    elif mutation == "nonce_attribute":
        association["a"]["nonce"] = association["u"]
    elif mutation == "expiry":
        association["a"]["expiresAt"] = 1791244900
    elif mutation == "oor_edge":
        association["e"]["oor"] = deepcopy(association["e"]["le"])
    elif mutation == "missing_proof":
        del association["a"]["proof"]
    elif mutation == "missing_u":
        del association["u"]
    elif mutation == "invalid_algorithm_type":
        association["a"]["proof"]["alg"] = 7
    elif mutation == "wrong_tag":
        association["a"]["proof"]["tag"] = "other/v1"
    else:
        association["e"]["le"]["o"] = "NI2I"
    with pytest.raises(ValidationError):
        Draft7Validator(load("association.schema.json")).validate(association)


@pytest.mark.parametrize("algorithm", ["EIP-191/ES256K", "Ed25519"])
def test_schema_accepts_external_proof_algorithm_identifiers(algorithm: str) -> None:
    """The carrier schema admits other profile algorithm names; EOA support is a separate policy check."""
    association = load("association.json")
    association["a"]["proof"]["alg"] = algorithm
    Draft7Validator(load("association.schema.json")).validate(association)


def test_schema_requires_nonempty_algorithm_identifier() -> None:
    """Reject an empty proof algorithm at the carrier-schema boundary."""
    association = load("association.json")
    association["a"]["proof"]["alg"] = ""
    with pytest.raises(ValidationError):
        Draft7Validator(load("association.schema.json")).validate(association)


@pytest.mark.parametrize(
    "ext_id", ["did:example:organization", "external:organization"]
)
def test_schema_accepts_profile_defined_external_identifiers(ext_id: str) -> None:
    """Keep the carrier schema extensible to external identifiers beyond the EOA profile."""
    association = load("association.json")
    association["a"]["extId"] = ext_id
    Draft7Validator(load("association.schema.json")).validate(association)


@pytest.mark.parametrize("ext_id", ["", 7])
def test_schema_requires_nonempty_external_identifier_string(ext_id: object) -> None:
    """Reject empty or non-string external identifiers before profile-specific interpretation."""
    association = load("association.json")
    association["a"]["extId"] = ext_id
    with pytest.raises(ValidationError):
        Draft7Validator(load("association.schema.json")).validate(association)


@pytest.mark.parametrize(
    "signature", ["dGVzdC1zaWduYXR1cmU=", "external-signature-value"]
)
def test_schema_accepts_profile_defined_signature_strings(signature: str) -> None:
    """Allow profile-defined signature strings in the carrier without claiming EOA-proof validity."""
    association = load("association.json")
    association["a"]["proof"]["sig"] = signature
    Draft7Validator(load("association.schema.json")).validate(association)


@pytest.mark.parametrize("signature", ["", 7])
def test_schema_requires_nonempty_signature_string(signature: object) -> None:
    """Reject empty or non-string signature values at the carrier-schema boundary."""
    association = load("association.json")
    association["a"]["proof"]["sig"] = signature
    with pytest.raises(ValidationError):
        Draft7Validator(load("association.schema.json")).validate(association)


def test_association_schema_and_payloads_have_no_intrinsic_expiry() -> None:
    """Keep the packaged schema and signed challenge free of intrinsic association-expiry fields."""
    for name in [
        "association.schema.json",
        "challenge.json",
    ]:
        assert "expiresAt" not in json.dumps(load(name))


@pytest.mark.parametrize(
    "ext_id",
    [
        "eip155:01:0x" + "ab" * 20,
        "eip155:0:0x" + "ab" * 20,
        "eip155:1:0x" + "AB" * 20,
        "eip155:-1:0x" + "ab" * 20,
        "eip155:" + "1" * 33 + ":0x" + "ab" * 20,
        "cosmos:1:0x" + "ab" * 20,
        "eip155:1:0x123",
        "eip155:" + str(2**256) + ":0x" + "ab" * 20,
    ],
)
def test_reject_noncanonical_chain_or_account(ext_id: str) -> None:
    """Reject unsupported namespaces and noncanonical chain/account spellings rather than normalizing them."""
    with pytest.raises(ValueError):
        ext_id_chain(ext_id)


@pytest.mark.parametrize(
    "nonce",
    [
        "25C89E61-21F8-4CCF-948D-46D1FBB7BAE8",
        "0123456789abcdef" * 4,
        "0AAAAQIDBAUGBwgJCgsMDQ4P",
        "x",
        "N" * 128,
    ],
)
def test_nonce_encoding_is_preserved_in_challenge_and_credential(nonce: str) -> None:
    """Sign each allowed nonce exactly as stored in the credential, preserving case and bytes."""
    fixture = load("association.json")
    values = {
        "issuer_aid": fixture["i"],
        "le_vlei_said": fixture["e"]["le"]["n"],
        "ext_id": fixture["a"]["extId"],
        "nonce": nonce,
    }
    challenge = build_challenge(**values)
    private_key = load("test-vector.json")["publicTestPrivateKey"]
    signature = Account.sign_message(
        encode_typed_data(full_message=challenge), private_key
    ).signature
    fixture["u"] = nonce
    assert challenge["message"]["nonce"] == fixture["u"] == nonce
    Draft7Validator(load("association.schema.json")).validate(fixture)
    assert (
        Account.recover_message(
            encode_typed_data(full_message=challenge), signature=signature
        )
        == Account.from_key(private_key).address
    )


@pytest.mark.parametrize(
    "nonce",
    [
        "",
        "x" * 129,
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
def test_nonce_type_and_length_match_schema_and_challenge(nonce: object) -> None:
    """Keep schema and challenge validation aligned for malformed, non-ASCII and oversized nonces."""
    association = load("association.json")
    association["u"] = nonce
    with pytest.raises(ValidationError):
        Draft7Validator(load("association.schema.json")).validate(association)
    values = {
        "issuer_aid": association["i"],
        "le_vlei_said": association["e"]["le"]["n"],
        "ext_id": association["a"]["extId"],
        "nonce": nonce,
    }
    with pytest.raises(ValueError, match="nonce"):
        build_challenge(**values)


def test_challenge_matches_known_signature_and_hashes() -> None:
    """Match the published typed data, domain/message hashes, signing digest and recovered wallet."""
    association = load("association.json")
    challenge = build_challenge(
        issuer_aid=association["i"],
        le_vlei_said=association["e"]["le"]["n"],
        ext_id=association["a"]["extId"],
        nonce=association["u"],
    )
    assert challenge == load("challenge.json")
    vector = load("test-vector.json")
    signable = encode_typed_data(full_message=challenge)
    assert "0x" + signable.header.hex() == vector["domainSeparator"]
    assert "0x" + signable.body.hex() == vector["messageHash"]
    assert (
        "0x"
        + keccak(b"\x19" + signable.version + signable.header + signable.body).hex()
        == vector["signingDigest"]
    )
    assert (
        Account.recover_message(
            encode_typed_data(full_message=challenge), signature=vector["signature"]
        )
        == vector["signer"]
    )


@pytest.mark.parametrize(
    "field", ["issuer", "le", "account", "chain", "nonce", "domain"]
)
def test_signature_cannot_be_transplanted(field: str) -> None:
    """Changing any bound issuer, LE, wallet, chain, nonce or domain prevents reuse of the proof."""
    association = load("association.json")
    if field == "issuer":
        association["i"] = signing.Signer(raw=b"\x02" * 32).verfer.qb64
    elif field == "le":
        association["e"]["le"]["n"] = association["ri"]
    elif field == "account":
        association["a"]["extId"] = "eip155:1:0x" + "ab" * 20
    elif field == "chain":
        association["a"]["extId"] = association["a"]["extId"].replace(
            "eip155:1:", "eip155:2:"
        )
    elif field == "nonce":
        association["u"] = "another-ceremony"
    elif field == "domain":
        association["a"]["proof"]["tag"] = "another-protocol/v1"
    with pytest.raises(ValueError, match="signer|domain"):
        verify_eoa_proof(association)


@pytest.mark.parametrize(
    "field,value,reason",
    [
        ("alg", "Ed25519", "algorithm"),
        ("sig", "0x1234", "encoding"),
        ("sig", "0x" + "00" * 64 + "1b", "scalars"),
        ("sig", "0x" + "01" * 32 + "ff" * 32 + "1b", "scalars"),
    ],
)
def test_invalid_eoa_proof_fails_before_rpc(field, value, reason):
    """Reject unsupported algorithms, malformed encoding and invalid scalars at the pure proof boundary."""
    association = load("association.json")
    association["a"]["proof"][field] = value
    with pytest.raises(ValueError, match=reason):
        verify_eoa_proof(association)


def test_profile_identifies_the_signed_wallet() -> None:
    """Validate the carrier and require its canonical wallet to match EIP-712 signer recovery."""
    association = load("association.json")
    validator = Draft7Validator(load("association.schema.json"))
    validator.check_schema(validator.schema)
    validator.validate(association)
    signer = Account.recover_message(
        encode_typed_data(full_message=load("challenge.json")),
        signature=association["a"]["proof"]["sig"],
    )
    assert signer.lower() == association["a"]["extId"].split(":")[2]


@pytest.mark.parametrize("field", ["issuer_aid", "le_vlei_said"])
def test_challenge_rejects_trailing_cesr_identifier_material(field: str) -> None:
    """Reject valid CESR prefixes followed by extra material when constructing a challenge."""
    association = load("association.json")
    values = {
        "issuer_aid": association["i"],
        "le_vlei_said": association["e"]["le"]["n"],
        "ext_id": association["a"]["extId"],
        "nonce": association["u"],
    }
    values[field] += "extra"
    with pytest.raises(ValueError, match="trailing"):
        build_challenge(**values)


def test_large_caip_reference_preserves_integer_precision() -> None:
    """Represent the maximum profile chain reference as exact decimal text in typed data."""
    association = load("association.json")
    chain_id = 10**32 - 1
    ext_id = f"eip155:{chain_id}:{load("test-vector.json")["signer"].lower()}"
    challenge = build_challenge(
        issuer_aid=association["i"],
        le_vlei_said=association["e"]["le"]["n"],
        ext_id=ext_id,
        nonce=association["u"],
    )
    assert challenge["domain"]["chainId"] == str(chain_id)


def test_optional_acdc_timestamp_accepts_keripy_utc_form() -> None:
    """Pin the schema to KERIpy's explicit UTC-offset spelling for the optional ACDC timestamp."""
    association = load("association.json")
    validator = Draft7Validator(load("association.schema.json"))
    association["a"]["dt"] = "2026-10-06T00:00:00.000000+00:00"
    validator.validate(association)
    association["a"]["dt"] = "2026-10-06T00:00:00.000000Z"
    with pytest.raises(ValidationError):
        validator.validate(association)
