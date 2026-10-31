"""Generate vLEI External Association EOA examples and a known-answer test vector.

Run from any directory using the project's Python environment. The private key
below is the PUBLIC test key 1; it must never hold funds or sign real claims.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import keccak
from keri.core import serdering

from eoa_verifier.verification.eoa import (
    build_challenge,
)

ROOT = Path(__file__).resolve().parents[2]
EOA_PROFILE = ROOT / "protocol" / "external-association-v1" / "eoa-v1"
PUBLIC_TEST_KEY = "0x" + "0" * 63 + "1"


def generate_fixtures(association_raw: bytes) -> dict[str, bytes]:
    """Derive EOA vectors from a serialized ACDC without constructing a credential.

    The input uses public test key 1. KERIpy parses its ACDC; eth-account
    reproduces its signature. The input credential bytes are preserved exactly.
    """
    association = serdering.SerderACDC(raw=association_raw).sad
    issuer = association["i"]
    account = Account.from_key(PUBLIC_TEST_KEY)
    challenge = build_challenge(
        issuer_aid=issuer,
        le_vlei_said=association["e"]["le"]["n"],
        ext_id=association["a"]["extId"],
        nonce=association["u"],
    )
    signature = (
        "0x"
        + Account.sign_message(
            encode_typed_data(full_message=challenge), PUBLIC_TEST_KEY
        ).signature.hex()
    )
    if signature != association["a"]["proof"]["sig"]:
        raise ValueError(
            "association must contain the signature from public test key 1"
        )
    if association["a"]["extId"].split(":")[2] != account.address.lower():
        raise ValueError("association must identify the public test account")
    signable = encode_typed_data(full_message=challenge)
    hashes = {
        "domainSeparator": "0x" + signable.header.hex(),
        "messageHash": "0x" + signable.body.hex(),
        "signingDigest": "0x" + keccak(b"\x19" + signable.version + signable.header + signable.body).hex(),
    }
    vector = {
        "purpose": "Encoding fixture only; synthetic KERI evidence MUST NOT pass production verification.",
        "publicTestPrivateKey": PUBLIC_TEST_KEY,
        "signer": account.address,
        "typedData": challenge,
        **hashes,
        "signature": signature,
        "schemaSaid": association["s"],
        "associationSaid": association["d"],
        "proofSaid": association["a"]["proof"]["d"],
    }
    return {
        "challenge.json": json_bytes(challenge),
        "association.json": association_raw,
        "test-vector.json": json_bytes(vector),
    }


def json_bytes(value: object) -> bytes:
    """Pretty-print supporting fixtures; ACDC bytes use compact_json instead."""
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def main() -> None:
    """Derive the three EOA fixtures from an existing public-test-key association."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--association",
        type=Path,
        default=EOA_PROFILE / "association.json",
        help="serialized association ACDC signed with public test key 1",
    )
    args = parser.parse_args()
    for name, raw in generate_fixtures(args.association.read_bytes()).items():
        (EOA_PROFILE / name).write_bytes(raw)
    print("Association, challenge, and test vector generated.")


if __name__ == "__main__":
    main()
