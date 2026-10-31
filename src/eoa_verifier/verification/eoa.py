"""Ethereum EOA identifiers, typed-data challenges, and proof verification."""

from __future__ import annotations

import re
from typing import Any

from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_keys.constants import SECPK1_N
from eth_keys.exceptions import BadSignature
from keri.core import coring

# Signed domain name and proof tag from the existing external-association v1 profile.
DOMAIN_TAG = "vlei-external-association/v1"

# Profile algorithm marker; changing it would change accepted credential semantics.
PROOF_ALGORITHM = "EIP-712/ES256K"
# EIP-712 primary struct name; its exact spelling participates in the signed hash.
PRIMARY_TYPE = "ExternalAssociation"


def validate_nonce(nonce: str) -> None:
    """Return None for an unchanged 1–256 character string; otherwise raise ValueError."""
    if not isinstance(nonce, str) or not 1 <= len(nonce) <= 256:
        raise ValueError("nonce must be a string of 1 to 256 characters")


def validate_association_identifiers(
    *, issuer_aid: str, le_vlei_said: str, nonce: str
) -> None:
    """Validate canonical issuer AID and LE credential SAID plus the nonce; return None.

    Use KERIpy CESR primitive decoders and reject trailing material. Invalid inputs raise
    ValueError or KERIpy material errors. This checks representation, not ownership.
    """
    validate_nonce(nonce)
    if coring.Prefixer(qb64=issuer_aid).qb64 != issuer_aid:
        raise ValueError("issuer AID must be canonical with no trailing material")
    if coring.Saider(qb64=le_vlei_said).qb64 != le_vlei_said:
        raise ValueError(
            "LE credential SAID must be canonical with no trailing material"
        )


def ext_id_chain(ext_id: str) -> int:
    """Return the integer chain ID from canonical lowercase eip155:chain:address text.

    Require a positive decimal chain reference of at most 32 digits within uint256,
    and a 20-byte lowercase address; aliases raise ValueError rather than being
    normalized after signing. This is syntax validation, not an Ethereum query.
    """
    if not isinstance(ext_id, str) or not re.fullmatch(
        r"eip155:[1-9][0-9]{0,31}:0x[0-9a-f]{40}", ext_id
    ):
        raise ValueError("external identifier must be canonical EOA CAIP-10")
    chain_id = int(ext_id.split(":")[1])
    if chain_id >= 2**256:
        raise ValueError("chain ID exceeds uint256")
    return chain_id


def build_challenge(
    *, issuer_aid: str, le_vlei_said: str, ext_id: str, nonce: str
) -> dict[str, Any]:
    """Return EIP-712 typed data reconstructed from committed association fields.

    issuer_aid, le_vlei_said, ext_id and nonce bind the issuer, LE edge, wallet/chain
    and credential nonce. Validate their representations; errors propagate. The
    fixed domain has no verifyingContract because this off-chain association is
    independent of any endorsement deployment. Nothing is signed or persisted here.
    """
    chain_id = ext_id_chain(ext_id)
    validate_association_identifiers(
        issuer_aid=issuer_aid, le_vlei_said=le_vlei_said, nonce=nonce
    )
    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
            ],
            PRIMARY_TYPE: [
                {"name": "issuerAid", "type": "string"},
                {"name": "leVleiSaid", "type": "string"},
                {"name": "extId", "type": "string"},
                {"name": "nonce", "type": "string"},
            ],
        },
        "primaryType": PRIMARY_TYPE,
        # Decimal text preserves large chain IDs through JSON clients; EIP-712
        # still encodes this field as uint256 according to the domain type.
        "domain": {"name": DOMAIN_TAG, "version": "1", "chainId": str(chain_id)},
        "message": {
            "issuerAid": issuer_aid,
            "leVleiSaid": le_vlei_said,
            "extId": ext_id,
            "nonce": nonce,
        },
    }


def verify_eoa_proof(association: dict[str, Any]) -> None:
    """Verify the EIP-712 signature in a schema-validated association dict; return None.

    Read i/u, e.le.n and a.extId/proof to reconstruct the challenge. Require the
    profile algorithm/domain, lowercase 65-byte hex signature with v=27/28, valid r
    and low-s (at most half the curve order), then match the recovered wallet.
    Policy/signature mismatches raise ValueError; malformed internal input may
    propagate KERIpy or programming errors. No network or acceptance check occurs.
    """
    attrs = association["a"]
    proof = attrs["proof"]
    if proof["alg"] != PROOF_ALGORITHM or proof["tag"] != DOMAIN_TAG:
        raise ValueError("unsupported EOA proof algorithm or domain")
    signature = proof["sig"]
    if not re.fullmatch(r"0x[0-9a-f]{128}(1b|1c)", signature):
        raise ValueError("invalid EOA signature encoding")
    raw = bytes.fromhex(signature[2:])
    r, s = int.from_bytes(raw[:32]), int.from_bytes(raw[32:64])
    if not 1 <= r < SECPK1_N or not 1 <= s <= SECPK1_N // 2:
        raise ValueError("EOA signature must have valid r and low-s scalars")
    challenge = build_challenge(
        issuer_aid=association["i"],
        le_vlei_said=association["e"]["le"]["n"],
        ext_id=attrs["extId"],
        nonce=association["u"],
    )
    wallet = attrs["extId"].split(":")[2]
    try:
        signer = Account.recover_message(
            encode_typed_data(full_message=challenge), signature=signature
        )
    except BadSignature as exc:
        raise ValueError("EOA proof signature cannot recover a signer") from exc
    if signer.lower() != wallet:
        raise ValueError("EOA proof signer does not match external identifier")


def verify_eoa_account(
    association: dict[str, Any], *, chain_id: int, code: bytes
) -> dict[str, str]:
    """Return {wallet: address} for the association and supplied chain/account facts.

    The caller supplies a previously proof-checked association, observed integer
    chain_id and raw code bytes. Require the matching chain and either empty code
    or exactly the EIP-7702 designation prefix plus a 20-byte address. Otherwise
    raise ValueError. This syntax rule neither inspects delegated code nor proves
    continued key possession; it describes the initial observation only.
    """
    if chain_id != ext_id_chain(association["a"]["extId"]):
        raise ValueError("association chain does not match configured network")
    # EIP-7702 represents delegation as 0xef0100 followed by a 20-byte address.
    if code and not (len(code) == 23 and code[:3] == b"\xef\x01\x00"):
        raise ValueError("external account has contract code, not an EOA delegation")
    return {"wallet": association["a"]["extId"].split(":")[2]}
