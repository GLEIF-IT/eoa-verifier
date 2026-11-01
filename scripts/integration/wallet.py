"""Public local-demo Ethereum wallets and canonical typed-data signing.

These numbered keys are intentionally public test constants. They must never
hold real assets. An external wallet can instead sign the exported challenge;
the demo issuer requires only its signature, never that wallet's private key.
"""

# The existing fixture/scenario wallets, now shared with the interactive driver.
TEST_KEYS = {1: "0x" + "0" * 63 + "1", 2: "0x" + "0" * 63 + "2"}


def wallet_address(number: int) -> str:
    """Return the lowercase address of a numbered public test wallet."""
    from eth_account import Account

    return Account.from_key(TEST_KEYS[number]).address.lower()


def sign_challenge(challenge: dict, number: int) -> dict:
    """Sign only the canonical association challenge for the selected test wallet.

    Return a portable signature JSON object. Reject another wallet or a modified
    type/domain definition before signing; this is not a general-purpose signer.
    """
    from eth_account import Account
    from eth_account.messages import encode_typed_data

    from eoa_verifier.verification.eoa import build_challenge

    message = challenge["message"]
    expected = build_challenge(
        issuer_aid=message["issuerAid"],
        le_vlei_said=message["leVleiSaid"],
        ext_id=message["extId"],
        nonce=message["nonce"],
    )
    if challenge != expected or message["extId"].split(":")[2] != wallet_address(
        number
    ):
        raise ValueError(
            "Challenge does not match the selected wallet and association profile"
        )
    signature = Account.sign_message(
        encode_typed_data(full_message=challenge), TEST_KEYS[number]
    ).signature
    return {"signature": "0x" + signature.hex()}


def fund_wallet(configuration: dict, address: str) -> None:
    """Give an empty local Anvil demo account 1,000 test ETH; preserve spent balances on restart."""
    import json

    from .services import request_json, validate_local_rpc

    validate_local_rpc(configuration["rpcUrl"])
    response = request_json(
        configuration["rpcUrl"],
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "eth_getBalance",
                "params": [address, "latest"],
            }
        ).encode(),
        headers={"Content-Type": "application/json"},
    )
    if "error" in response:
        raise ValueError(f"Cannot read local demo balance: {response['error']}")
    if int(response["result"], 16) == 0:
        response = request_json(
            configuration["rpcUrl"],
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "anvil_setBalance",
                    "params": [address, hex(1000 * 10**18)],
                }
            ).encode(),
            headers={"Content-Type": "application/json"},
        )
        if "error" in response:
            raise ValueError(f"Cannot fund local demo wallet: {response['error']}")
