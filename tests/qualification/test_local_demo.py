"""The Bash demo uses real installed services, witnessed issuance and a funded local chain."""

import json
import os
import subprocess
from pathlib import Path

from eth_account import Account
from eth_account.messages import encode_typed_data

from scripts.integration.artifacts import load_json, source_revision
from scripts.integration.services import request_json


def test_local_demo_acceptance_revocation_and_restart(tmp_path):
    """Drive the external-signature path through the public Bash CLI, then prove durable restart.

    Use a fresh installed wheel, native LE holder and independent witness/receiver/
    Verifier processes. No application acceptance or nonce records are seeded.
    """
    source = Path(__file__).resolve().parents[2]
    wheel = os.environ.get("EOA_VERIFIER_WHEEL")
    assert wheel and Path(wheel).is_file(), (
        "EOA_VERIFIER_WHEEL must select a fresh wheel"
    )
    root = tmp_path / "a space's $demo"
    base = ["bash", str(source / "scripts/demo.sh"), "--run-dir", str(root)]

    def invoke(*args, success=True):
        """Run one real CLI command and retain its errors; never evaluate shell argument text."""
        result = subprocess.run(
            [*base, *args], cwd=source, text=True, capture_output=True, timeout=180
        )
        assert (result.returncode == 0) == success, (
            result.stdout,
            result.stderr,
            str(root),
        )
        return result.stdout

    try:
        setup = subprocess.run(
            [
                *base,
                "--verifier-wheel",
                wheel,
                "--tool-revision",
                os.getenv("GITHUB_SHA") or source_revision(source),
                "up",
            ],
            cwd=source,
            text=True,
            capture_output=True,
            timeout=180,
        )
        assert setup.returncode == 0, (setup.stdout, setup.stderr, str(root))
        config = load_json(root / "run.json")
        assert "1.5.1" in config["versions"]["anvil"]
        assert len(config["witnesses"]) == 1 and not config["dropAck"]
        for address in config["wallets"].values():
            balance = request_json(
                config["rpcUrl"],
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
            assert int(balance["result"], 16) == 1000 * 10**18
        descriptor = json.loads(
            invoke("challenge", "--wallet-address", config["wallets"]["2"])
        )
        invoke(
            "sign", success=False
        )  # External signing never accesses a private wallet key.
        challenge = load_json(Path(descriptor["challenge"]))
        signature = Account.sign_message(
            encode_typed_data(full_message=challenge), "0x" + "0" * 63 + "2"
        ).signature
        signature_file = tmp_path / "external signature.json"
        signature_file.write_text(json.dumps({"signature": "0x" + signature.hex()}))
        association = json.loads(
            invoke("issue", "--signature-file", str(signature_file))
        )
        accepted = json.loads(invoke("present"))
        assert accepted["status"] == "accepted" and accepted["delivery"]["delivered"]
        assert accepted["associationSaid"] == association["said"]
        revoked = json.loads(invoke("revoke"))
        assert revoked["status"] == "revoked" and revoked["delivery"]["delivered"]
        assert revoked["accountObservation"] == accepted["accountObservation"]
        events = json.loads(invoke("events"))
        assert [
            (item["event"]["status"], item["event"]["eventId"]) for item in events
        ] == [
            ("accepted", association["said"] + ":1"),
            ("revoked", association["said"] + ":2"),
        ]
        receiver_log = invoke("logs")
        assert "Webhook received" in receiver_log
        assert (
            association["said"] + ":1" in receiver_log
            and association["said"] + ":2" in receiver_log
        )
        invoke("clean", success=False)
        assert (root / "run.json").exists()
        request_json(
            config["rpcUrl"],
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "anvil_setBalance",
                    "params": [config["wallets"]["1"], hex(7 * 10**18)],
                }
            ).encode(),
            headers={"Content-Type": "application/json"},
        )
        invoke("down")
        reopened = json.loads(invoke("up"))
        assert reopened["verifierAid"] == config["verifierAid"]
        assert reopened["association"] == revoked
        assert json.loads(invoke("events")) == events
        assert json.loads(invoke("revoke")) == revoked
        balance = request_json(
            config["rpcUrl"],
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "eth_getBalance",
                    "params": [config["wallets"]["1"], "latest"],
                }
            ).encode(),
            headers={"Content-Type": "application/json"},
        )
        assert int(balance["result"], 16) == 7 * 10**18
        reused = json.loads(
            invoke("challenge", "--nonce", challenge["message"]["nonce"])
        )
        assert reused["directory"] != descriptor["directory"]
        assert (
            load_json(Path(reused["challenge"]))["message"]["nonce"]
            == challenge["message"]["nonce"]
        )
        # The one-command path must also work on an existing, restarted demo.
        second = json.loads(invoke("run", "--wallet", "1"))
        assert second["status"] == "accepted" and second["delivery"]["delivered"]
        assert second["associationSaid"] != association["said"]
        assert json.loads(invoke("revoke"))["status"] == "revoked"
        assert len(json.loads(invoke("events"))) == 4
    finally:
        if (root / "run.json").exists():
            invoke("down")
    invoke("clean")
    assert not root.exists()
