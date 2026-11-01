"""Interactive local demo workflows over the maintained witnessed environment.

All identities, chain state, credentials and event artifacts belong to one demo
run. The normal Verifier receives evidence over HTTP; nothing here writes its
application records. Wallet signing remains separate from issuer KERI operations.
"""

import ctypes.util
import json
import os
import shutil
import sys
from contextlib import redirect_stdout
from pathlib import Path
from urllib.error import HTTPError
from uuid import uuid4

from .artifacts import load_json, save_json
from .environment import (
    load_run,
    prepare_run,
    present_credential,
    start_run,
    wait_for_status,
)
from .foundry import ensure_foundry
from .processes import is_running, process_records
from .services import request_json


def load_demo(root: Path) -> dict:
    """Read only an explicitly marked demo run; do not adopt qualification/operator stores."""
    configuration = load_run(root)
    if configuration.get("purpose") != "interactive-demo":
        raise ValueError("Not an interactive demo; choose a fresh --run-dir")
    return configuration


def prepare_demo(root: Path, source: Path, *, wheel=None, revision=None) -> dict:
    """Install qualified tools and build a fresh isolated witnessed LE holder when absent.

    Reopening retains all state and the snapshotted implementation. Foundry is
    installed in a user cache; the host installation and shell profile are untouched.
    """
    if root.exists():
        configuration = load_demo(root)
        if not configuration.get("prepared"):
            raise ValueError(
                "Preparation did not complete; inspect logs, then down/clean or choose a fresh --run-dir"
            )
        return configuration
    if sys.version_info < (3, 12, 6):
        raise ValueError("The demo requires Python 3.12.6 or newer")
    if not shutil.which("git"):
        raise ValueError("Install Git before preparing the demo")
    if not (
        ctypes.util.find_library("sodium") or ctypes.util.find_library("libsodium")
    ):
        raise ValueError(
            "Install libsodium first: brew install libsodium (macOS), or apt install libsodium-dev (Debian/Ubuntu)"
        )
    tools = ensure_foundry()
    os.environ["PATH"] = str(tools) + os.pathsep + os.environ.get("PATH", "")
    prepare_run(
        root,
        source,
        witness_count=1,
        wheel=wheel,
        tool_revision=revision,
        purpose="interactive-demo",
    )
    configuration = load_run(root)
    configuration.update(
        purpose="interactive-demo", dropAck=False, forge=str(tools / "forge")
    )
    save_json(root / "run.json", configuration)
    return configuration


def start_demo(root: Path, configuration: dict) -> dict:
    """Start owned witnesses/schema host, funded Anvil, receiver and installed Verifier.

    Seed the two public test wallets once. Persistent restart retains subsequent
    chain state and balances. Return public URLs, holder facts and artifact locations.
    """
    from .wallet import fund_wallet, wallet_address

    start_run(root, configuration)
    if not configuration.get("seeded"):
        configuration["wallets"] = {
            str(number): wallet_address(number) for number in (1, 2)
        }
        for address in configuration["wallets"].values():
            fund_wallet(configuration, address)
        configuration["seeded"] = True
        save_json(root / "run.json", configuration)
    return demo_status(root, configuration)


def demo_status(root: Path, configuration: dict) -> dict:
    """Describe owned processes, public identities/URLs and the current credential status."""
    status = {
        "runDir": str(root),
        "verifierUrl": configuration["verifierUrl"],
        "webhookUrl": configuration["webhookUrl"],
        "rpcUrl": configuration["rpcUrl"],
        "chainId": configuration["chainId"],
        "verifierAid": configuration["verifierAid"],
        "holder": load_json(root / "chain.json"),
        "wallets": configuration.get("wallets", {}),
        "forge": configuration["forge"],
        "receiverLog": str(root / "logs/receiver.log"),
        "processes": {
            name: is_running(record) for name, record in process_records(root).items()
        },
    }
    if (root / "demo.json").exists():
        status["ceremony"] = load_json(root / "demo.json")
        descriptor = Path(status["ceremony"]["directory"]) / "association.json"
        if descriptor.exists() and status["processes"].get("verifier"):
            said = load_json(descriptor)["said"]
            try:
                status["association"] = request_json(
                    configuration["verifierUrl"] + f"/v1/associations/{said}/status"
                )
            except HTTPError as error:
                if error.code != 404:
                    raise
                status["association"] = None
    return status


def require_running(root: Path) -> None:
    """Require this run's recorded services before network/issuer operations; never adopt a foreign peer."""
    records = process_records(root)
    if not all(
        name in records and is_running(records[name])
        for name in ("infrastructure", "anvil", "receiver", "verifier")
    ):
        raise ValueError("Demo services are stopped; run scripts/demo.sh up first")


def create_challenge(
    root: Path, configuration: dict, *, wallet=1, address=None, nonce=None
) -> dict:
    """Export a fresh canonical challenge from this demo's actual LE credential.

    A new directory retains every prior ceremony. An explicit external address
    needs no private key; its holder can supply a separate signature JSON file.
    """
    require_running(root)
    from eoa_verifier.verification.eoa import build_challenge, validate_nonce

    from .wallet import fund_wallet, wallet_address

    nonce = uuid4().hex if nonce is None else nonce
    validate_nonce(nonce)
    selected_wallet = None if address is not None else wallet
    address = address if address is not None else wallet_address(wallet)
    chain = load_json(root / "chain.json")
    challenge = build_challenge(
        issuer_aid=chain["issuerAid"],
        le_vlei_said=chain["leSaid"],
        ext_id=f"eip155:{configuration['chainId']}:{address}",
        nonce=nonce,
    )
    fund_wallet(configuration, address)
    # Artifact identity is independent of the signed nonce: do not add issuer-side
    # nonce policy. The Verifier alone decides whether a credential reuses one.
    directory = root / "ceremonies" / uuid4().hex
    directory.mkdir(parents=True)
    save_json(directory / "challenge.json", challenge)
    descriptor = {
        "directory": str(directory),
        "wallet": selected_wallet,
        "challenge": str(directory / "challenge.json"),
        "signature": str(directory / "signature.json"),
    }
    save_json(root / "demo.json", descriptor)
    return descriptor


def sign_wallet(root: Path, *, wallet=None) -> dict:
    """Sign the current exported challenge with a public test key, never an external private key."""
    from .wallet import sign_challenge

    descriptor = load_json(root / "demo.json")
    number = wallet if wallet is not None else descriptor["wallet"]
    if number is None:
        raise ValueError(
            "External wallet: sign challenge.json and use issue --signature-file FILE"
        )
    signature = sign_challenge(load_json(Path(descriptor["challenge"])), number)
    save_json(Path(descriptor["signature"]), signature)
    return {"signatureFile": descriptor["signature"], **signature}


def issue_credential(root: Path, *, signature_file=None) -> dict:
    """Verify the wallet's signature and issue the association using the actual local LE holder."""
    require_running(root)
    from .ceremony import complete_ceremony, open_ceremony

    descriptor = load_json(root / "demo.json")
    directory = Path(descriptor["directory"])
    if (directory / "association.json").exists():
        return load_json(directory / "association.json")
    challenge = load_json(Path(descriptor["challenge"]))
    signature = load_json(signature_file or Path(descriptor["signature"]))
    with redirect_stdout(sys.stderr), open_ceremony(root) as ceremony:
        association = complete_ceremony(
            ceremony,
            ceremony.issue_signed_association(challenge, signature["signature"]),
        )
    save_json(directory / "association.json", association)
    return association


def current_association(root: Path) -> dict:
    """Read the latest issued descriptor; the signed credential remains under credentials/SAID.json."""
    return load_json(
        Path(load_json(root / "demo.json")["directory"]) / "association.json"
    )


def present_association(root: Path, configuration: dict) -> dict:
    """IPEX-present the issued credential over HTTP; wait for accepted status AND webhook delivery."""
    require_running(root)
    association = current_association(root)
    present_credential(root, configuration, association["said"])
    return wait_for_status(configuration, association["said"], "accepted")


def revoke_association(root: Path, configuration: dict, *, said=None) -> dict:
    """Issue witnessed TEL revocation, present evidence and wait for the revoked webhook.

    Only an already accepted association is the demo's revocation target. Repeated
    invocation of an already delivered revocation returns stored status unchanged.
    """
    require_running(root)
    from .ceremony import complete_ceremony, open_ceremony

    said = said or current_association(root)["said"]
    status = request_json(
        configuration["verifierUrl"] + f"/v1/associations/{said}/status"
    )
    if status["status"] == "revoked":
        return wait_for_status(configuration, said, "revoked")
    if status["status"] != "accepted":
        raise ValueError("Present and accept the association before revoking it")
    with redirect_stdout(sys.stderr), open_ceremony(root) as ceremony:
        complete_ceremony(ceremony, ceremony.revoke_association(said))
    present_credential(root, configuration, said)
    return wait_for_status(configuration, said, "revoked")


def received_events(configuration: dict) -> list:
    """Return readable authenticated receiver events and their durable reception counts."""
    return [
        {"event": json.loads(item["body"]), "attempts": item["attempts"]}
        for item in request_json(configuration["webhookUrl"])
    ]
