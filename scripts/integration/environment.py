"""Prepare and sequence the owned Verifier environment lifecycle."""

import os
import shutil
import subprocess
import time
from pathlib import Path

from . import services
from .artifacts import load_json, save_json
from .builds import prepare_installation
from .infrastructure import infrastructure
from .processes import free_port, is_running, launch, process_records, stop, wait_ready

OWNER = "eoa-verifier-integration"


def tool_command(configuration: dict, *arguments: str) -> list[str]:
    """Invoke this run's snapshotted tooling using its isolated interpreter."""
    return [
        configuration["python"],
        "-m",
        "scripts.integration.env",
        *arguments,
        "--run-dir",
        configuration["root"],
    ]


def prepare_run(
    root: Path,
    source: Path,
    *,
    witness_count: int,
    wheel: Path | None = None,
    tool_revision: str | None = None,
) -> None:
    """Create one fresh run, install its wheel, and issue its real source chain.

    Partial failures retain artifacts/logs but stop any owned infrastructure.
    Existing directories are never overwritten or treated as completed runs.
    """
    if root.resolve().is_relative_to(source.resolve()):
        raise ValueError("Run directory must be outside its source checkout")
    anvil = shutil.which("anvil")
    if not anvil:
        raise ValueError("Anvil is required; install Foundry 1.5.1")
    if root.exists():
        raise ValueError(f"Run already exists; choose a fresh directory: {root}")
    root.mkdir(mode=0o700, parents=True)
    for name in ("logs", "wheels", "credentials", "tools"):
        (root / name).mkdir()
    installation = prepare_installation(
        root, source, wheel=wheel, tool_revision=tool_revision
    )
    ports = _ports(4 + witness_count)
    configuration = {
        "version": 1,
        "owner": OWNER,
        "root": str(root),
        **installation,
        "chainId": 31337,
        "anvil": anvil,
        "rpcPort": ports[0],
        "verifierPort": ports[1],
        "receiverPort": ports[2],
        "schemaPort": ports[3],
        "witnesses": [{"port": port} for port in ports[4:]],
        "dropAck": True,
        "rpcUrl": f"http://127.0.0.1:{ports[0]}",
        "verifierUrl": f"http://127.0.0.1:{ports[1]}",
        "webhookUrl": f"http://127.0.0.1:{ports[2]}/hook",
    }
    save_json(root / "run.json", configuration)
    subprocess.run(
        tool_command(configuration, "_initialize"),
        check=True,
        cwd=Path(configuration["tool"]).parents[2],
    )
    configuration = load_run(root)
    try:
        infrastructure(root, configuration)
        with (root / "logs/issuance.log").open("w") as log:
            subprocess.run(
                tool_command(configuration, "_bootstrap"),
                check=True,
                stdout=log,
                stderr=log,
                cwd=Path(configuration["tool"]).parents[2],
            )
        configuration["gedaAid"] = load_json(root / "chain.json")["gedaAid"]
        configuration["prepared"] = True
        save_json(root / "run.json", configuration)
    finally:
        stop(root)


def load_run(root: Path) -> dict:
    """Read and validate the explicit run ownership before operating on resources."""
    configuration = load_json(root / "run.json")
    if configuration["owner"] != OWNER or configuration["root"] != str(root):
        raise ValueError("Run ownership mismatch")
    return configuration


def start_run(
    root: Path,
    configuration: dict,
    *,
    local_only: bool = False,
    rpc_url: str | None = None,
    webhook_url: str | None = None,
    peer_kel: Path | None = None,
) -> None:
    """Start/reopen this run with immutable mode, peer and chain configuration.

    An external RPC is owned by the caller. An external webhook replaces only the
    fixture receiver, never verification or issuance. Failure stops owned services
    while preserving data; it never stops the external RPC or webhook.
    """
    if not configuration.get("prepared"):
        raise ValueError("Run preparation did not complete; inspect retained logs")
    requested = {
        "localOnly": local_only,
        "externalWebhook": bool(webhook_url),
        "rpcUrl": rpc_url or configuration["rpcUrl"],
        "externalRpc": bool(rpc_url),
    }
    if webhook_url:
        requested.update(webhookUrl=webhook_url)
    if configuration.get("configured"):
        if any(configuration.get(key) != value for key, value in requested.items()):
            raise ValueError(
                "Run configuration is immutable; use its original start options"
            )
    configuration.update(requested)
    if (
        peer_kel is not None
        and peer_kel.resolve() != (root / "receiver.cesr").resolve()
    ):
        shutil.copyfile(peer_kel, root / "receiver.cesr")
    configuration["configured"] = True
    services.validate_local_rpc(configuration["rpcUrl"])
    save_json(root / "run.json", configuration)
    try:
        infrastructure(root, configuration)
        if rpc_url is None:
            services.start_anvil(root, configuration)
        services.check_chain(configuration)
        if not local_only and webhook_url is None:
            services.start_receiver(root, configuration)
        launch(
            root,
            "verifier",
            services.verifier_command(root, configuration),
            port=configuration["verifierPort"],
            env={
                key: value
                for key, value in os.environ.items()
                if key not in ("VLEI_ORACLE_POSTING_KEY", "PRIVATE_KEY", "ADMIN_PK")
            },
        )
        wait_ready(
            root,
            "verifier",
            lambda: services.request_json(configuration["verifierUrl"] + "/health"),
        )
        if not local_only and (root / "receiver.cesr").is_file():
            services.request_json(
                configuration["verifierUrl"] + "/",
                (root / "receiver.cesr").read_bytes(),
                method="PUT",
            )
        configuration["startedOnce"] = True
        save_json(root / "run.json", configuration)
    except BaseException:
        stop(root)
        raise


def restart_verifier(root: Path, configuration: dict) -> None:
    """Restart the installed Verifier without presenting another Grant."""
    stop(root, "verifier")
    start_run(
        root,
        configuration,
        local_only=configuration["localOnly"],
        rpc_url=configuration["rpcUrl"] if configuration["externalRpc"] else None,
        webhook_url=configuration["webhookUrl"]
        if configuration["externalWebhook"]
        else None,
        peer_kel=(root / "receiver.cesr")
        if (root / "receiver.cesr").is_file()
        else None,
    )


def present_credential(root: Path, configuration: dict, said: str) -> None:
    """Send exported source/evidence bytes to the public CESR-stream endpoint."""
    presentationCesr = (root / "chain.cesr").read_bytes() + (
        root / "credentials" / f"{said}.cesr"
    ).read_bytes()
    services.request_json(
        configuration["verifierUrl"] + "/", presentationCesr, method="PUT"
    )


def wait_for_status(
    configuration: dict, said: str, expected: str, timeout: float = 25
) -> dict:
    """Wait for public stored state and, when present, its HTTP delivery completion."""
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            last = services.request_json(
                configuration["verifierUrl"] + f"/v1/associations/{said}/status"
            )
            delivery = last.get("delivery")
            if last["status"] == expected and (
                delivery is None or delivery["delivered"]
            ):
                return last
        except OSError:
            pass
        time.sleep(0.1)
    raise TimeoutError(f"{said} did not reach {expected}: {last}")


def clean_run(root: Path) -> None:
    """Remove an explicitly owned stopped run, never a live process's state."""
    load_run(root)
    if any(is_running(item) for item in process_records(root).values()):
        raise ValueError("Stop the run before clean")
    shutil.rmtree(root)


def _ports(count: int) -> list[int]:
    """Choose distinct probe ports; the launch boundary checks them again."""
    ports = set()
    while len(ports) < count:
        ports.add(free_port())
    return list(ports)
