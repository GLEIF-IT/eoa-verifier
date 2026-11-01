"""Concrete Verifier environment lifecycle, distinct from CLI and issuer policy.

The run artifact fixes identity, trust, ports and installed code. Start/stop manage
only that run; they never retarget previously accepted delivery obligations.
"""

import json
import os
from pathlib import Path
import shutil
import subprocess
import time
from urllib.request import Request, urlopen

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


def request_json(
    url: str,
    body: bytes | None = None,
    *,
    method: str | None = None,
    headers: dict | None = None,
):
    """Perform a bounded local HTTP exchange; return decoded JSON or no content."""
    with urlopen(
        Request(url, data=body, method=method, headers=headers or {}), timeout=5
    ) as response:
        raw = response.read()
        return json.loads(raw) if raw else None


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
    webhook_aid: str | None = None,
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
        if not webhook_aid or peer_kel is None:
            raise ValueError("External webhook requires an explicit AID and KEL file")
        requested.update(webhookUrl=webhook_url, receiverAid=webhook_aid)
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
    _validate_local_rpc(configuration["rpcUrl"])
    save_json(root / "run.json", configuration)
    try:
        infrastructure(root, configuration)
        if rpc_url is None:
            _start_anvil(root, configuration)
        _check_chain(configuration)
        if not local_only and webhook_url is None:
            _start_receiver(root, configuration)
        launch(
            root,
            "verifier",
            _verifier_command(root, configuration),
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
            lambda: request_json(configuration["verifierUrl"] + "/health"),
        )
        if not local_only:
            request_json(
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
        webhook_aid=configuration["receiverAid"],
        peer_kel=root / "receiver.cesr",
    )


def present_credential(root: Path, configuration: dict, said: str) -> None:
    """Send exported source/evidence bytes to the public CESR-stream endpoint."""
    evidence = (root / "chain.cesr").read_bytes() + (
        root / "credentials" / f"{said}.cesr"
    ).read_bytes()
    request_json(configuration["verifierUrl"] + "/", evidence, method="PUT")


def wait_for_status(
    configuration: dict, said: str, expected: str, timeout: float = 25
) -> dict:
    """Wait for public stored state and, when present, its authenticated delivery ACK."""
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            last = request_json(
                configuration["verifierUrl"] + f"/v1/associations/{said}/status"
            )
            delivery = last.get("delivery")
            if last["status"] == expected and (
                delivery is None or delivery["acknowledged"]
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


def _start_anvil(root: Path, configuration: dict) -> None:
    """Start only this run's local chain, retaining state for a persistent restart."""
    launch(
        root,
        "anvil",
        [
            configuration["anvil"],
            "--host",
            "127.0.0.1",
            "--port",
            str(configuration["rpcPort"]),
            "--chain-id",
            "31337",
            "--state",
            str(root / "anvil.json"),
            "--state-interval",
            "1",
            "--silent",
        ],
        port=configuration["rpcPort"],
    )
    wait_ready(root, "anvil", lambda: _check_chain(configuration))


def _check_chain(configuration: dict) -> bool:
    """Require the expected chain ID before any Verifier can observe accounts."""
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}
    ).encode()
    response = request_json(
        configuration["rpcUrl"], body, headers={"Content-Type": "application/json"}
    )
    if response.get("result") != hex(configuration["chainId"]):
        raise RuntimeError("RPC chain differs from the prepared run")
    return True


def _start_receiver(root: Path, configuration: dict) -> None:
    """Start the focused receiver and wait for its persisted-receipt read endpoint."""
    tool = Path(configuration["tool"]).with_name("receiver.py")
    launch(
        root,
        "receiver",
        [
            configuration["python"],
            "-m",
            "scripts.integration.receiver",
            "--root",
            str(root),
        ],
        port=configuration["receiverPort"],
        cwd=tool.parents[2],
    )
    wait_ready(root, "receiver", lambda: request_json(configuration["webhookUrl"]))


def _verifier_command(root: Path, configuration: dict) -> list[str]:
    """Construct the supported installed CLI without posting keys or hidden peers."""
    command = [
        str(Path(configuration["python"]).with_name("eoa-verifier")),
        "server",
        "start",
        "--name",
        "verifier",
        "--alias",
        "verifier",
        "--head-dir",
        str(root / "services"),
        "--host",
        "127.0.0.1",
        "--http-port",
        str(configuration["verifierPort"]),
        "--trusted-geda-aid",
        configuration["gedaAid"],
        "--chain-id",
        "31337",
        "--rpc-url",
        configuration["rpcUrl"],
    ]
    if not configuration["localOnly"]:
        command += [
            "--webhook-url",
            configuration["webhookUrl"],
            "--webhook-aid",
            configuration["receiverAid"],
            "--webhook-timeout",
            "1",
            "--webhook-interval",
            ".1",
            "--webhook-backoff-base",
            ".1",
            "--webhook-backoff-cap",
            ".2",
        ]
    return command


def _validate_local_rpc(url: str) -> None:
    """Refuse non-local RPC URLs before launching infrastructure or signing work."""
    from urllib.parse import urlsplit

    parsed = urlsplit(url)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in ("127.0.0.1", "localhost")
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "Integration RPC must be an explicit loopback HTTP URL and port"
        )
