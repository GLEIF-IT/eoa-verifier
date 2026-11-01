"""Launch concrete fixture services and perform bounded local HTTP exchanges."""

import json
from pathlib import Path
from urllib.request import Request, urlopen

from .processes import launch, wait_ready


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


def start_anvil(root: Path, configuration: dict) -> None:
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
    wait_ready(root, "anvil", lambda: check_chain(configuration))


def check_chain(configuration: dict) -> bool:
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


def start_receiver(root: Path, configuration: dict) -> None:
    """Start the focused receiver and wait for its stored-status-event read endpoint."""
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


def verifier_command(root: Path, configuration: dict) -> list[str]:
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
            "--webhook-timeout",
            "1",
            "--webhook-interval",
            ".1",
            "--webhook-backoff-base",
            ".1",
            "--webhook-backoff-cap",
            ".2",
        ]
    if configuration.get("webhookOobi"):
        command += ["--webhook-oobi", configuration["webhookOobi"]]
    return command


def validate_local_rpc(url: str) -> None:
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
