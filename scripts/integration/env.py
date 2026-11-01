"""CLI for the standalone Verifier environment and its public fixture operations.

Preparation builds/installs a wheel; all native work re-executes in that isolated
interpreter. Lifecycle, native ceremonies and scenario assertions have separate
owners so the command dispatcher contains no business workflow.
"""

import argparse
import json
import os
import signal
import sys
from contextlib import redirect_stdout
from pathlib import Path

from .environment import clean_run, load_run, prepare_run, present_credential, start_run
from .processes import is_running, process_records, stop

# Repository root used to snapshot this command and owned integration inputs.
SOURCE = Path(__file__).resolve().parents[2]
# Public lifecycle commands plus narrow internal daemon entry points.
COMMANDS = (
    "prepare",
    "start",
    "flow",
    "qualify",
    "status",
    "logs",
    "stop",
    "clean",
    "issue",
    "present",
    "revoke",
    "_initialize",
    "_infrastructure",
    "_bootstrap",
)


def parser() -> argparse.ArgumentParser:
    """Describe the explicit run, candidate/artifact inputs and operation parameters."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=COMMANDS)
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--verifier-source", type=Path, default=SOURCE)
    parser.add_argument("--verifier-wheel", type=Path)
    parser.add_argument("--tool-revision")
    parser.add_argument("--witness-count", type=int, choices=(1, 6), default=6)
    parser.add_argument("--local-only", action="store_true")
    parser.add_argument("--rpc-url")
    parser.add_argument("--webhook-url")
    parser.add_argument("--webhook-oobi")
    parser.add_argument("--said")
    parser.add_argument("--nonce")
    parser.add_argument("--wallet", type=int, choices=(1, 2), default=1)
    parser.add_argument("--service")
    return parser


def main() -> None:
    """Validate inputs, select the prepared interpreter and dispatch one command."""
    arguments = parser().parse_args()
    root = arguments.run_dir.expanduser().resolve()
    if arguments.command in ("prepare", "qualify") and not root.exists():
        prepare_run(
            root,
            arguments.verifier_source.resolve(),
            witness_count=arguments.witness_count,
            wheel=arguments.verifier_wheel,
            tool_revision=arguments.tool_revision,
        )
        if arguments.command == "prepare":
            print(f"Prepared {root}")
            return
    elif arguments.command == "prepare":
        raise ValueError("Run already exists; choose a fresh directory")
    configuration = load_run(root)
    if arguments.command in ("status", "logs", "stop", "clean"):
        inspect_or_stop(root, arguments)
        return
    if sys.prefix != str(root / "venv"):
        os.chdir(Path(configuration["tool"]).parents[2])
        os.execv(
            configuration["python"],
            [configuration["python"], "-m", "scripts.integration.env", *sys.argv[1:]],
        )
    execute(root, configuration, arguments)


def inspect_or_stop(root: Path, arguments) -> None:
    """Handle resource inspection and deletion without importing application code."""
    if arguments.command == "stop":
        stop(root, arguments.service)
    elif arguments.command == "clean":
        clean_run(root)
    elif arguments.command == "status":
        print(
            json.dumps(
                {
                    "run": load_run(root),
                    "processes": {
                        name: is_running(record)
                        for name, record in process_records(root).items()
                    },
                },
                indent=2,
            )
        )
    else:
        for path in sorted((root / "logs").glob((arguments.service or "*") + ".log")):
            print(f"{path}\n{path.read_text(errors='replace')[-12000:]}")


def execute(root: Path, configuration: dict, arguments) -> None:
    """Dispatch in the isolated interpreter; internal daemon commands stay narrow."""
    action = arguments.command
    if action in ("issue", "revoke", "_bootstrap"):
        issue_or_revoke(root, arguments)
    elif action == "_initialize":
        from .infrastructure import initialize

        initialize(root, configuration)
    elif action == "_infrastructure":
        from .infrastructure import serve_infrastructure

        serve_infrastructure(root, configuration)
    elif action == "present":
        if not arguments.said:
            raise ValueError("present requires --said")
        present_credential(root, configuration, arguments.said)
    elif action == "start":
        start(root, configuration, arguments)
    elif action == "flow":
        from .scenario import run_flow

        run_flow(root, configuration)
    elif action == "qualify":
        from .scenario import run_flow

        try:
            start(root, configuration, arguments)
            run_flow(root, configuration)
            print("Witnessed Verifier qualification passed")
        finally:
            stop(root)


def start(root: Path, configuration: dict, arguments) -> None:
    """Pass the explicit CLI mode and peer configuration to the lifecycle owner."""
    start_run(
        root,
        configuration,
        local_only=arguments.local_only,
        rpc_url=arguments.rpc_url,
        webhook_url=arguments.webhook_url,
        webhook_oobi=arguments.webhook_oobi,
    )


def issue_or_revoke(root: Path, arguments) -> None:
    """Run a single native ceremony and emit only its JSON descriptor to stdout."""
    from .ceremony import complete_ceremony, open_ceremony

    if arguments.command == "issue" and arguments.nonce is None:
        raise ValueError("issue requires --nonce")
    if arguments.command == "revoke" and not arguments.said:
        raise ValueError("revoke requires --said")
    with redirect_stdout(sys.stderr), open_ceremony(root) as ceremony:
        if arguments.command == "_bootstrap":
            ceremonyGen = ceremony.bootstrap_sources()
        elif arguments.command == "issue":
            ceremonyGen = ceremony.issue_association(
                "0x" + "0" * 63 + str(arguments.wallet), arguments.nonce
            )
        else:
            ceremonyGen = ceremony.revoke_association(arguments.said)
        ceremonyResult = complete_ceremony(ceremony, ceremonyGen)
    print(json.dumps(ceremonyResult))


def shutdown(signum, frame) -> None:
    """Unwind native context managers on owned daemon termination."""
    raise KeyboardInterrupt


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, shutdown)
    try:
        main()
    except KeyboardInterrupt:
        pass
