"""Developer CLI for the local wallet-to-vLEI Verifier demonstration.

The Bash launcher needs only Python 3.12 (or uv). Preparation owns tool/wheel
installation; all wallet/KERI operations re-exec in the run's isolated interpreter.
Concrete command handlers keep CLI input separate from demonstration workflows.
"""

import argparse
import json
import os
import subprocess
import sys
from contextlib import redirect_stdout
from pathlib import Path

from . import demoing
from .environment import clean_run
from .processes import stop


def cli_path(value):
    """Resolve user paths against the original shell directory across snapshot re-exec."""
    path = Path(value).expanduser()
    return (Path(os.environ.get("EOA_DEMO_CWD", os.getcwd())) / path).resolve()


def make_parser():
    """Declare small, explicit demo commands and their operator-facing arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--run-dir",
        type=cli_path,
        default=Path.home() / ".local/share/eoa-verifier/demo",
    )
    parser.add_argument(
        "--verifier-source", type=cli_path, default=Path(__file__).resolve().parents[2]
    )
    parser.add_argument("--verifier-wheel", type=cli_path, help=argparse.SUPPRESS)
    parser.add_argument("--tool-revision", help=argparse.SUPPRESS)
    commands = parser.add_subparsers(dest="command", required=True)
    for name, handler, description in (
        ("up", up, "Start witnesses, funded Anvil, Verifier and webhook receiver"),
        (
            "run",
            run,
            "Start everything, sign/issue/present and wait for the accepted webhook",
        ),
        (
            "challenge",
            challenge,
            "Export typed data for the local LE holder and selected wallet",
        ),
        ("sign", sign, "Sign the exported challenge with a public test wallet"),
        ("issue", issue, "Issue a witnessed association using the wallet signature"),
        (
            "present",
            present,
            "Send its IPEX Grant and wait for acceptance plus webhook",
        ),
        (
            "revoke",
            revoke,
            "Revoke the credential and wait for revoked status plus webhook",
        ),
        (
            "status",
            status,
            "Show service URLs, holder identities and current association",
        ),
        ("events", events, "Show accepted/revoked JSON received by the webhook"),
        ("logs", logs, "Read or follow receiver/service logs"),
        ("down", down, "Stop owned processes, preserving identities and chain state"),
        ("clean", clean, "Remove an explicitly stopped demo run"),
    ):
        command = commands.add_parser(name, help=description)
        command.set_defaults(handler=handler)
        if name in ("challenge", "run"):
            wallets = command.add_mutually_exclusive_group()
            wallets.add_argument("--wallet", type=int, choices=(1, 2), default=1)
            if name == "challenge":
                wallets.add_argument(
                    "--wallet-address",
                    help="Lowercase external wallet; sign its challenge yourself",
                )
            command.add_argument(
                "--nonce", help="Fresh ASCII nonce; defaults to a random UUID"
            )
        elif name == "sign":
            command.add_argument("--wallet", type=int, choices=(1, 2))
        elif name == "issue":
            command.add_argument(
                "--signature-file",
                type=cli_path,
                help='JSON {"signature":"0x..."} from an external wallet',
            )
        elif name == "revoke":
            command.add_argument(
                "--said", help="An earlier demo credential; defaults to the latest"
            )
        elif name == "logs":
            command.add_argument(
                "--service",
                choices=("receiver", "verifier", "infrastructure", "anvil"),
                default="receiver",
            )
            command.add_argument("--follow", action="store_true")
    return parser


def main(argv=None):
    """Bootstrap before native imports, dispatch one command, and print public JSON results."""
    os.environ.setdefault("EOA_DEMO_CWD", os.getcwd())
    args = make_parser().parse_args(argv)
    root = args.run_dir.expanduser().resolve()
    try:
        if args.command in ("up", "run"):
            with redirect_stdout(sys.stderr):
                demoing.prepare_demo(
                    root,
                    args.verifier_source.resolve(),
                    wheel=args.verifier_wheel,
                    revision=args.tool_revision,
                )
        configuration = demoing.load_demo(root)
        if args.command not in ("down", "clean", "logs") and sys.prefix != str(
            root / "venv"
        ):
            os.chdir(Path(configuration["tool"]).parents[2])
            os.execv(
                configuration["python"],
                [
                    configuration["python"],
                    "-m",
                    "scripts.integration.demo",
                    *(sys.argv[1:] if argv is None else argv),
                ],
            )
        result = args.handler(root, configuration, args)
        if result is not None:
            print(json.dumps(result, indent=2))
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        print(f"eoa-demo: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    return 0


def up(root, configuration, args):
    """Start or reopen this run's processes and show their public connection details."""
    return demoing.start_demo(root, configuration)


def run(root, configuration, args):
    """Perform the explicit local happy path, leaving services running for manual revocation."""
    info = demoing.start_demo(root, configuration)
    print(
        f"Verifier: {info['verifierUrl']} | Webhook: {info['webhookUrl']} | RPC: {info['rpcUrl']}",
        file=sys.stderr,
    )
    descriptor = demoing.create_challenge(
        root, configuration, wallet=args.wallet, nonce=args.nonce
    )
    print(f"EIP-712 challenge: {descriptor['challenge']}", file=sys.stderr)
    demoing.sign_wallet(root)
    print(f"Wallet signature: {descriptor['signature']}", file=sys.stderr)
    association = demoing.issue_credential(root)
    print(
        f"Credential SAID: {association['said']}; presenting its IPEX Grant",
        file=sys.stderr,
    )
    return demoing.present_association(root, configuration)


def challenge(root, configuration, args):
    """Translate wallet selection into one exported challenge artifact."""
    return demoing.create_challenge(
        root,
        configuration,
        wallet=args.wallet,
        address=args.wallet_address,
        nonce=args.nonce,
    )


def sign(root, configuration, args):
    """Sign only with the selected public demo wallet."""
    return demoing.sign_wallet(root, wallet=args.wallet)


def issue(root, configuration, args):
    """Pass an external or local signature file to the witnessed issuer ceremony."""
    return demoing.issue_credential(root, signature_file=args.signature_file)


def present(root, configuration, args):
    """Present the latest issued association and wait for webhook delivery."""
    return demoing.present_association(root, configuration)


def revoke(root, configuration, args):
    """Revoke the selected credential using its issuer, not the Ethereum wallet."""
    return demoing.revoke_association(root, configuration, said=args.said)


def status(root, configuration, args):
    """Show owned process and association state without changing it."""
    return demoing.demo_status(root, configuration)


def events(root, configuration, args):
    """Display the receiver's stored JSON payloads and attempt counts."""
    return demoing.received_events(configuration)


def logs(root, configuration, args):
    """Display or follow one owned log; Ctrl-C ends viewing without stopping services."""
    path = root / "logs" / (args.service + ".log")
    if args.follow:
        subprocess.run(["tail", "-n", "50", "-f", str(path)], check=True)
    else:
        print(path.read_text()[-12000:])


def down(root, configuration, args):
    """Stop only recorded owned process groups and preserve the run's artifacts."""
    stop(root)
    return {"stopped": str(root)}


def clean(root, configuration, args):
    """Remove a demo only after the existing ownership/live-process checks pass."""
    clean_run(root)
    return {"removed": str(root)}


if __name__ == "__main__":
    raise SystemExit(main())
