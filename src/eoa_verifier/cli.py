"""Start the standalone verifier without any Ethereum posting credentials."""

import argparse
import sys

from keri import kering

from .serving import ServiceConfig, run_service


def main(argv=None):
    """Parse argv (or process arguments when None) and run the standalone service.

    Return 0 on normal shutdown. Report ValueError, OSError and native KeriError
    to stderr and return 1; other exceptions propagate. argparse exits directly
    for help or invalid/missing arguments. This entry point owns no posting keys.
    """
    parser = argparse.ArgumentParser(prog="eoa-verifier")
    commands = parser.add_subparsers(dest="command", required=True)
    server = commands.add_parser("server")
    actions = server.add_subparsers(dest="action", required=True)
    start = actions.add_parser("start")
    start.add_argument(
        "--trusted-geda-aid",
        required=True,
        help="Required canonical GEDA AID trusted for QVI issuance and delegation",
    )
    start.add_argument(
        "--rpc-url",
        required=True,
        help="Required trusted Ethereum RPC URL for initial account observations",
    )
    start.add_argument(
        "--chain-id",
        type=int,
        required=True,
        help="Required positive Ethereum chain ID; must match the association and RPC",
    )
    start.add_argument(
        "--name",
        default="eoa-verifier",
        help="Native store name to create or reopen (default: eoa-verifier)",
    )
    start.add_argument(
        "--alias",
        default="verifier",
        help="Service habitat alias to create or reopen (default: verifier)",
    )
    start.add_argument(
        "--base", default="", help="Native store namespace (default: empty)"
    )
    start.add_argument(
        "--head-dir",
        help="Native storage root override (default: native store defaults/fallbacks)",
    )
    start.add_argument(
        "--host", default="127.0.0.1", help="HTTP bind address (default: 127.0.0.1)"
    )
    start.add_argument(
        "--http-port",
        type=int,
        default=9724,
        help="HTTP listening port; 0 selects an available port (default: 9724)",
    )
    start.add_argument(
        "--passcode", help="Optional passcode for the native keystore (default: none)"
    )
    start.add_argument(
        "--incept-file",
        help="JSON inception options for a new identity only (default: built-in inception options)",
    )
    args = vars(parser.parse_args(argv))
    args.pop("command")
    args.pop("action")
    try:
        run_service(ServiceConfig(**args))
    except (ValueError, OSError, kering.KeriError) as exc:
        print(f"eoa-verifier: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
