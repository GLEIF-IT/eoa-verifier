"""Start a vLEI External Association verifier with the Externally Owned Account profile integration.

Supports verification of both sides of an Ethereum to vLEI association.
"""

import argparse
import sys

from keri import kering

from .config import ServiceConfig
from .serving import run_service


def main(argv=None):
    """Parse argv (or process arguments when None) and run the standalone service.

    Return 0 on normal shutdown. Report ValueError, OSError and KERIpy KeriError
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
        help="KERIpy store name to create or reopen (default: eoa-verifier)",
    )
    start.add_argument(
        "--alias",
        default="verifier",
        help="Service habitat alias to create or reopen (default: verifier)",
    )
    start.add_argument(
        "--base", default="", help="KERIpy store namespace (default: empty)"
    )
    start.add_argument(
        "--head-dir",
        help="KERIpy storage root override (default: KERIpy store defaults/fallbacks)",
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
        "--passcode", help="Optional passcode for the KERIpy keystore (default: none)"
    )
    start.add_argument(
        "--incept-file",
        help="JSON inception options for a new identity only (default: built-in inception options)",
    )
    start.add_argument(
        "--webhook-url", help="Configured destination for association-status events"
    )
    start.add_argument(
        "--webhook-aid", help="Trusted destination AID; required with --webhook-url"
    )
    start.add_argument(
        "--webhook-timeout",
        type=float,
        default=10.0,
        help="Overall request timeout in seconds (default: 10)",
    )
    start.add_argument(
        "--webhook-interval",
        type=float,
        default=1.0,
        help="Minimum seconds between request starts (default: 1)",
    )
    start.add_argument(
        "--webhook-backoff-base",
        type=float,
        default=1.0,
        help="Initial retry lower bound in seconds; upper is twice this (default: 1)",
    )
    start.add_argument(
        "--webhook-backoff-cap",
        type=float,
        default=150.0,
        help="Retry lower-bound cap in seconds; upper is twice this (default: 150)",
    )
    start.add_argument("--webhook-max-attempts", type=int, default=3)
    for phase in ("delivery", "verification", "grant", "acceptance"):
        retry = commands.add_parser(
            f"retry-{phase}",
            help=f"Resume a corrected {phase} dead letter with service stopped",
        )
        retry.add_argument(
            "identifier", help="Event ID, association SAID, or Grant notice ID"
        )
        retry.add_argument("--name", default="eoa-verifier")
        retry.add_argument("--base", default="")
        retry.add_argument("--head-dir")
    args = vars(parser.parse_args(argv))
    if args["command"].startswith("retry-"):
        from keri.db import dbing

        from eoa_verifier.associations.accepting import AcceptanceService
        from eoa_verifier.delivery.delivering import DeliveryService
        from eoa_verifier.persistence.basing import VerifierBaser
        from eoa_verifier.persistence.reading import ApplicationReader
        from eoa_verifier.persistence.writing import ApplicationWriter
        from eoa_verifier.receiving.replaying import GrantReplayService
        from eoa_verifier.verification.verifying import VerificationService

        try:
            with dbing.openLMDB(
                cls=VerifierBaser,
                name=args["name"],
                base=args["base"],
                headDirPath=args["head_dir"],
                temp=False,
            ) as baser:
                actions = {
                    "retry-delivery": DeliveryService(
                        ApplicationReader(baser), ApplicationWriter(baser)
                    ).retry,
                    "retry-verification": VerificationService(
                        ApplicationReader(baser), ApplicationWriter(baser)
                    ).retry,
                    "retry-grant": GrantReplayService(
                        ApplicationReader(baser), ApplicationWriter(baser)
                    ).retry,
                    "retry-acceptance": AcceptanceService(
                        ApplicationReader(baser), ApplicationWriter(baser)
                    ).retry,
                }
                actions[args["command"]](args["identifier"])
        except (ValueError, OSError) as exc:
            print(f"eoa-verifier: {exc}", file=sys.stderr)
            return 1
        return 0
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
