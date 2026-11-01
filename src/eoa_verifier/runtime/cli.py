"""Public Verifier CLI for service startup and offline dead-letter recovery.

Parse operator configuration before opening stores. Startup owns the scheduled
service lifetime; retry commands open only the persistent application store and
require the running service to be stopped. No issuer or Ethereum posting keys
are accepted here.
"""

import argparse
import sys

from keri import kering
from keri.db import dbing

from eoa_verifier.persistence.associations import AssociationReader, AssociationWriter
from eoa_verifier.persistence.basing import VerifierBaser
from eoa_verifier.persistence.delivery import DeliveryReader, DeliveryWriter
from eoa_verifier.persistence.grants import GrantReader, GrantWriter
from eoa_verifier.persistence.verification import VerificationReader, VerificationWriter

from .config import ServiceConfig
from .serving import run_service


def main(argv=None):
    """Parse operator input, run one command, and return its process exit status.

    argv=None reads process arguments. argparse exits for help/invalid syntax.
    Expected configuration, storage and KERI errors print to stderr and return 1;
    programming errors propagate. Handlers own resources and return normally on success.
    """
    args = make_parser().parse_args(argv)
    try:
        args.handler(args)
    except (ValueError, OSError, kering.KeriError) as exc:
        print(f"eoa-verifier: {exc}", file=sys.stderr)
        return 1
    return 0


def make_parser():
    """Declare supported commands and bind each to its concrete handler; open no resources."""
    parser = argparse.ArgumentParser(prog="eoa-verifier")
    commands = parser.add_subparsers(dest="command", required=True)
    server_parser = commands.add_parser("server")
    actions = server_parser.add_subparsers(dest="action", required=True)
    start_parser = actions.add_parser("start")
    _start_args(start_parser)
    start_parser.set_defaults(handler=start_service)
    for phase, handler, identifier in (
        ("delivery", retry_delivery, "Delivery event ID"),
        ("verification", retry_verification, "Association credential SAID"),
        ("grant", retry_grant, "IPEX Grant notice ID"),
        ("acceptance", retry_acceptance, "Association credential SAID"),
    ):
        retry_parser = commands.add_parser(
            f"retry-{phase}",
            help=f"Resume a corrected {phase} dead letter with service stopped",
        )
        retry_parser.add_argument("identifier", help=identifier)
        _store_args(retry_parser)
        retry_parser.set_defaults(handler=handler)
    return parser


def _store_args(parser):
    """Declare the application-store selector shared by startup and offline recovery."""
    parser.add_argument(
        "--name",
        default=ServiceConfig.name,
        help="KERIpy store name to create or reopen (default: %(default)s)",
    )
    parser.add_argument(
        "--base",
        default=ServiceConfig.base,
        help="KERIpy store namespace (default: empty)",
    )
    parser.add_argument(
        "--head-dir",
        help="KERIpy storage root override (default: KERIpy store defaults/fallbacks)",
    )


def _start_args(parser):
    """Declare service identity, verification network and optional webhook settings."""
    parser.add_argument(
        "--trusted-geda-aid",
        required=True,
        help="Required canonical GEDA AID trusted for QVI issuance and delegation",
    )
    parser.add_argument(
        "--rpc-url",
        required=True,
        help="Required trusted Ethereum RPC URL for initial account observations",
    )
    parser.add_argument(
        "--chain-id",
        type=int,
        required=True,
        help="Required positive Ethereum chain ID; must match the association and RPC",
    )
    parser.add_argument(
        "--alias",
        default=ServiceConfig.alias,
        help="Service habitat alias to create or reopen (default: %(default)s)",
    )
    _store_args(parser)
    parser.add_argument(
        "--host",
        default=ServiceConfig.host,
        help="HTTP bind address (default: %(default)s)",
    )
    parser.add_argument(
        "--http-port",
        type=int,
        default=ServiceConfig.http_port,
        help="HTTP listening port; 0 selects an available port (default: %(default)s)",
    )
    parser.add_argument(
        "--passcode", help="Optional passcode for the KERIpy keystore (default: none)"
    )
    parser.add_argument(
        "--incept-file",
        help="JSON inception options for a new identity only (default: built-in inception options)",
    )
    parser.add_argument(
        "--webhook-url", help="Configured destination for association-status events"
    )
    parser.add_argument("--webhook-oobi", help="Optional response-signer OOBI URL")
    parser.add_argument(
        "--webhook-timeout",
        type=float,
        default=ServiceConfig.webhook_timeout,
        help="Overall request timeout in seconds (default: %(default)s)",
    )
    parser.add_argument(
        "--webhook-interval",
        type=float,
        default=ServiceConfig.webhook_interval,
        help="Minimum seconds between request starts (default: %(default)s)",
    )
    parser.add_argument(
        "--webhook-backoff-base",
        type=float,
        default=ServiceConfig.webhook_backoff_base,
        help="Initial retry lower bound in seconds; upper is twice this (default: %(default)s)",
    )
    parser.add_argument(
        "--webhook-backoff-cap",
        type=float,
        default=ServiceConfig.webhook_backoff_cap,
        help="Retry lower-bound cap in seconds; upper is twice this (default: %(default)s)",
    )
    parser.add_argument(
        "--webhook-max-attempts", type=int, default=ServiceConfig.webhook_max_attempts
    )


def start_service(args):
    """Validate explicit CLI settings, then delegate store/scheduler ownership to the runtime."""
    config = ServiceConfig(
        trusted_geda_aid=args.trusted_geda_aid,
        rpc_url=args.rpc_url,
        chain_id=args.chain_id,
        name=args.name,
        alias=args.alias,
        base=args.base,
        head_dir=args.head_dir,
        host=args.host,
        http_port=args.http_port,
        passcode=args.passcode,
        incept_file=args.incept_file,
        webhook_url=args.webhook_url,
        webhook_oobi=args.webhook_oobi,
        webhook_timeout=args.webhook_timeout,
        webhook_interval=args.webhook_interval,
        webhook_backoff_base=args.webhook_backoff_base,
        webhook_backoff_cap=args.webhook_backoff_cap,
        webhook_max_attempts=args.webhook_max_attempts,
    )
    run_service(config)


def _open_store(args):
    """Return KERIpy's persistent application-store context for one offline command.

    The caller enters/exits this context; no habitat, network task or unrelated
    feature service is created. Operators must stop the running service first.
    """
    return dbing.openLMDB(
        cls=VerifierBaser,
        name=args.name,
        base=args.base,
        headDirPath=args.head_dir,
        temp=False,
    )


def retry_delivery(args):
    """Resume one delivery event while retaining its destination cooldown and exact bytes."""
    from eoa_verifier.delivery.delivering import DeliveryService

    with _open_store(args) as baser:
        DeliveryService(
            DeliveryReader(baser),
            DeliveryWriter(baser),
            association_reader=AssociationReader(baser),
        ).retry(args.identifier)


def retry_verification(args):
    """Resume one initial-verification dead letter with a fresh attempt budget."""
    from eoa_verifier.verification.verifying import VerificationService

    with _open_store(args) as baser:
        VerificationService(VerificationReader(baser), VerificationWriter(baser)).retry(
            args.identifier
        )


def retry_grant(args):
    """Resume one corrected Grant notice without creating an intake parser or network task."""
    from eoa_verifier.receiving.replaying import GrantReplayService

    with _open_store(args) as baser:
        GrantReplayService(GrantReader(baser), GrantWriter(baser)).retry(
            args.identifier
        )


def retry_acceptance(args):
    """Resume one acceptance dead letter, preserving its completed verification result."""
    from eoa_verifier.associations.accepting import AcceptanceService

    with _open_store(args) as baser:
        AcceptanceService(
            AssociationReader(baser),
            AssociationWriter(baser),
            verification_reader=VerificationReader(baser),
        ).retry(args.identifier)


if __name__ == "__main__":
    raise SystemExit(main())
