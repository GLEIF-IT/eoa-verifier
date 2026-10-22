"""Start the standalone verifier without any Ethereum posting credentials."""

import argparse
import sys

from keri import kering

from .serving import ServiceConfig, run_service


def main(argv=None):
    parser = argparse.ArgumentParser(prog="eoa-verifier")
    commands = parser.add_subparsers(dest="command", required=True)
    server = commands.add_parser("server")
    actions = server.add_subparsers(dest="action", required=True)
    start = actions.add_parser("start")
    start.add_argument("--trusted-geda-aid", required=True)
    start.add_argument("--rpc-url", required=True)
    start.add_argument("--chain-id", type=int, required=True)
    start.add_argument("--name", default="eoa-verifier")
    start.add_argument("--alias", default="verifier")
    start.add_argument("--base", default="")
    start.add_argument("--head-dir")
    start.add_argument("--host", default="127.0.0.1")
    start.add_argument("--http-port", type=int, default=9724)
    start.add_argument("--passcode")
    start.add_argument("--incept-file")
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
