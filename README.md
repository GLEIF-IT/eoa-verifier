# EOA verifier

Receives native CESR/IPEX Grants and verifies EOA associations against the trusted
GEDA, the LE/QVI credential chain, the wallet's EIP-712 signature and a configured
Ethereum network. Native evidence and initial verification progress survive restart.
Repeated Grants do not reset that progress. No Ethereum posting key is needed.
The service uses [HIO structured concurrency](adrs/0003-hio-structured-concurrency.md).

## Run

Requires Python 3.12.6 or newer. Install with `python -m pip install .`, then:

```sh
eoa-verifier server start \
  --trusted-geda-aid "$GEDA_AID" \
  --chain-id 31337 --rpc-url http://127.0.0.1:8545 \
  --head-dir ./state --http-port 9724
```

The service creates or reopens its KERI identity under the chosen store root.
Reuse `--name`, `--base`, `--alias` and `--head-dir` on restart. `--incept-file`
accepts native inception options for a new identity, including witnesses.
Send CESR to `/`; `/health` reports liveness. The listener defaults to loopback.

This increment performs initial verification only. Application acceptance,
public association-status GET, revocation notifications and authenticated webhook
delivery are not implemented yet. It does not publish Ethereum mappings or run
periodic verification/account checks.

## Test

Install `python -m pip install '.[test]'` and run `python -m pytest -q`.
The native integration test requires `anvil` from Foundry on `PATH` and fails if
it is missing. It creates isolated GEDA/QVI/LE, witness and verifier stores and
uses real IPEX/CESR, HTTP and a local chain. It never uses existing identities.

Verification was extracted from [vlei-oracle](https://github.com/GLEIF-IT/vlei-oracle/tree/77849caae048381aee96b42f75053368d8d24c53).
Packaged LE/QVI schemas come from [vLEI](https://github.com/GLEIF-IT/vLEI/tree/743622abc9a3b3684552e439efc5c8b6fda2f645/schema/acdc);
the association schema retains the existing oracle protocol SAID.
See the [service design](protocol/verifier-api-v1/README.md) and
[workflow diagrams](docs/README.md).
