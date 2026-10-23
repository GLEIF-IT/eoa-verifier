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

## Maintainer orientation

| Module                                   | Responsibility                                                                    |
| ---------------------------------------- | --------------------------------------------------------------------------------- |
| `cli`, `serving`                         | Configuration, native stores, shared parser and HIO task/resource ownership.      |
| `receiving/grants`                       | Decode authenticated native Grants, replay embeds and create duplicate-safe work. |
| `basing`                                 | Persist initial-verification progress keyed by association SAID.                  |
| `verification/coordinating`              | Scan bounded work pages, dispatch one association and apply results.              |
| `verification/credentials`               | Check locally accepted ACDC/TEL/KEL evidence and LE/QVI relationships.            |
| `verification/eoa`, `worker`, `rpc`      | Check the wallet proof and observe the configured Ethereum account.               |
| `verification/constants`, `schema_cache` | Pin the existing credential schemas and load packaged resources.                  |

Initial flow: native Grant acceptance → embed replay and durable work → native
credential checks → wallet proof and chain/block/code observation → final local
native-state check after the RPC wait → terminal work status. Missing artifacts
or unusable RPC responses leave unfinished work for retry. Native acceptance is
separate from receipt of bytes; KELs, TELs, credentials and schemas live in the
native Habery/Reger stores, not in the work record.

Unfinished verification lives in `pending`; completed initial checks live in
`results` with a `verified` or `rejected` outcome. Completion writes the result
and removes pending work in one LMDB transaction. Duplicate Grants preserve the
first Grant and never re-enqueue completed work. Verified results retain the
wallet and initial account observation; they do not mean application acceptance,
webhook delivery or Ethereum endorsement. Restart rediscovers pending work.

## Service authentication primitives

`authing.ServiceAuthenticator` signs and authenticates exact HTTP body bytes with
the native service habitat and one configured peer AID. It uses the pinned KERI
`Signature-Input`/`Signature` format, checks locally accepted current keys, and
stores nonce claims in `VerifierBaser` across restart. Single-key transferable
Ed25519 service AIDs at threshold one are supported. See the
[transport profile](protocol/verifier-api-v1/README.md#transport-signature-profile).

These are callable primitives for the later sender/intake integrations; this
increment adds no authenticated delivery route, retry worker or public status API.
Authenticated messages do not establish durable application acceptance. The caller
commits application state before signing an ACK and validates the ACK payload
before marking delivery complete.

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
