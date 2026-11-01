# EOA verifier

Receives IPEX Grants carrying JSON messages with CESR attachments and verifies EOA associations against the trusted
GEDA, the LE/QVI credential chain, the wallet's EIP-712 signature and a configured
Ethereum network. KERIpy evidence and initial verification progress survive restart.
Repeated Grants do not reset that progress. With a webhook configured, verified
results become durable acceptance and signed delivery events. No Ethereum posting
key is needed.
The service uses [HIO structured concurrency](adrs/0003-hio-structured-concurrency.md).

For installation, peer introduction, restart and delivery recovery, see the
[operator guide](docs/operations.md).

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
accepts KERIpy inception options for a new identity, including witnesses.
Send CESR to `/`; `/health` reports liveness. The listener defaults to loopback.

Add `--webhook-url https://receiver.example/hook --webhook-aid "$RECEIVER_AID"`
to enable application acceptance and delivery. Configure both together. The peer's
current key state must already be KERIpy-accepted by this verifier; missing
keys leave delivery blocked pending correction. Omitting both retains verification-only operation.

Public `GET /v1/associations/{said}/status` returns stored `pending`, `rejected`,
`verified`, `accepted` or `revoked` status and any initial account observation.
Accepted/retired records also expose their current event’s delivery progress and
errors. Unknown SAIDs return 404.
GET requires no signature and performs no RPC or refresh.

The sender keeps one request in flight and spaces starts by at least one second,
including successes. Connection failures, timeouts, HTTP 408/429 and 5xx errors
(except 501/505) retry automatically with jittered backoff from 1–2 seconds to
150–300 seconds. A valid `Retry-After` is a minimum, even beyond that cap.
Cooldown applies to the whole destination and survives restart. Only the expected
authenticated ACK completes delivery and resets the failure count.

Permanent HTTP, payload, signature or configuration failures remain visible as
`delivery.blocked`, with the current event's `error`. Shared destination scheduling
state stays in local storage. After correcting the cause, an embedding caller can resume
with `service.sender.request(event_id)`; restart alone does not unblock it.
There is no retry REST route; the [operator guide](docs/operations.md#delivery-failures)
also describes an offline resume for standalone deployments. Old acceptance events superseded by retirement stay
stored and blocked; retirement requires its own ACK. No periodic verification or
account checks run, and Ethereum publication remains the oracle's responsibility.

| Option                   | Default | Meaning                                               |
| ------------------------ | ------- | ----------------------------------------------------- |
| `--webhook-timeout`      | 10      | Overall request timeout, seconds.                     |
| `--webhook-interval`     | 1       | Minimum seconds between request starts.               |
| `--webhook-backoff-base` | 1       | First retry's lower bound; upper bound is twice this. |
| `--webhook-backoff-cap`  | 150     | Maximum lower bound; upper bound is twice this.       |


## Maintainer orientation

| Component | Modules and responsibility |
| --- | --- |
| `runtime` | `cli`, `config`, `serving`: arguments, validated configuration, KERIpy stores and HIO task/resource ownership. |
| `receiving` | `directing`, `grants`: finite CESR HTTP intake, shared parser/escrows, IPEX replay and duplicate-safe work creation. |
| `verification` | `coordinating`, `credentials`, `eoa`, `worker`, `rpc`: initial credential/wallet/account verification; `constants`, `schema_cache`, `errors` support that contract. |
| `associations` | `accepting`, `retiring`, `statusing`: application acceptance, verified association revocation and public stored status. |
| `delivery` | `authing`, `delivering`: signed transport/replay protection and webhook attempts, retry pacing and ACK policy. |
| `persistence` | `records`, `basing`: durable record schemas and atomic verification, acceptance/outbox and delivery transitions. |

These are sibling leaf component packages. Runtime composes them; workflow
components depend on persistence and KERIpy evidence, not on runtime or each
other. Persistence owns no network or verification policy. See
[ADR 0004](adrs/0004-component-organization.md) for boundaries and import migration.

Initial flow: IPEX Grant acceptance → embed replay and durable work → KERIpy
credential checks → wallet proof and chain/block/code observation → final local
KERIpy-state check after the RPC wait → a completed result. Missing artifacts
or unusable RPC responses leave unfinished work for retry. KERIpy acceptance is
separate from receipt of bytes; KELs, TELs, credentials and schemas live in the
KERIpy Habery/Reger stores, not in the work record.

Unfinished verification lives in `pending`; completed initial checks live in
`results` with a `verified` or `rejected` outcome. Completion writes the result
and removes pending work in one LMDB transaction. Duplicate Grants preserve the
first Grant and never re-enqueue completed work. Verified results retain the
wallet and initial account observation; they do not mean application acceptance,
webhook delivery or Ethereum endorsement. Restart rediscovers pending work.

`AcceptanceDoer` reads completed results and locally accepted issuance evidence
without repeating initial checks. Acceptance permanently binds the exact issuer/nonce
to one SAID, atomically with immutable facts and any configured outbox obligation.
Another SAID using that pair becomes locally `rejected` with `NONCE_REUSED`; its
initial verification remains `verified`. Same-SAID replay is idempotent, and
revocation/supersession never releases the nonce.
Nonces contain 1–128 ASCII characters from `[A-Za-z0-9_-]`; storage uses ordinary
`issuer.nonce` Komer keys. See [ADR 0005](adrs/0005-accepted-association-nonces.md).

Acceptance runs with or without webhooks. With no target, public `delivery` is null;
enabling delivery later does not backfill events for locally accepted records.
Restart recovers results awaiting acceptance. KERIpy evidence lives in a separate
database and is not part of the application transaction. Missing evidence or
already-known revocation prevents first acceptance. Observation age does not
invalidate an accepted record.

`RetirementDoer` scans bounded pages of accepted records against locally accepted
association TEL state. KERIpy `rev`/`brv` retires only that SAID and atomically
creates its second event when an original delivery exists, preserving original issuance facts, observation and
webhook destination. Duplicate evidence and restart do not create more events or
revive retirement. A different association for the same wallet is untouched;
ownership selection belongs to the oracle.

IPEX Grant delivers supporting KEL/TEL artifacts; the Grant’s embedded
issuance or credential alone does not prove revocation. The existing shared parser
and escrows validate those artifacts. Retirement also recovers from stored KERIpy
state after restart, so it requires neither a retained cue nor another Grant.
Missing or escrowed evidence leaves accepted status unchanged. This local scan
performs no account/source reassessment or network refresh. Previously accepted
records still retire when webhook sending is disabled; their delivery obligations
remain stored for the original destination.

`run_service()` owns shared stores through KERIpy context managers.
`VerifierService` borrows those stores and composes the HIO tasks. HIO stops
children before the outer contexts close stores, including startup failure and
cancellation. HIO network Doers own sockets; persistent stores survive shutdown.

Direct intake uses `CesrEnd` on `/`: JSON body/CESR-attachment header POST and raw
CESR-stream PUT, with 204 acknowledging intake only. Explicit POST queries are
unsupported; PUT streams are not filtered. `Receiver` schedules the shared KERIpy
parser and escrows. There is no mailbox polling, mailbox store or SSE query service.

See the [testing guide](docs/testing.md) for component and integration lookup.

## Service authentication primitives

`delivery.authing.ServiceAuthenticator` signs and authenticates exact HTTP body bytes with
the KERIpy service habitat and one configured peer AID. It uses the pinned KERI
`Signature-Input`/`Signature` format, checks locally accepted current keys, and
stores nonce claims in `VerifierBaser` across restart. Single-key transferable
Ed25519 service AIDs at threshold one are supported. See the
[transport profile](protocol/verifier-api-v1/README.md#transport-signature-profile).

`WebhookSender` uses these common primitives and owns ACK policy: actual HTTP 200,
expected peer, exact attempt reference and a `stored: true` acknowledgment for the event.
The receiver commits durable event receipt before signing an ACK and acknowledges
redelivery without repeating effects. This does not confirm contract publication. See [Verifier API v1](protocol/verifier-api-v1/README.md)
for event and ACK definitions. Authentication alone is not delivery
completion or Ethereum confirmation.

## Test

Install `python -m pip install '.[test]'` and run `python -m pytest -q`.
The KERI/IPEX integration test requires `anvil` from Foundry on `PATH` and fails if
it is missing. It creates isolated GEDA/QVI/LE, witness and verifier stores and
uses real IPEX/CESR, HTTP and a local chain. It never uses existing identities.

Verification was extracted from [vlei-oracle](https://github.com/GLEIF-IT/vlei-oracle/tree/77849caae048381aee96b42f75053368d8d24c53).
Packaged LE/QVI schemas come from [vLEI](https://github.com/GLEIF-IT/vLEI/tree/743622abc9a3b3684552e439efc5c8b6fda2f645/schema/acdc);
the association schema and its new SAID enforce the 1–128 ASCII nonce contract.
See the [service design](protocol/verifier-api-v1/README.md) and
[workflow diagrams](docs/README.md).

Terminology: this service exchanges JSON messages with CESR attachments.
“KERIpy” identifies the implementation used for parsing, verification and storage;
“CESR-native” is reserved for CESR serialization of message structures.
See the [store baseline](docs/operations.md#protocol-and-store-baseline)
before using this revision with existing stores or an oracle deployment.

This repository owns [external-association-v1](protocol/external-association-v1/README.md),
its sole packaged schema, proof vectors, generator and conformance tests, plus
[verifier-api-v1](protocol/verifier-api-v1/README.md) and the shared signed
webhook/ACK profile. Oracle owns its selection/publication API; Comply owns the
registry ABI and calldata fixtures.

For an independent witnessed local environment, see [the integration commands](scripts/integration/README.md).
