# ADR 0005: Consume association nonces at verifier acceptance

Status: Accepted
Date: 2026-10-31

## Decision and rationale

Nonce consumption belongs to the application accepting an association, not the
issuer constructing it or Oracle receiving downstream status. Bind each exact
issuer/nonce pair permanently to one accepted SAID. Keep initial verification
separate from application rejection so a valid proof can still fail local reuse
policy. [Verifier API v1](../protocol/verifier-api-v1/README.md) owns these visible
semantics; [external-association-v1](../protocol/external-association-v1/README.md)
owns nonce syntax and signed commitments.

`AcceptanceService` prepares status and event records before persistence.
`ApplicationWriter.accept_association()` commits local-only acceptance;
`accept_and_queue_delivery()` commits the claim, status and delivery obligation
in one synchronous LMDB write transaction. Nonce insertion never overwrites.
A conflict aborts the entire attempted acceptance. The service then reads and
validates committed ownership before `reject_reused_nonce()` saves rejection and
removes acceptance work. Inconsistent or orphaned claims fail closed. A crash
between conflict and rejection leaves the acceptance obligation recoverable. LMDB supplies process coordination; no
application locks, threads or additional environment are needed for nonce claims.

The typed `AcceptedNonce` record stores issuer, exact nonce and accepted SAID.
Komer's ordinary issuer.nonce key is unambiguous under the credential profile and
at most 173 bytes, within the pinned environment's 511-byte key limit. Hashing
or custom key encodings add no value. Standard name/base/head-dir selects the
existing application store. Persistent closure retains all claims.

KERIpy evidence and application state use separate transactions. A dedicated
`accepting.` phase recovers completed verified results one at a time; invalid, pending or revoked
evidence cannot burn a nonce. Target-free acceptance still claims the nonce,
without an event. Later enabling delivery does not backfill those acceptances.

## Store and operational limits

The `durable-phases-v1` scope requires complete claim history. Startup rejects
pre-policy or inconsistent acceptance stores; it does not migrate, backfill or
recreate missing claims. The history audit detaches bounded pages before checking them and holds accepted
SAIDs in memory. Uniqueness applies within one preserved verifier store, not globally
across independent deployments. Do not erase history to evade reuse rejection.

See [operations](../docs/operations.md) for store layout and maintenance, and
[testing](../docs/testing.md) for process-race, crash/rollback, exact-key and
witnessed-intake coverage. Transport replay claims and Ethereum transaction
nonces are separate concerns.
