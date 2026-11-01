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

`VerifierBaser.accept()` commits the claim, accepted status and optional outbox
obligation in one native synchronous LMDB write transaction. Insert without
overwrite and inspect existing data in the same transaction. Inconsistent or
orphaned claims abort acceptance. Native LMDB supplies process coordination; no
application locks, threads, queues or additional environment are needed.

The typed `AcceptedNonce` record stores issuer, exact nonce and accepted SAID.
Komer's ordinary issuer.nonce key is unambiguous under the credential profile and
at most 173 bytes, within the pinned environment's 511-byte key limit. Hashing
or custom key encodings add no value. Standard name/base/head-dir selects the
existing application store. Persistent closure retains all claims.

KERIpy evidence and application state use separate transactions. A bounded
acceptance scan recovers completed verified results; invalid, pending or revoked
evidence cannot burn a nonce. Target-free acceptance still claims the nonce,
without an event. Later enabling delivery does not backfill those acceptances.

## Store and operational limits

The `issuer-nonce-ascii-v1` scope requires complete claim history. Startup rejects
pre-policy or inconsistent acceptance stores; it does not migrate, backfill or
recreate missing claims. The history audit currently holds accepted SAIDs in
memory. Uniqueness applies within one preserved verifier store, not globally
across independent deployments. Do not erase history to evade reuse rejection.

See [operations](../docs/operations.md) for store layout and maintenance, and
[testing](../docs/testing.md) for process-race, crash/rollback, exact-key and
witnessed-intake coverage. Transport replay claims and Ethereum transaction
nonces are separate concerns.
