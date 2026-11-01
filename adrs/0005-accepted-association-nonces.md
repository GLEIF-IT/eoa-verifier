# ADR 0005: Consume association nonces at verifier acceptance

Status: Accepted
Date: 2026-10-31

## Decision and rationale

Nonce consumption belongs to the application accepting an association. It does
not belong to the issuer ceremony or the downstream Oracle. Each exact nonce is
permanently unique within the accepting verifier store, across all issuers.
Another credential using it is rejected with `NONCE_REUSED`. Initial proof
verification remains separate from application acceptance.

The LMDB key is the nonce's exact ASCII bytes. The `AcceptedNonce` value records
the accepted credential SAID. A key's presence means consumed regardless of its
value. No issuer prefix, digest, owner lookup, history scan, paging or startup
nonce audit is needed. The 1–128 character `[A-Za-z0-9_-]` contract fits directly
inside LMDB's key limit without encoding tricks or normalization.

`AcceptanceService` prepares status and event records. The writer performs one
no-overwrite nonce insert, atomically with accepted status and any delivery
obligation. A conflict aborts the acceptance transaction. The service saves a
`NONCE_REUSED` rejection for a new credential; a same-credential race returns its
already stored status. Duplicate delivery does not perform a second acceptance.
No nonce value is decoded to decide reuse. An opaque or malformed value still
denies acceptance. Revocation and supersession never release the key.

The `accepting.` work queue recovers one verified result at a time. Invalid,
pending or revoked evidence cannot burn a nonce. Target-free acceptance uses the
same atomic claim without an event. LMDB provides durability and independent
process coordination; there is no application mutex or extra nonce environment.

## Breaking storage contract

Use fresh application stores for this direct nonce-key layout. There are no old-format
readers, migrations, backfills or compatibility APIs. Startup settings are advisory:
changed trust/network settings log a warning and update their baseline without
auditing the nonce or association datasets. Operators own store selection; no
nonce-policy version marker gates startup. Atomic writes
prevent partial acceptance; the application does not reconstruct history or
attempt to repair manual database edits. Preserve the store across restart.
Uniqueness is local to that verifier store, not shared across independent deployments.

[Verifier API v1](../protocol/verifier-api-v1/README.md) owns acceptance behavior;
[external-association-v1](../protocol/external-association-v1/README.md) owns signed
fields and syntax. HTTP signatures use no transport nonce ledger; Ethereum
transaction nonces are a separate concern. See [testing](../docs/testing.md) for process-race, crash,
rollback, exact-key and witnessed-intake coverage.
