# ADR 0005: Consume association nonces at verifier acceptance

Status: Accepted
Date: 2026-10-31

## Decision

EOA Verifier permanently binds each exact `(issuerAid, nonce)` pair to one
application-accepted association SAID. Read both values from the native credential
after initial credential, relationship, wallet and account verification. Preserve
Unicode representation and whitespace. Issuers may issue candidates, but neither
credential creation nor oracle status receipt consumes an association nonce.

Another issuer may use the same nonce. Another SAID from the same issuer may not,
even for another wallet or LE credential. Same-SAID redelivery returns the original
application status/event. Revocation and downstream supersession never release
ownership. A conflict stores terminal local `rejected` / `NONCE_REUSED` with no
event or outbox entry. Its initial verification result remains `verified`, keeping
acceptance policy distinct from failed proof validation. Public status exposes
that local rejection; the verifier-to-oracle wire contract remains unchanged.

## Transaction and lifecycle

`VerifierBaser.accept()` uses one native LMDB write transaction for the permanent
claim, accepted status and optional outbox obligation. Insert the claim without
overwrite; inspect an existing claim in that same transaction. A minimal typed
`AcceptedNonce` contains issuer, exact nonce and accepted SAID. Its `accepted_nonces.`
Komer key is the 64-character hexadecimal SHA-256 digest of a compact UTF-8 JSON
array `[issuerAid, nonce]`. Compare stored fields as well as the key; inconsistent
or orphaned claims abort acceptance. No application locks, worker threads, queues,
retry loops or additional LMDB environments are introduced.

Claims share the existing synchronous VerifierBaser environment, under
`<head>/eoa-verifier/db/<base>/<name>/data.mdb` with native `lock.mdb`. The service's
existing name/base/head-dir options select the store. Persistent closure retains
claims; standard temporary stores remain test-owned. KERIpy evidence and application
state use separate transactions: a bounded AcceptanceDoer scan recovers verified
results whose native evidence is available but application acceptance is absent.
Missing, revoked, invalid or still-pending evidence does not consume a nonce.

Acceptance runs whether webhook delivery is enabled or disabled. Without a target,
status and claim commit without an outbox entry or event ID; public `delivery` is null. Enabling
delivery later does not retrospectively publish those acceptances. Existing outbox
obligations retain their original target, including retirement while sending is
disabled. Retirement of explicitly local-only acceptance records local status only. A missing
referenced outbox event is an error, not a fallback to local-only retirement.

## Baseline and limits

The verification scope now requires the acceptance-policy identifier
`issuer-nonce-v1`. Pre-policy scopes are refused; use a deliberate fresh complete
store set and preserve historical stores separately. Startup validates that every
accepted/revoked SAID has exactly one consistent claim and every claim has an
accepted/revoked owner. It does not backfill, migrate, release or silently recreate
history. Startup validation scans application acceptance history and retains its
SAIDs in memory; operational scaling of that audit is future work.

Uniqueness applies within one verifier store, not across independent stores or a
reset deployment. Do not erase claim history or run differently configured verifier
stores as though they share one acceptance authority. The oracle still owns webhook
transport replay protection and Ethereum transaction nonce recovery; those are
separate concerns. Old oracle issuer stores are no longer read or migrated.

## Qualification

Storage tests cover exact pairs, Unicode/whitespace, issuer scoping, idempotence,
revocation, restart, malformed history, native independent-process races and abrupt
death before/after commit. Fault injection verifies rollback of the claim/status
when outbox serialization fails. Real witnessed IPEX intake exercises a differently
signed second wallet credential sharing the accepted pair, with delivery enabled
and disabled; invalid and pending candidates cannot burn a nonce. The maintained
paired qualification preserves both actors, witnesses, real transfers, replacement,
retirement, lost ACK and restart while additionally rejecting valid nonce reuse.
