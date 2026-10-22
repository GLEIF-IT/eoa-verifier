# Verifier API v1

This directory owns the split-service contract. It is a protocol specification
with executable conformance vectors, not an implemented HTTP service. PR 01
covers WBS 1.1, 3.1, the specification part of 3.3, and ABI analysis for 2.4.
Durable stores, live service authentication and native refresh qualification
belong to their subsequent implementation gates.

## Design argument

The verifier owns association evidence and continuing assessment. The oracle
owns deployment policy and Ethereum effects. Neither imports the other
application or reads its writable databases. A versioned, authenticated decision
is the narrow boundary; a fresh observation is a separate claim. This separates
cryptographic acceptance from permission to post and keeps transaction recovery
independent of peer availability. No structural refactor is needed in this
documentation-only repository before adding the contract. Application extraction
will preserve behavior before replacing its local handoff.

One authoritative wire representation and pinned vectors prevent drift without
a third shared runtime package. Simple application-local adapters will implement
it. There is no general message bus, jobs framework or arbitrary action language.

## Verification claim

Profile is `vlei-external-association/eoa/v1`; wire version is `1`.
The three outcomes are `valid`, `invalid`, `unavailable`. Valid means all checks
in [the acceptance matrix](acceptance.md) passed. Invalid requires established contradictory evidence or deterministic profile
failure, never timeout or missing evidence. A known credential
revocation is terminal for that SAID and outranks later unavailability.
Account code invalidity may recover at a higher revision. EIP-7702 designation
acceptance does not evaluate the delegated code's behavior.

One chain is configured per service deployment. Canonical `extId` is
`eip155:<positive decimal chainId, at most 32 digits>:<0x lowercase 20-byte address>`.
The wallet is its address; `identityRef = keccak256(UTF-8(issuerAid))`, not SHA3-256,
LEI or LE SAID. Redundant wallet/identity claims are omitted from v1 wire messages.
If a future adapter accepts them, it must compare locally derived values.
Each application checks its own trusted RPC's chain ID and a configured
`(blockNumber, blockHash)` checkpoint. Neither credentials nor events select RPC
URLs. A checkpoint detects a differently initialized Anvil with the same chain
ID, not forks sharing that checkpoint. Reset requires fresh deployment state or
explicit reconciliation, never silent reuse of the signed transaction journal.

## Exact wire and signature bytes

All authenticated requests and responses have `Content-Type: application/json`
and the closed envelope `{protected, payload, signature}`. `signature` is one
native KERI indexed Ed25519 `Siger` at index zero (code A), qb64 encoded. This is
an application envelope, not a new CESR message type or proof of ACDC acceptance.

Canonical encoding C(x) is JSON with recursively sorted ASCII object keys,
no whitespace or terminal newline, no duplicate keys, only printable ASCII
strings (U+0020 through U+007E), booleans, null, arrays and objects. Numbers are
forbidden: counters, times, status and chain IDs are canonical unsigned decimal
strings (`0` or nonzero first digit), bounded by their schema. JSON string
escaping uses `\"` and `\\` only where required; `/` is unescaped. On receipt,
require the raw bytes equal C(parsed object); reject alternate encodings, BOM,
unknown fields and trailing data. Diagnostics are bounded ASCII text.
Maximum whole HTTP body is 1,048,576 bytes; implementations bound reads before
parsing. GET requests carry the envelope in `EOA-Authorization`, unpadded
base64url of C(envelope), with payload `{}` and no HTTP body (header limit 8192
bytes). POST uses C(envelope) as its body. Responses always use the body.
TLS authenticates configured remote endpoints; plain HTTP is limited to the
explicit loopback local fixture. Do not forward authorization on redirects.

`protected` contains exactly:

| Field | Meaning |
| --- | --- |
| version | `1` |
| kind | `request` or `response` |
| signerAid, audience | Sender and intended recipient service AIDs |
| establishment | `{sequence, digest}` of the accepted signing establishment event |
| method, target | Original HTTP method and exact canonical path/query |
| issuedAt, expiresAt | Unix seconds as decimal strings |
| nonce | Fresh 32 random bytes, unpadded base64url (43 characters) |
| payloadDigest | Lowercase SHA-256 hex of C(payload), without `0x` |
| requestDigest | null in requests; SHA-256 of the complete original C(request envelope) in responses |
| requestNonce | null in requests; original request nonce in responses |
| status | null in requests; actual HTTP status as decimal string in responses |

Signing bytes are ASCII `EOA-VERIFIER-API/1\n` followed by C(protected).
The payload digest binds the entire payload, not a selection of fields.
Every response has a fresh nonce and is bound to the exact initiating request,
including errors and ACKs. A poll response binds the poll request; its payload
also binds the original refresh POST with `originRequestDigest` and
`originRequestNonce`. A response cannot be repurposed as a request.

Paths are the literals below with canonical qb64 identifiers or lowercase
SHA-256 refresh handles. No percent encoding, dot segments, trailing slash,
fragment or duplicate query keys. Replay has exactly
`/v1/events?after=<decimal>&limit=<decimal>&stream=<32-byte base64url>` in that
order, limit 1–20. Bootstrap uses `stream=initial` and `after=0`; only an empty
consumer may bootstrap. A configured peer URL chooses the origin separately.

Service AIDs are single-key transferable Ed25519, signing threshold one and
next threshold one with one next-key commitment. Unsupported service profiles
fail startup. Credential issuer thresholds are unchanged. Obtain keys only from
native accepted KEL state for the configured AID, verify the establishment seal
against that state, and require the latest accepted establishment epoch. Unknown
or old epochs trigger bounded discovery then fail closed if unresolved; old
keys do not authorize retries after rotation. Native KEL/delegation/witness
validation is mandatory; a public key or OOBI in a message grants no trust.
PR 03 proves signing and same-AID rotation with the pinned native dependency.

Explicit trust maps AID to peer URL/discovery, recipient AID, profile, chain and
permitted endpoints/actions. Direction is fixed: verifier sends events; oracle
sends queries; a response must come from the requested peer. Discovery is not
authorization. Persist the authority binding; changing AID requires quarantine
and reconciliation before new grants. Unresolved peer key state blocks intake
and grants, not receipt/nonce/reorg recovery or persisted invalidation handling.

Require `issuedAt <= now + skew`, `now < expiresAt`, `issuedAt < expiresAt`,
and `expiresAt - issuedAt <= configured requestLifetime`. Request nonce use is
durable per signer, audience and nonce until expiresAt + skew; replayed requests
are rejected even after restart. A legitimate delivery retry uses a new nonce
and signature over the same event payload. Authenticate and validate before
reserving a nonce; reserve it atomically with acceptance/enqueue, or durably
consume rejected authenticated requests. Outbound requests retain nonce/digest
until response/deadline; accept only the corresponding response once. A lost
response is retried with a new request; this is safe because domain IDs are
durably idempotent. PR 05/07 test lost ACK after inbox commit explicitly.

Authentication, observation-age checks and nonce pruning share one durable
security-time floor. Before admitting a request/response or pruning nonces,
persist the current Unix-second time as the floor if it is higher. If wall time
is below the persisted floor (including after restart or a forward jump followed
by rollback), suspend authenticated intake, signing fresh claims and new grants
until time catches up or an operator reconciles time and retained replay state.
Do not reset the floor or erase nonces merely to restore readiness. Commit a
pruning time floor before deleting any expired nonce. This prevents a previously
expired request from becoming admissible after its nonce was pruned. Receipt,
nonce and reorg reconciliation using already persisted transaction identities
continues during clock suspension. Whole-database rollback requires the separate
stream/high-water reconciliation rule; time policy cannot detect erased state.

## Payloads and state

`schema.json` defines closed shapes, and `vectors.json` supplies positive and
negative examples. Counters are decimal strings up to 20 digits (chain IDs up
to 32); arithmetic is integer arithmetic, never lexical or floating point.

An assessment contains `version`, `profile`, `verifierAid`, `associationSaid`,
`revision`, `decision`, `decisionDigest`, and `observations`. The immutable
decision core contains `outcome`, `reasonCode`, `facts` (or null while facts
cannot be verified), and `provenance`. Digest is SHA-256 of C(decision).
Facts contain issuer AID, LE and QVI credential SAIDs, extId, and issuance
`registrySaid`, `telSequence` (zero), `telDigest`, `anchorSequence`, `anchorDigest`.
The anchor is the accepted issuer-KEL seal for the issuance, never revocation.
Provenance names the evidence/policy version used to make that decision.
Its evidence digest identifies decision-relevant accepted proof/status evidence;
it excludes transport timestamps and unchanged refresh-response bytes. Refresh
alone cannot change provenance to force a new decision revision.
Once verified, facts are immutable and retained after revocation. Initial
unknown/unavailable/rejected presentations remain queryable without a success
event. Enrollment requires valid evidence/facts; all later meaningful core
changes create a higher revision, including invalidity and unavailability.
No change to the core means no new revision. An unavailable observation cannot
erase known revocation. Core equality never implies fresh evidence.

Observations contain optional account observation and credential observations.
Account data: chain, canonical block number/hash, observation time, code
classification (`empty`, `delegation`, `contract`) and SHA-256 digest of raw code.
Credential data identifies each credential/registry and accepted TEL event,
issuer KEL state, refresh start/end and the configured peers' response digests.
Freshness requires successful responses for the association and LE/QVI sources,
with matching accepted evidence, and an account observation on the configured
chain. See [native-refresh.md](native-refresh.md) for the bounded peer claim.
Stored assessments may have no observations and never promise freshness.

An event adds `streamId`, `eventSequence`, `eventId` and `assessment`.
`eventId = SHA-256(C({streamId,eventSequence,assessment}))`. Sequence starts at
one, is contiguous and durable per stream. Event ID and complete payload,
including creation observations, are immutable. Event sequence is replay order,
revision is association-state order, anchor sequence is issuance order.
None substitutes for the others. No payload carries posting keys, arbitrary
contracts, transaction instructions or authority to change deployment policy.

The oracle derives binding locally after authentication. Inbox receipt and
revision reduction commit together before ACK. For the same event ID, identical
bytes return the same stored acceptance payload; altered bytes conflict. For
the same `(verifierAid, associationSaid, revision)`, differing decision digests
conflict even if that revision is older than the high-water mark; retain the
seen revision/digest history. Identical core with newer observations is not a
conflict. Lower unseen revisions are recorded as stale without replacing
accepted state. Higher revisions apply unless they contradict immutable facts
or terminal credential revocation. Query decisions use the same reducer and
survive restart. ACK outcome is `applied`, `same` or `stale`; acceptanceId is
the eventId. ACK also binds eventId and complete event payload digest; it means
durable acceptance, never endorsement or freshness.

Replay pages have streamId, after, next, highWater and an array of events.
Only replay processing advances the contiguous cursor, atomically with reducer
effects; a webhook arriving ahead does not skip missing events. Page entries
must be consecutive from after+1, next must equal the final entry (or after for
an empty terminal page), and highWater >= next. Verify each event's stream,
sequence and verifierAid against the authenticated response authority. Retain
`(verifierAid, streamId, eventSequence) -> eventId` for both webhook and replay;
a second event at a seen position is a conflict even with a higher revision.
No pruning in the prototype. Unknown stream, after > highWater, lost
history or rollback of any persisted high-water mark is 409 and suspends new
grants pending reconciliation. An empty page with highWater > after is invalid.

## Endpoints and errors

| Owner | Request | Successful result |
| --- | --- | --- |
| Oracle | POST /v1/verifier-events, event payload | 200 signed durable ACK |
| Verifier | GET /v1/assessments/{said}, empty payload | 200 stored assessment |
| Verifier | GET /v1/assessments/{said}/facts, empty payload | 200 immutable facts with association/verifier identities |
| Verifier | POST /v1/assessments/{said}/refresh | 202 refresh handle |
| Verifier | GET /v1/refreshes/{requestId}, empty payload | 202 pending or 200 complete |
| Verifier | GET /v1/events?after=…&limit=…&stream=… | 200 replay page |

Refresh POST payload: associationSaid, chainId, minRevision. Association must
match the path and chain must match deployment configuration. `minRevision`
is the requesting oracle's durable accepted revision floor (zero if unknown),
not equality with the verifier's current revision. A floor below or equal to
the verifier's current revision is accepted. A floor above it returns 409
`CONFLICT` and blocks grants pending rollback reconciliation; do not lower the
oracle's floor to retry. Completed results must have revision >= minRevision.
`requestId` is SHA-256 of the
complete POST envelope. Refresh payloads carry requestId, associationSaid,
originRequestDigest/Nonce, expiresAt and state. Completed payload also contains
assessment. A refreshed assessment must meet minRevision; a lower result is
rollback/unavailable, never permission. Persist bounded work/waiters, expire at
the request deadline, and return 404 for unknown/expired handles. Handlers enqueue;
Doers own waits and escrow progression. A restart either resumes work before its
deadline or makes it unavailable, never fabricates completion. Immutable facts
lookup after revocation is allowed; unknown facts return 404, not a fabricated
issuance order. A valid facts response grants no posting authority.

Errors: 400 malformed, 401 authentication failed/replay, 403 forbidden authority
or action, 404 unknown/expired resource, 409 event/revision/stream conflict,
413 body too large, 422 unsupported version/profile/chain, 503 unavailable.
Error payload has code, bounded diagnostic and retryable. Sign errors only when
request identity/context is authenticated; malformed/unauthenticated requests
may receive an unsigned closed error payload. Clients never treat unsigned
errors as authoritative assessment/ACK/state. A completed refresh can report
`unavailable` at HTTP 200; transport failure never means `invalid`.
`/health` and `/ready` are unauthenticated minimal liveness/readiness endpoints,
not assessment or trust assertions.

## Use-time authority gate

Configure timeout, maximum credential/account ages, reassessment interval,
clock skew and request lifetime explicitly. Freshness is tested at use, not
just arrival: source refresh must begin after the original refresh POST,
complete before its expiry, observations must not be in the future beyond skew,
and both source/account age limits must hold. Check each provider checkpoint
and canonical account block; recheck native source state after account RPC.
Reject contradictory signed summaries: valid source observations must all be at
issuance TEL sequence zero; the association issuer, registry and issuance digest
must match immutable facts. An empty-code classification must carry the digest
of empty bytes. These comparisons do not replace native validation at the verifier.

Before grant, replacement or granting rebroadcast, require an authenticated
request-bound valid refresh and recompute wallet candidate selection and current
on-chain issuance ordering. Recheck after every wait, including preparation and
before signing/submission: association revision alone is insufficient because
candidate B can supersede A without changing A's revision. Same issuer with a
strictly later verified issuance anchor may replace; same anchor or differing
issuer is unresolved. Missing facts for the current on-chain SAID block replacement.

Unavailability blocks new authority/rebroadcast but does not withdraw confirmed
endorsements or alone cancel transactions. Persisted invalidation permits exact
withdrawal and same-nonce cancellation despite peer outages. Retain invalidation
evidence separately from the latest
assessment: an unavailable revision cannot erase an earlier invalidation or its
recovery obligation. Only a higher valid account-recovery decision can retire
nonterminal account invalidation; credential revocation remains terminal.
Retain this evidence even when the invalidation arrives below the latest
assessment revision: unavailable r3 followed by account-invalid r2 still owes
invalidation handling unless a valid revision above r2 is known. A terminal
revocation discovered below already accepted later-valid history is an authority
contradiction: retain revocation, quarantine the association and suspend grants
pending reconciliation. Do not discard it as an ordinary stale packet. Persist
the highest known valid recovery revision independently of the latest assessment.
Already broadcast transactions may mine; retain original/cancellation identities and reconcile
canonical receipts, nonce use and reorgs. No distributed check eliminates the
race between unseen revocation and mining. Contracts have no expiry: outages
provide no automatic finite on-chain stale-authority bound.

## Source and fixture ownership

The existing EIP-712 carrier stays canonical in GLEIF-IT/vlei-oracle at
`77849caae048381aee96b42f75053368d8d24c53`,
`protocol/external-association-v1/eoa-v1/` until its planned extraction. The
manifest records blob hashes and the generator imports exact bytes; never
hand-edit a copied EIP-712 vector. These synthetic encoding examples cannot
establish native credential acceptance. The signed-service vectors use public
test seeds, not service secrets. Oracle will consume a pinned copy of this
directory with provenance, without a runtime import.

See [acceptance.md](acceptance.md) for diagram mapping and unchanged ABI analysis,
and [native-refresh.md](native-refresh.md) for source-backed feasibility bounds.

## Run the contract checks

Requires Python 3.12.6+ and libsodium (for native KERI signature primitives).
From the repository root, use a fresh environment to avoid mixing upstream and
GLEIF distributions that own the same import paths:

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -r protocol/verifier-api-v1/requirements.txt
.venv/bin/python -m unittest discover -s protocol/verifier-api-v1 -p 'test_*.py' -v
```

These checks must not skip. `conformance.py` is an in-memory contract model for
vectors, not production authorization, persistence, KERI discovery or refresh.
It receives explicit fixture trust state. The key-epoch vectors demonstrate
exact signature encoding; accepted native KEL rotation remains PR 03's gate.
Nonce persistence, atomic commits and crash windows require the later real
service tests. There is no claim of an implemented application from these tests.

To reproduce the byte-pinned carrier copies and deterministic public-key service
vectors, supply an oracle checkout containing the provenance commit:

```sh
.venv/bin/python protocol/verifier-api-v1/generate_vectors.py --oracle-dir /path/to/vlei-oracle
git diff --exit-code -- protocol/verifier-api-v1/carrier protocol/verifier-api-v1/provenance.json protocol/verifier-api-v1/vectors.json
```

The generator reads committed source with `git show`; it neither imports the
oracle application nor copies dirty working-tree files. A changed normative
field or serialization rule requires updated positive and negative vectors and
review of both consumers before releasing a new wire contract.
