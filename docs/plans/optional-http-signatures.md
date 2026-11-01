# URL-only webhooks with optional signature verification

Status: implemented and qualified by the full installed-wheel suites and the
maintained paired scenario, including the subsequent OOBI startup qualification.

## Decision

Verifier knows a webhook destination by URL, not by a required receiver AID.
It signs outgoing status-event bytes with its own existing AID. A receiver may
ignore those headers entirely. Oracle chooses to verify them and still authorizes
only its configured Verifier AID.

Response signing is optional. Verifier accepts an ordinary HTTP success response
without signature headers. If either signature header is present, the response
must have a complete, valid signature and a matching body digest. Unknown key
state, malformed signatures and altered bytes fail verification; they never
silently fall back to unsigned success. Oracle keeps its AID and signs responses.

Signature verification proves who signed the covered bytes. It does not by itself
authorize an arbitrary signer as an Oracle producer, prove freshness, or establish
on-chain publication. HTTPS authenticates the configured URL and protects HTTP
status and the optional-signature negotiation from stripping. Optional signatures
cannot provide mandatory mutual authentication or downgrade resistance.

## Inspected sources

- Verifier `7875daeb50dc0df7a8644d8ad11e51673a2ec522` and Oracle
  `633b9880bd07331b8a60267d66c012354980fc4d`, matching their merged trees.
- Actual installed `gleif_keri==1.2.19`: `keri.end.ending.siginput`,
  `desiginput`, `signature`, and `designature`. The old development environment
  contained 1.2.17; use a fresh pinned environment for implementation checks.
- KERIA `d35ef3e6baf19f31dbd4035300d401aaf009b8d7`,
  `SignedHeaderAuthenticator` and its tests. Its signed-header path uses KERIpy
  primitives, a signer AID and request method/path for response context; it does
  not require our five eoa-* attributes or durable transport nonce ledger.

KERIpy's helper supports method/path and ordinary header coverage. It is not a
general RFC 9421 implementation. Do not introduce a second HTTP-signature library
or claim universal RFC interoperability.

## Small signing contract

Use `Signature-Input` and CESR `Signature`, with label `sig0`. The `keyid`
parameter declares the source AID in an HTTP header; no additional AID header is
needed. Keep the helper's `created` parameter and `alg=ed25519`.

Cover `@method`, `@path`, and `content-digest`. The digest is SHA-256 over the
exact transmitted body bytes, including an empty response. Body coverage is the
deliberate addition to KERIA's minimal header pattern: these bytes drive
association selection and contract publication. Content-Type remains ordinary
HTTP metadata; the event endpoint always parses its defined JSON representation.

For a response, method/path identify the initiating request, as in KERIA. This
profile does not sign HTTP status, full origin/query, or a unique attempt ID.
It verifies signed content, not a self-contained per-attempt storage receipt.
Do not restore those guarantees through new application-specific attributes.
Retain transport-safe URL handling and test the actual HIO/Falcon path spelling.

Resolve keyid only through locally accepted KERI key state. Never accept an
unvalidated public key from a header or fetch an arbitrary header-provided URL.
Oracle retains its producer allowlist. Verifier can verify a response from any
locally resolved signer without requiring a per-destination AID setting. Operators
choosing signed responses configure its OOBI; native KERIpy resolution obtains
and validates key state, refreshed on restart after rotation. Plain targets require none of this. Retain the current single-key,
threshold-one limitation; multi-key signing is outside this change.

Remove `eoa-target`, `eoa-audience`, `eoa-action`, `eoa-request`, `eoa-status`,
the application context, attempt nonce, expiry policy, AuthenticatedMessage and
request-reference construction. `created` is signed metadata, not a new freshness
gate. Repeated valid signatures can verify; event deduplication owns replay safety.

## Delivery and persistence

Any complete 2xx response completes delivery after optional signature verification.
No receiver-specific JSON ACK is required. Valid signed error responses remain
errors. Keep current bounded retries, Retry-After handling, dead letters, immutable
event bytes/destinations and restart behavior. Never follow redirects implicitly.

Use `delivered` instead of `acknowledged` in the record and public delivery view,
and `complete` for the completion operation. This means the target returned HTTP
success, not that Verifier independently proved its storage implementation.
Oracle continues returning success only after its atomic event/status/selection/
queue commit, and may retain its useful JSON storage result. Verifier does not
require that JSON contract from other consumers.

Remove Delivery.peerAid, --webhook-aid and all destination-AID plumbing from
acceptance, revocation, composition and tooling. Remove ReplayClaim,
replay_claims. and persistence/transport.py in both applications, and fixture
transport replay storage. Preserve accepted_nonces. and permanent association
nonce consumption: those are unrelated domain protections.

Oracle retains eventId/exact-body conflict checks, monotonic revisions, terminal
revocation, selection isolation, one-operation queues and atomic writes. An exact
duplicate, including the same signed request after restart, returns success
without adding posting work. A conflicting body is rejected.

This intentionally breaks internal APIs, the transport profile and the delivery
record/status schema. No aliases, legacy readers, migrations or fallback profiles.
Use intentionally selected fresh test/deployment stores; never automatically
delete an operator's existing stores or consumed association nonces.

## Implementation sequence

1. **Verifier:** separate signature mechanics from delivery policy, reduce the
   signer/verifier to the small profile, remove required receiver identity and
   transport replay persistence, implement optional response verification and
   ordinary HTTP completion. Update public status, callers and tests together.
   Prove a receiver with no KERI knowledge works, alongside signed-response cases.
2. **Oracle:** adopt the same signature profile, retain explicit producer
   authorization and optional-response signing, remove transport nonce storage,
   and update duplicate/restart expectations. Keep its signing identity and OOBI
   export because signed responses are now an explicit requirement. Provisioning
   a response-signer OOBI in tooling becomes optional, not a webhook startup prerequisite.
3. **Coordinated qualification/docs:** update protocol, operator guides, ADRs,
   earlier maintained plans, integration tooling and diagram sources/artifacts.
   Comply needs only any affected integration wording, not Solidity/ABI changes.
   Advance exact producer/contract pins; publish reviewable PRs promptly and merge
   the coordinated set after tests pass. No intermediate compatibility mode.

## Validation

- Pure signature cases: actual pinned KERIpy encoding, body/method/path tampering,
  missing/partial/malformed headers, changed keyid/digest, unknown key state,
  accepted key rotation and persisted rotation after restart.
- Real HTTP delivery: KERI-unaware receiver; unsigned 200/202/204; valid signed
  success; signed error; invalid or partial signatures; empty signed body;
  disconnect/timeout/framing failure; bounded retries and Retry-After. An unsigned
  error cannot complete work, and a signature failure cannot fall back to success.
- Oracle: unsigned/untrusted requests fail; exact signed duplicates survive
  restart without new effects; changed event bodies fail; rollback remains atomic;
  response loss after commit triggers harmless redelivery. Preserve producer
  proof validation, permanent association nonce rejection and revocation rules.
- Full fresh installed-wheel Verifier and Oracle suites, then maintained paired
  qualification (included in the Oracle suite) at exact coordinated revisions.
  Preserve witnessed issuance, independent services/stores, lost-response faults,
  replacement, withdrawal, and actual token balance assertions.
- Audit obsolete API/header names and current documentation manually. Add no
  architecture/docs-check scripts, generic authentication framework, extra locks,
  key-discovery service or new dependency package.

PR descriptions record the final profile, removed code, changed guarantees,
exact pins and focused/full/paired evidence.
