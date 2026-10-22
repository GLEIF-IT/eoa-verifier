# Bounded native source refresh

This contract defines a successful observation of configured peers during one
refresh interval. It does not establish global latest state, continuous
observation, or a cryptographic proof of non-revocation. A successfully
validated revocation remains authoritative even when the rest of a refresh
cannot complete. This specification adds no new KERI message type.

## Concrete native path and its limits

The inspected KERI dependency is GLEIF-IT/keripy commit
`0d3f4808aa9960bdc6a63da7aede2fca7101bea8`. Paths below are relative to that tree.

| Native source | Observed behavior used by this contract |
| --- | --- |
| `src/keri/app/indirecting.py`, `setupWitness`, `QueryEnd.on_get` | Witness setup registers `GET /query`. `typ=kel&pre=<issuerAid>` returns a full first-seen KEL replay. `typ=tel&reg=<registrySaid>&vcid=<credentialSaid>` concatenates registry and credential TEL replays. Successful responses use `application/json+cesr`. |
| `src/keri/db/basing.py`, `Baser.clonePreIter` | KEL replay includes native event attachments, but skips an event when cloning raises an exception. HTTP success alone therefore cannot certify complete accepted history. |
| `src/keri/vdr/viring.py`, `Reger.clonePreIter`, `cloneTvt` | TEL replay includes native backer signatures and issuer source-seal attachments when present. |
| `src/keri/app/agenting.py`, `WitnessInquisitor.msgDo` | `sent` records transport/query-dispatch completion. Its documentation explicitly excludes proof that requested KEL/TEL evidence arrived. This is not the refresh completion signal. |
| `src/keri/vdr/verifying.py`, `Verifier.processCredential` | Native credential acceptance and source checks are required; `CredentialExpiry` compares event time, not receipt of a new peer response. It cannot supply this observation clock. |

The existing combined oracle's `verification/credentials.py:assess_association`
and `accepted_credential` read accepted local credentials and TEL state. They do
not contact peers. `serving.py` wires the native Parser, Kevery, Tevery, Revery,
Verifier and mailbox machinery; their accepted state remains authoritative for
cryptographic validation. The refresh coordinator will add request-specific
response accounting around that machinery, not replace its validation.

Use direct GET responses because the HTTP request/response exchange can be
attributed to one bounded attempt even when the peer returns unchanged events.
Do not substitute a queued `qry`, a transport ACK, mailbox arrival unrelated to
this attempt, an empty parser queue, or a reread of `saved`/`vcState`.

`QueryEnd` returns no request nonce, signed response head, snapshot identifier,
or signed claim that no later event exists. The response is not a witness's
signed freshness assertion. Native signatures authenticate contained evidence;
TLS authenticates the configured endpoint for the observed exchange. Completeness
of that endpoint's current replay is an explicit operational trust assumption.
An unknown omitted final suffix or a dishonest peer serving an old valid prefix
cannot be excluded by this API. Detectable gaps, conflicting histories, missing
required evidence, and responses behind locally accepted state cannot succeed.

## Contact selection

Deployment configuration binds each permitted issuer AID to:

- Its allowed discovery/OOBI sources and an optional issuer-operated QueryEnd
  base URL, authenticated by a configured TLS identity.
- A mapping of permitted witness AIDs to QueryEnd base URLs, also authenticated
  by configured TLS identities. A peer AID is bound to its endpoint in this
  configuration; an arbitrary URL returned inside evidence is not permission
  to contact or trust it.

An explicitly configured local integration fixture may use HTTP on loopback
with its peer-AID/port mapping fixed by the fixture. This relies on trusted local
processes; it supplies no remote endpoint authentication. Remote cleartext HTTP,
unverified TLS, redirects and caching proxies are unsupported. Configure the
endpoint to execute QueryEnd for every request, issue no conditional requests,
request cache bypass, and reject 304 responses. Cache-control headers alone do
not prove this deployment assumption.

Resolve candidate witness locations with native accepted endpoint/location
records (`Hab.endsFor` / `Hab.fetchUrls`) and the issuer's native accepted KEL
witness list, then match them to the configured allowed mapping. OOBI resolution
is discovery, not endpoint authorization, credential acceptance or freshness.
There is no random single-witness shortcut.

For each association, LE and QVI credential, derive its issuer and registry from
native accepted credential bytes. The QVI issuer must be the configured trusted
GEDA. The required peer set is every witness in that issuer's current accepted
witness list plus its issuer-operated endpoint when configured. A witnessed
issuer with an unmapped/unavailable current witness cannot complete refresh. For
an issuer with no witnesses, a configured issuer-operated endpoint is mandatory.
The association issuance must independently satisfy the profile's historical
witness-receipt requirement; a refresh contact policy does not weaken it.
All required peers must support both QueryEnd calls and retain the relevant TELs.
Witnessing a KEL alone does not establish that a witness stores those TELs.

Freeze the selected peer set for the attempt. If newly accepted issuer KEL state
changes that set, extend the work to the newly required peers and re-evaluate
within the original deadline. Never silently shrink the original required set
to make an outage pass. Repeated changes or more than the wire limit of sixteen
unique peers make this attempt unavailable. Deployment policy must represent the
full supported set; truncating it is forbidden.

## Required responses and completion predicate

A refresh records its original authenticated request digest/nonce, association,
minimum revision, start and deadline. Its start is after the refresh POST is
accepted. Doers own network waits and native escrow progression; Falcon handlers
enqueue bounded work. Coalesced work may satisfy a waiter only when its evidence
requests began after that waiter's POST acceptance.

For each required peer and each of the three credentials:

1. After the attempt starts, issue
   `GET /query?typ=kel&pre=<issuerAid>` and
   `GET /query?typ=tel&reg=<registrySaid>&vcid=<credentialSaid>` against its
   configured origin. Omit `sn` so that evidence from inception is available;
   the incremental KEL endpoint rejects a missing starting sequence and cannot
   express unchanged-at-head completion by itself. Bound connection, body size,
   parsing and total attempt time. A size limit failure is unavailable, never
   permission to truncate evidence.
2. Require a complete successful HTTP 200 response with the expected native
   content type, correct target attribution and a nonempty body for each call.
   Reject wrong-origin, empty, malformed, truncated, oversized or failed
   responses. Retain the exact body digest and local request/completion times.
   Each response must belong to the current attempt, not a prior cache entry.
3. Account for all replayed events and attachments using native decoding and
   validation. Ensure the KEL is for the requested issuer and the TEL replay is
   for the requested registry/credential; require registry ownership and issuer
   anchors, credential sequence continuity and all necessary native signatures,
   witness/backer receipts and delegation validation. Resolve dependency evidence
   and relevant escrows within the same deadline. Unrelated escrow entries need
   not be drained. Parser consumption alone cannot certify acceptance: errors
   may be consumed and duplicates need not produce a new acceptance cue.
4. Require each peer's supplied replay to cover the final accepted issuer KEL
   head and the final accepted registry/credential TEL state used for this
   assessment. Mere agreement with an older prefix is insufficient when local
   state or another peer shows a later event. If peers diverge, retry within the
   deadline or finish unavailable; never choose the oldest common state. Already
   accepted revocation overrides an incomplete response set. Native fork or
   delegation problems cannot be normalized into a fresh valid result.
5. After native acceptance, reread association, LE and QVI credential statuses
   through native indexed state and re-run the relationship, schema, issuer,
   witness-anchor and external-association proof checks. Observe the account
   from the configured chain/checkpoint at a canonical block, then recheck native
   source state after the RPC wait. A newer relevant event or changed required
   peer set invalidates the pending completion until it is accounted for.

An **unchanged-valid** refresh completes only when all three credentials were
already accepted, every required peer has supplied both qualifying responses
within the attempt, the native accepted evidence still says issued and meets all
profile checks, and the account observation meets the policy. Every advertised
head must be supported by this attempt's responses even if those exact bytes
were accepted previously. Duplicate native processing is expected and does not
require a new TEL event, credential `saved` entry or assessment revision.

The resulting decision core may be identical to the stored decision. Preserve
its revision and digest; produce new request-bound observations. Credential
observation `telDigest` and `kelDigest` identify accepted native event SAIDs.
Within each `peers` entry, `kelDigest` and `telDigest` instead mean lowercase
SHA-256 digests of the exact respective HTTP response bodies; `peerAid` identifies
the configured contact. Keep those entries unique and sorted by peer AID.
`completedAt` for a peer is after both complete responses; credential
`completedAt` is after native validation and final source checks, with
`startedAt <= peer.completedAt <= credential.completedAt` for every peer.
These local observation times do not replace native event timestamps.
The durable local attempt record retains endpoint selection, request/response
association and validation dispositions needed to substantiate the wire summary.

Missing contacts, required responses or validation at the deadline yields
`unavailable`, unless accepted contradictory evidence already establishes
`invalid`. Restart must resume a durable attempt before its deadline or mark it
unavailable; old body digests and a new timestamp cannot fabricate a new attempt.
Use-time freshness still applies to a successfully completed response. There is
no promise that a revocation cannot be issued or received immediately afterward.

## Feasibility boundary and required evidence

Source inspection establishes the replay API and a possible unchanged-response
transport boundary, not a working refresh implementation. The contract's bounded
claim is supportable only under the explicit honest-current-replay endpoint
assumption above. A requirement for a nonce-bound witness-signed latest/nonrevoked
assertion would be unsupported by this API and would require a plan/dependency
change before freezing or implementing that stronger claim.

PR 03 must prove the selected path with the pinned dependency and actual HTTP
peers: repeat unchanged issued evidence, accept newly received revocation, account
for duplicate replay without a new native cue, reject missing/truncated/wrong or
behind-head responses, and demonstrate the relevant escrow/acceptance correlation.
It must also verify actual required peers expose QueryEnd and hold issuer KEL,
registry and credential TEL data. Configuration examples alone are insufficient.
PR 06 adds the durable multi-source coordinator, request deadlines, account wait,
source-change fan-out and restart qualification. No feasibility proof is claimed
by PR 01's static vectors.

Known blockers before enabling fresh-valid posting are: absent required QueryEnd
or TEL retention; inability to distinguish response-specific validation from
unrelated accepted cache state; inability to account for incomplete/malformed
replays through the pinned parser; and failure of TLS/current-replay deployment
assumptions. Do not solve them with timestamp stamping, disabling native checks,
or treating `WitnessInquisitor.sent` as success. Surface any failed PR 03 proof
and resolve it before relying on this completion predicate.
