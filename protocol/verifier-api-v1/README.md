# EOA verifier service boundary

`eoa-verifier` verifies EOA associations and delivers their status to a configured
webhook. `vlei-oracle` uses that authenticated status to publish or withdraw
Ethereum mappings. This document describes the service contract; see
the [operator guide](../../docs/operations.md) for deployment and recovery. [ADR 0002](../../adrs/0002-verifier-result-object.md) records
the rationale for ordinary immutable API objects. This document owns their wire definition.

## Responsibilities

| Component    | Owns                                                                                                           |
| ------------ | -------------------------------------------------------------------------------------------------------------- |
| eoa-verifier | Initial verification, KERIpy credential stores, durable association status and authenticated webhook delivery. |
| vlei-oracle  | Trusted status intake, ownership/replacement selection, Ethereum publish/withdraw and transaction results.     |
| vlei-comply  | Registry, identity adapter and wallet-association policy for token transfers.                                  |

Services have separate identities and writable stores, with no runtime imports
between them. The verifier has no Ethereum posting key. The oracle authenticates
its verifier but does not independently reverify association credentials.

## Verification and acceptance

Initial verification requires KERI/ACDC acceptance, the LE/QVI chain and
issuer-holder relationships, schema/nested SAIDs, registry status, configured
GEDA/QVI trust and delegation, and witnessed issuance. The association issuer
must be the holder identified by the LE ACDC; retain the untargeted/I2I profile.
Receiving credential bytes alone is not acceptance.

Verify the [EIP-712 wallet proof][carrier] and the existing empty-code/EIP-7702
account rule against the configured chain ID/RPC at an identified canonical block.
Confirm KERIpy status after the initial RPC wait before accepting. These checks
do not assess delegated-code safety or prove against later wallet-key theft.

Initial evidence or RPC unavailability moves work to `waiting` with a durable
five-second cooldown. Three attempts exhaust into `dead-letter`; restart and
duplicate Grants do not renew the budget. Established failure
produces `rejected`, and completed initial checks produce `verified`. With a
webhook configured, acceptance commits status and an event. Without a webhook,
acceptance commits locally without an outbox obligation (`delivery` is null).
Association nonces contain 1–128 ASCII characters from `[A-Za-z0-9_-]`.
In either mode, acceptance permanently consumes the exact nonce for that
SAID. Another SAID reusing the nonce is locally `rejected` with `NONCE_REUSED`;
initial verification remains `verified`. Revocation and downstream selection supersession do not
release claims. See [ADR 0005](../../adrs/0005-accepted-association-nonces.md).
Only acceptance
(`status: "accepted"`) and later association revocation (`status: "revoked"`,
`reasonCode: "REVOKED"`) are webhook events; initial rejection/unavailability is
available through public stored status, not sent as a status event.

Verifier acceptance lasts indefinitely until verified revocation of that association.
Oracle supersession changes selection only; it does not revoke verifier acceptance.
Elapsed time, old observations and outages do not invalidate it. There are no
verification refreshes, periodic account checks or continuing source-chain
reassessments. Initial source-chain validation remains mandatory.

## Delivery and revocation

The sender resumes explicit LMDB delivery phases across restart, validates HTTP success,
the signed request reference and event-storage acknowledgment before completion, and
signs every retry anew. Permanent failures stay blocked until correction and
explicit resumption; transient failures retry up to a finite attempt budget. Acceptance events replaced by terminal revocation
remain stored but are not sent after revocation.

Completed verification queues acceptance atomically. Acceptance consumes that
phase and queues its webhook obligation atomically. Delivery references move from
ready to one active slot, then leave active work on ACK or move to dead letters.
Completed results and outbox history are never scanned to discover delivery work.

Persist acceptance and its webhook obligation together. Deliver after commit;
the receiver durably stores the status before acknowledging. Retry unacknowledged
events across restart, preserving event identity and duplicate-safe processing.

Use one HIO sender per configured destination. Configurable defaults are one
request in flight, at least one second between starts (including successes),
a 10-second overall request timeout, and three attempts per event before dead-lettering. Transient failures use jittered
exponential backoff from 1–2 seconds to a 150–300-second cap; valid `Retry-After`
can extend that delay. Persist destination-wide cooldown across restart, reset
failures only on an authenticated ACK, and retain permanent errors for correction.
Retry the immutable event with a fresh signature; never discard failed events.
Only the worker retries, using yielding waits. These are operational defaults,
not cryptographic requirements; the authenticated ACK protocol is unchanged.

Associations arrive through IPEX Grant with supporting KERI evidence.
Receiving a Grant or credential bytes alone do not prove revocation. The issuer issues
the credential TEL revocation. After KERIpy validates that evidence, the verifier
records revoked association status and a separate webhook obligation requiring its own
acknowledgement. Revocation survives restart and duplicate/reordered delivery;
an older success event cannot restore a revoked association.

Sign outbound requests with the EOA Verifier AID using KERI HTTP
`Signature-Input`/`Signature` headers and authenticated body-digest coverage.
The configured target is assumed capable of verification; vlei-oracle is the
initial consumer. Authenticate service requests/replies and acknowledgements
against configured AIDs, binding the payload, peer/action and request/response.
Preserve transport expiry/replay protection and same-AID rotation across restart.
Initially support single-key transferable service AIDs with threshold one.
Transport-message expiry does not expire an accepted association. The public
status route below is outside this authenticated service protocol.

## Transport signature profile

`ServiceAuthenticator` implements this profile with the pinned KERIpy
`Signature-Input` and CESR `Signature` primitives. This is the KERIpy signing
format, not a general RFC 9421 implementation. The webhook sender uses these
primitives; the oracle owns its durable receiver endpoint. The caller
supplies exact body bytes, actual HTTP method
and absolute target URL (including query), matched to its configured destination.
Expected action and peer trust come from configuration/operation, not incoming headers.

Configuration rejects path/query spellings that the pinned HIO client rewrites.
For example, `?memo=a+b&path=%2F` is preserved; `?memo=a%20b`, repeated parameter
names, bare parameters and percent-escaped paths are rejected before startup.
Include an explicit path (`/` for the root endpoint); leading `//` paths are unsupported.
Use the same supported URL on both peers. Existing event destinations stay immutable.

Signature label `sig0` covers, in order: `@method`, `@path`, `content-digest`,
`content-type`, `eoa-target`, `eoa-audience`, `eoa-action`, `eoa-request`,
`eoa-status`. The digest is SHA-256 over the exact bytes; content type is
`application/json`. Target is the full URL; audience is the receiving AID.
Action identifies the expected operation. Requests use an empty request reference
and status `0`; ACKs use action `ack`, HTTP status `200` and the original
`nonce:Content-Digest` reference. The actual response status must also be `200`.
ACK policy belongs to the webhook delivery components, which use the common
`sign()` and `verify()` operations. The webhook receiver signs after durable
storage; the sender validates response status, request/event correlation and
application ACK payload before completing delivery. Authentication alone can
succeed for a signed error response and does not imply delivery success.

KERIpy signature parameters include the sender AID as key ID, context
`eoa-verifier/v1`, algorithm `ed25519`, a random 128-bit hexadecimal attempt nonce,
and created/expiry UTC seconds. The configurable maximum lifetime defaults to
60 seconds, with no clock-skew allowance. Expired or future-created messages fail;
transport expiry has no effect on association validity.

Verify only the configured peer's locally accepted current key. Rotation needs
KERIpy event acceptance; after rotation, old-key attempts fail and a retry signs
anew. There is no network key refresh in this helper. After authentication, an
insert-only peer/nonce claim rejects replay across restart. Claims are retained persistently. A lost ACK is retried with a fresh nonce and the same immutable
application event; event deduplication remains separate. Missing keys or invalid
signatures never consume a nonce or establish application acceptance.

## Downstream consumers

Durable delivery ACK, Oracle selection and confirmed on-chain endorsement are
separate milestones. Oracle owns [oracle-api-v1](https://github.com/GLEIF-IT/vlei-oracle/blob/main/protocol/oracle-api-v1/README.md),
including ownership, replacement and withdrawal. Oracle supersession is not a
verifier status and cannot revoke acceptance here. Contracts own their
[registry interface](https://github.com/GLEIF-IT/vlei-comply/blob/main/docs/oracle-registry.md).

## Stored status

Public `GET /v1/associations/{said}/status` requires no caller KERI signature or
signed response. Return stored pending/verifying/waiting/dead-letter/verified/rejected/accepted/revoked
status and reason,
plus the last-known initial account observation: wallet address, chain ID, code,
block number/hash and observation time. Unknown observations remain unknown.
Known candidates, including waiting and dead-letter work, return `200`; unknown SAIDs return `404`.
Observation age is informational. GET performs no RPC, refresh or enrollment;
its response does not replace authenticated status delivery to the oracle.
Delivery progress describes the requested association's current event; shared
destination scheduling metadata is not public. Supersession is the oracle’s
selection decision, not a verifier status.

[carrier]: ../external-association-v1/eoa-v1/README.md

## Status event and application ACK

The initial acceptance shape is:

```json
{
  "version": "1",
  "eventId": "example-association:1",
  "associationSaid": "example-association",
  "statusRevision": 1,
  "status": "accepted",
  "association": {
    "issuerAid": "example-issuer",
    "leSaid": "example-le",
    "extId": "eip155:31337:0x1111111111111111111111111111111111111111",
    "issuanceAnchor": {"sequenceNumber": 3, "said": "example-issuer-kel-event"}
  },
  "accountObservation": {
    "wallet": "0x1111111111111111111111111111111111111111",
    "chainId": 31337,
    "blockNumber": 42,
    "blockHash": "0x2222222222222222222222222222222222222222222222222222222222222222",
    "code": "0x",
    "observedAt": "2026-10-23T12:00:00Z"
  }
}
```

Identifiers above are illustrative. Issuance identifies the verified anchor in the
issuer's KEL, not arrival order. The observation records the initial check only;
its age never expires acceptance. `eventId` combines association SAID and status revision.

Verified association revocation creates a second event: `statusRevision: 2`,
`eventId: "example-association:2"`, `status: "revoked"`, and
`reasonCode: "REVOKED"`. Keep the original `association` and `accountObservation` objects;
the issuance anchor must not become the revocation anchor. Commit revocation and
this event together, using the original delivery destination. Revocation is terminal
for that SAID and requires its own ACK; the initial event’s ACK cannot complete it.

POST the exact stored bytes to the configured destination with the service
signature profile. Completion requires an authenticated HTTP 200 response bound
to that attempt, with exactly this JSON object (`stored` is a boolean):

```json
{"eventId": "example-association:1", "stored": true}
```

The receiver signs only after durable status-event storage. Redelivery keeps the event/body
and gets a fresh transport signature; the receiver acknowledges duplicates without
repeating effects. A signature on an error response does not complete delivery.


## Evidence intake

`POST /` accepts the KERI JSON-body/CESR-attachment-header form; `PUT /` accepts
a finite CESR stream. HTTP 204 means intake only. Each request is independent
remote evidence; complete messages may enter KERIpy state even if a later message
is incomplete. Missing source evidence uses native escrows. `GET /health` is
liveness only; KERIpy also exposes public OOBI introduction routes. See
[operations](../../docs/operations.md) for peer introduction, bounded framing and
the known KERIpy receipt-couple shortage limitation.
