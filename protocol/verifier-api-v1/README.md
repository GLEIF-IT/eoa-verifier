# EOA verifier service boundary

`eoa-verifier` verifies EOA associations and delivers their status to a configured
webhook. `vlei-oracle` uses that authenticated status to publish or withdraw
Ethereum mappings. This document describes the service contract; see
the [operator guide](../../docs/operations.md) for deployment and recovery. [ADR 0002](../../adrs/0002-verifier-result-object.md) records
the initial delivery object and ACK shape.

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

Initial evidence or RPC unavailability leaves work `pending`; established failure
produces `rejected`, and completed initial checks produce `verified`. With a
webhook configured, acceptance commits status and an event. Only acceptance
(`status: "accepted"`) and later association retirement (`status: "revoked"`,
`reasonCode: "REVOKED"`) are webhook events; initial rejection/unavailability is
available through public stored status, not sent as a status event.

Acceptance lasts indefinitely until association revocation or supersession.
Elapsed time, old observations and outages do not invalidate it. There are no
verification refreshes, periodic account checks or continuing source-chain
reassessments. Initial source-chain validation remains mandatory.

## Delivery and revocation

The sender rediscovers pending events across restart, validates HTTP success,
the signed request reference and event-storage acknowledgment before completion, and
signs every retry anew. Permanent failures stay blocked until correction and
explicit resumption; transient failures retry automatically. Superseded acceptance
events remain stored but are not sent after retirement.

Persist acceptance and its webhook obligation together. Deliver after commit;
the receiver durably stores the status before acknowledging. Retry unacknowledged
events across restart, preserving event identity and duplicate-safe processing.

Use one HIO sender per configured destination. Configurable defaults are one
request in flight, at least one second between starts (including successes),
and a 10-second overall request timeout. Transient failures use jittered
exponential backoff from 1–2 seconds to a 150–300-second cap; valid `Retry-After`
can extend that delay. Persist destination-wide cooldown across restart, reset
failures only on an authenticated ACK, and retain permanent errors for correction.
Retry the immutable event with a fresh signature; never discard failed events.
Only the worker retries, using yielding waits. These are operational defaults,
not cryptographic requirements; the authenticated ACK protocol is unchanged.

Associations arrive through IPEX Grant with supporting KERI evidence.
Grant receipt or credential bytes alone do not prove revocation. Retire an
association only after KERIpy verification accepts its revocation evidence,
then persist retirement and a separate webhook obligation requiring its own
acknowledgement. Retirement survives restart and duplicate/reordered delivery;
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
Include an explicit path (`/` for the root endpoint).
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
acceptance; the sender validates response status, request/event correlation and
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
insert-only peer/nonce claim rejects replay across restart. Claims are retained
in this increment. A lost ACK is retried with a fresh nonce and the same immutable
application event; event deduplication remains separate. Missing keys or invalid
signatures never consume a nonce or establish application acceptance.

## Ownership and Ethereum mappings

Follow [ADR 0001](../../adrs/0001-eoa-association-ownership-and-replacement.md):
strictly later verified issuance wins within the same LE; another LE must wait
for verified revocation releasing the current claim. Never order different
issuers by their KEL sequence numbers. Same-event multiple-association handling
is deferred in the ADR appendix.

The oracle publishes an accepted, issued, selected association and withdraws a
revoked association by exact SAID. A delayed revocation of an older association
must not remove its replacement. Check durable revocation and selection before
acting or retrying, without repeating initial verification.

Preserve the existing [registry ABI][registry], identity adapter and wallet policy.
Derive the wallet from canonical `extId` and the identity reference from
`keccak256(UTF-8(issuerAid))`, not LEI or LE credential SAID. Deployment supplies
chain/RPC, writer and contract configuration. Use ordinary submission, receipt
and contract-state handling: submission is not confirmation. An in-flight
transaction can still mine after revocation; no immediate reversal or advanced
transaction-recovery guarantee is made. Undelivered revocation can leave a
mapping active because contracts do not expire mappings automatically.

## Stored status

Public `GET /v1/associations/{said}/status` requires no caller KERI signature or
signed response. Return stored pending/verified/rejected/accepted/revoked status and reason,
plus the last-known initial account observation: wallet address, chain ID, code,
block number/hash and observation time. Unknown observations remain unknown.
Known pending/rejected candidates return `200`; unknown SAIDs return `404`.
Observation age is informational. GET performs no RPC, refresh or enrollment;
its response does not replace authenticated status delivery to the oracle.
Supersession is the oracle’s selection decision, not a verifier status.

[carrier]: https://github.com/GLEIF-IT/vlei-oracle/blob/77849caae048381aee96b42f75053368d8d24c53/protocol/external-association-v1/eoa-v1/README.md
[registry]: https://github.com/GLEIF-IT/vlei-comply/blob/6220cd78411b8b721838ee67f11293ff5504c05c/src/attestation/VLEIOracleRegistry.sol
