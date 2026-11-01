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

A webhook requires only `--webhook-url`. The target can be entirely KERI unaware:
Verifier signs requests with its own AID, and the target chooses whether to verify.
No receiver AID, shared secret, registration or signed response is required.
Oracle chooses to verify requests and authorize its configured Verifier AID.

Verification queues acceptance atomically. Acceptance consumes its phase and
queues its immutable event/destination atomically. One HIO sender advances durable
ready/active/dead references; it never scans completed history for work. A complete
2xx response completes delivery after verification of any supplied signature.
The response body can be empty or arbitrary; no common JSON ACK is required.
Public `delivery.delivered` means HTTP success, not independently proven storage
or Ethereum publication. Oracle returns success only after its durable commit.

Keep one request in flight, at least one second between starts, a ten-second
request timeout and three attempts by default. Transient errors use persisted
jittered backoff and Retry-After; permanent errors require correction and manual
resumption. Retry identical event bytes. No implicit redirects. A valid signed
error is still an error; an invalid signature never falls back to unsigned success.

After KERIpy validates the issuer's credential TEL revocation, Verifier records
revoked association status and a separate delivery obligation. Do not send an
older acceptance after local revocation. Duplicate/reordered status events cannot
restore a revoked Oracle association. Permanent association nonce consumption is
unchanged and independent of HTTP signatures.

## Transport signature profile

`HttpSignatures` uses pinned KERIpy `Signature-Input` and CESR `Signature` helpers.
It is not a general RFC 9421 implementation. Label `sig0` covers, in order,
`@method`, `@path`, and `content-digest`. Content-Digest is SHA-256 over the exact
transmitted bytes. Signature-Input `keyid` declares the source AID; `created` and
`alg=ed25519` are KERIpy signature parameters. No application-specific headers,
attempt nonces, expiry, audience or request-reference fields are used.

For responses, method/path refer to the initiating HTTP request, following KERIA's
signed-header pattern. Signature coverage does not include HTTP status, origin,
query or a unique attempt. `created` is metadata, not a freshness requirement.
These are signed contents, not portable per-attempt storage receipts. Use HTTPS
for target authentication and transport integrity. Accepting unsigned responses
necessarily permits signature stripping outside an authenticated transport.

Verifier checks signatures whenever either Signature or Signature-Input is
present. Both must be complete and valid; digest mismatch, unknown signing key
state, malformed signatures and invalid signatures fail delivery. With neither
header, normal HTTP result handling applies. A digest header alone does not opt
into signature verification. There is no target-specific authentication mode.

Resolve `keyid` only against locally accepted current KERI key state. The header
never authorizes an arbitrary Oracle producer or supplies a trusted public key.
Oracle checks the signer against `--verifier-aid`. Verifier verifies response
signers without a required destination-AID setting; operators opting into signed
responses configure `--webhook-oobi`. The native resolver obtains validated key
state before delivery starts and refreshes the introduction on restart after rotation.
Unknown keys are not fetched automatically. Initially support single-key,
threshold-one transferable service AIDs; retain rotation/restart verification.

Exact replay can verify. Oracle deduplicates durably by eventId and exact body,
checks revision order and terminal revocation, and adds no work on redelivery.
There is no transport nonce database. Signature verification does not claim
application persistence or Ethereum publication.

HIO URL rendering restrictions remain: use an explicit path and a spelling the
client preserves. Percent-escaped paths, leading //, duplicate query names and
other rewritten query spellings remain rejected. Query parameters are transported
but not signed; Oracle's configured route/query validation remains separate.

## Downstream consumers

HTTP delivery completion, Oracle selection and confirmed on-chain endorsement are
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

## Status event and HTTP completion

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
for that SAID and requires its own successful delivery; completion of the initial
event cannot complete the revocation event.

POST the exact stored bytes to the configured destination with the service
signature profile. Any complete HTTP 2xx response completes delivery after any
supplied signature verifies. There is no required response body. Oracle returns
a signed storage result like this after committing (`stored` is a boolean):

```json
{"eventId": "example-association:1", "stored": true}
```

Oracle signs only after durable status-event storage. Redelivery keeps the event/body
and gets a fresh transport signature; Oracle accepts duplicates without repeating
effects. Other targets may return unsigned success. A signature on an error
response does not complete delivery.


## Evidence intake

`POST /` accepts the KERI JSON-body/CESR-attachment-header form; `PUT /` accepts
a finite CESR stream. HTTP 204 means intake only. Each request is independent
remote evidence; complete messages may enter KERIpy state even if a later message
is incomplete. Missing source evidence uses native escrows. `GET /health` is
liveness only; KERIpy also exposes public OOBI introduction routes. See
[operations](../../docs/operations.md) for peer introduction, bounded framing and
the known KERIpy receipt-couple shortage limitation.
