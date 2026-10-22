# EOA verifier service boundary

`eoa-verifier` verifies EOA associations and delivers their status to a configured
webhook. `vlei-oracle` uses that authenticated status to publish or withdraw
Ethereum mappings. This document describes the service contract; no runtime is
implemented yet. [ADR 0002](../../adrs/0002-verifier-result-object.md) illustrates
a provisional result object.

## Responsibilities

| Component    | Owns                                                                                                           |
|--------------|----------------------------------------------------------------------------------------------------------------|
| eoa-verifier | Initial verification, native credential stores, durable association status and authenticated webhook delivery. |
| vlei-oracle  | Trusted status intake, ownership/replacement selection, Ethereum publish/withdraw and transaction results.     |
| vlei-comply  | Registry, identity adapter and wallet-association policy for token transfers.                                  |

Services have separate identities and writable stores, with no runtime imports
between them. The verifier has no Ethereum posting key. The oracle authenticates
its verifier but does not independently reverify association credentials.

## Verification and acceptance

Initial verification requires native KERI/ACDC acceptance, the LE/QVI chain and
issuer-holder relationships, schema/nested SAIDs, registry status, configured
GEDA/QVI trust and delegation, and witnessed issuance. The association issuer
must be the holder identified by the LE ACDC; retain the untargeted/I2I profile.
Receiving credential bytes alone is not acceptance.

Verify the [EIP-712 wallet proof][carrier] and the existing empty-code/EIP-7702
account rule against the configured chain ID/RPC at an identified canonical block.
Confirm native status after the initial RPC wait before accepting. These checks
do not assess delegated-code safety or prove against later wallet-key theft.

| Outcome       | Meaning                                                                        |
|---------------|--------------------------------------------------------------------------------|
| `valid`       | Required initial checks succeeded.                                             |
| `invalid`     | Initial verification failed or the accepted association ACDC was revoked.      |
| `unavailable` | Required initial evidence or access is missing; the candidate is not accepted. |

Acceptance lasts indefinitely until association revocation or supersession.
Elapsed time, old observations and outages do not invalidate it. There are no
verification refreshes, periodic account checks or continuing source-chain
reassessments. Initial source-chain validation remains mandatory.

## Delivery and revocation

Persist acceptance and its webhook obligation together. Deliver after commit;
the receiver durably stores the status before acknowledging. Retry unacknowledged
events across restart, preserving event identity and duplicate-safe processing.

Associations arrive through IPEX Grant with supporting native KERI evidence.
Grant receipt or credential bytes alone do not prove revocation. Retire an
association only after native verification accepts its revocation evidence,
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
signed response. Return stored acceptance/revocation/supersession state and reason,
plus the last-known initial account observation: address, chain ID, classification,
block number/hash and observation time. Unknown observations remain unknown.
Known pending/failed candidates return `200`; unknown SAIDs return `404`.
Observation age is informational. GET performs no RPC, refresh or enrollment;
its response does not replace authenticated status delivery to the oracle.

[carrier]: https://github.com/GLEIF-IT/vlei-oracle/blob/77849caae048381aee96b42f75053368d8d24c53/protocol/external-association-v1/eoa-v1/README.md
[registry]: https://github.com/GLEIF-IT/vlei-comply/blob/6220cd78411b8b721838ee67f11293ff5504c05c/src/attestation/VLEIOracleRegistry.sol
