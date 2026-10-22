# EOA verifier service boundary

This is the initial design for independently deployable `eoa-verifier` and
`vlei-oracle`. The [schema](schema.json) and [examples](examples.json) describe
basic assessment data, not a complete wire protocol or cryptographic proof.
Exact signing, event and ACK contracts belong with their implementations.

## Responsibilities

| Component | Owns |
| --- | --- |
| eoa-verifier | Native CESR/IPEX intake and credential stores, initial credential/wallet/account verification, durable acceptance and association revocation, authenticated webhook delivery. |
| vlei-oracle | Trust in the configured verifier, durable status intake, ownership/replacement selection, Ethereum publish/withdraw and ordinary transaction result handling. |
| vlei-comply | Existing registry, identity adapter and wallet-association policy for token transfers. |

Each service has its own identity, configuration and writable stores. Neither
imports the other at runtime. The verifier has no Ethereum posting key. The
oracle retains native KERI support for service authentication, not association
credential reverification.

## Initial verification and result shape

Preserve exact ACDC/schema and nested SAIDs, native association and LE/QVI source
acceptance, issuer/holder relationships, configured GEDA and QVI delegation,
untargeted association/I2I edge, registry ownership/status and historical
witnessed issuance with verified receipts. Candidate bytes and escrows are not
acceptance. The association issuer must be the verified LE ACDC holder AID.

Reconstruct and verify the canonical EIP-712 wallet proof. Check the configured
chain ID/RPC and empty-code/EIP-7702 account rule at an identified canonical
block. Recheck native status after the initial account RPC wait before accepting.
Keep the existing [EIP-712 profile and vectors][carrier]. The account check does
not assess delegated-code safety; the ceremony does not prove against later theft.

| Outcome | Meaning |
| --- | --- |
| `valid` | Initial required checks succeeded; stored acceptance suffices for endorsement processing subject to ownership/replacement and retirement state. |
| `invalid` | Initial verification failed or the accepted association ACDC was revoked. |
| `unavailable` | Initial verification lacks required evidence/access; do not accept that candidate. This does not invalidate an already accepted association. |

`associationSaid` is the identity; no second ceremony UUID. `revision` orders
changed decisions within one verifier AID/association, not issuance or expiry.
`binding` is required for `valid` and carries verified issuer/LE/QVI identities and
canonical `extId`. The oracle derives wallet from `eip155:<chainId>:<address>` and
`identityRef = keccak256(UTF-8(issuerAid))`; LEI and LE credential SAID are not
substitutes. `reasonCode` explains the result; its final taxonomy is deferred.
The synthetic examples show success, later revocation and a separate incomplete
presentation. Schema validation is not native verification. Transport signatures,
delivery IDs and issuance/account evidence fields are settled with implementation.

## Acceptance lifetime and service authentication

**User-directed scope reduction, 2026-10-22:** accepted associations remain valid
indefinitely until their association ACDC is revoked or they are superseded.
Elapsed time, old observations and service outages do not invalidate acceptance.
This build has no age limits, freshness leases, verification refreshes, periodic
account checks or continuing LE/QVI reassessment. Initial source validation is
mandatory. Future account rechecking is deferred without infrastructure now.

The oracle trusts authenticated status from its configured EOA Verifier. An
accepted, issued and selected association is published; a revoked association's
exact mapping is withdrawn. No new credential verification, account check or
observation-age gate precedes posting or retry. Check durable revocation and
selection state before acting and after waits.

Send webhooks to one configured destination; vlei-oracle is the initial consumer.
Use KERI HTTP `Signature-Input`/`Signature` headers signed with the verifier's
habitat/AID, as in Sally's outbound sender. Bind the payload with an authenticated
body digest; matching header names alone is not interoperability. The receiver
is assumed capable of verification. Sign each delivery attempt while retaining
its immutable event identity. No custom JSON envelope or routing framework.

Authenticate service requests/replies and ACKs with configured AIDs and native
accepted key state. Bind body, intended peer/action and request/response; preserve
transport expiry/replay protection across restart and supported same-AID rotation.
Discovery is not authorization. Initially support single-key transferable service
AIDs with threshold one; this does not restrict native credential issuers.
Message expiry does not expire stored association acceptance. The public status
GET below is outside this authenticated service protocol.

## Workflows

1. **Accept:** verify initially; atomically persist acceptance, verified facts and
   an outbox obligation. Send HTTP after commit; retry until authenticated ACK.
   Pending/rejected presentations remain queryable without a success event.
2. **Publish:** authenticate and durably store status before ACK. Duplicates do
   not repeat business effects. Apply [ADR 0001](../../adrs/0001-eoa-association-ownership-and-replacement.md):
   same-LE strictly later issuance wins; another LE must wait for verified
   revocation releasing the current claim. Never compare different KEL sequences.
3. **Retire:** native-verified association revocation durably retires that SAID
   and creates a separate webhook obligation requiring its own ACK. Preserve
   retirement across restart/replay. A delayed old-SAID revocation cannot remove
   its replacement. No continuing source-chain or account reassessment.
4. **Apply contract effects:** reuse existing operations and ordinary submission,
   receipt and contract-state handling. Report pending, failed and confirmed
   outcomes accurately; a transaction hash is not confirmation. No new cancellation
   workflow, nonce-reconciliation state machine or reorg-recovery subsystem is
   required. Reuse useful existing code without unrelated deletion/refactoring.
   An in-flight transaction may still mine after revocation; use ordinary result
   handling and exact-SAID withdrawal, without claiming immediate reversal or
   automatic advanced recovery.

Duplicate/reordered old events cannot resurrect revoked status. Native evidence
and application stores are separate; recover their commit gap using persisted
native state. Multiple associations in one issuance event are deferred to the
ADR appendix, with no conflict-detection/invalidation machinery or special tests.

### Native revocation delivery

In inspected KERIpy, `GrantDoer.grantDo` calls `credentialing.sendArtifacts` to
stream issuer KEL, registry TEL and credential TEL before the IPEX Grant. The
embedded `iss` comes from `cloneTvtAt(said)` at sequence zero and is issuance,
not revocation. A sender with stored revocation conveys it through the TEL stream.

The receiver parser dispatches `rev`/`brv` to Tevery. `Tever.revoke` checks prior
TEL linkage and native anchor/backer requirements before persisting the event
and emitting a revoked cue; `vcState` exposes accepted TEL status. Grant receipt,
credential bytes, unvalidated events and escrow presence alone are insufficient.
Recover retirement from persisted TEL if a cue/application commit was lost.
This uses native delivery and escrow completion, not a new revocation protocol
or periodic verification. The Grant intake's embedded `anc`/`iss`/`acdc` replay
alone is not proof of revocation; PR 06 must demonstrate the accompanying native
revocation stream and restart behavior.

Source basis: GLEIF KERI `0d3f4808aa9960bdc6a63da7aede2fca7101bea8`,
`app/cli/commands/ipex/grant.py`, `vdr/credentialing.py:sendArtifacts`,
`vdr/viring.py:cloneTvtAt`, `core/parsing.py` and `vdr/eventing.py:Tever.revoke`.
This is source inspection, not completed integration qualification.

## Stored status

Public `GET /v1/associations/{said}/status` requires no KERI caller signature or
signed response. Return stored acceptance/revocation/supersession state and reason,
plus the last-known initial account observation: address, chain ID, classification,
block number/hash and observation time. Unknown observations remain unknown.
Known pending/failed candidates return `200`; unknown SAIDs return `404`.
Times/block identifiers are informational; age never invalidates acceptance.
GET performs no RPC, refresh or enrollment. Its public response is not a substitute
for authenticated status intake by the oracle. PR 04 defines the minimal response
with its implementation; PR 06 adds durable delivered-revocation retirement.

## Compatibility and implementation scope

The existing [registry][registry] publishes wallet, issuer-derived identityRef and
association SAID, and withdraws by wallet plus exact SAID. Preserve its ABI,
identity adapter and wallet policy. Deployment supplies chain/RPC/checkpoint,
writer and contracts; credentials/results cannot supply executable configuration.
Contracts do not expire mappings; undiscovered/undelivered revocation can leave
one active. Old account/source observations remain sufficient by explicit policy.

The [sequence diagrams](../../docs/README.md) describe earlier workflows; this
scope revision supersedes their ongoing refresh/source-monitoring and advanced
recovery requirements. Later implementation docs must align with the reduced scope.
This increment implements no runtime. Native intake, signing, durable status and
webhooks, ordinary contract effects and two-service/Anvil qualification remain
subsequent increments. Removed original-WBS requirements are deferred, not passed.

[carrier]: https://github.com/GLEIF-IT/vlei-oracle/blob/77849caae048381aee96b42f75053368d8d24c53/protocol/external-association-v1/eoa-v1/README.md
[registry]: https://github.com/GLEIF-IT/vlei-comply/blob/6220cd78411b8b721838ee67f11293ff5504c05c/src/attestation/VLEIOracleRegistry.sol
