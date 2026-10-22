# EOA verifier service boundary

This is the initial design for two independently deployable applications.
The [result schema](schema.json) and [examples](examples.json) describe an
assessment's basic data. They are not a complete wire protocol, evidence of
native credential verification, or an authorization to post transactions.
Signing, refresh and delivery details will be specified with their production
implementations and tests before split-service posting is enabled.

## Responsibilities

| Component | Owns |
| --- | --- |
| eoa-verifier | CESR/IPEX presentation intake, native KERI/ACDC verification and stores, Ethereum wallet-proof/account checks, continuing source/status assessment and authenticated result delivery. |
| vlei-oracle | Trust in the configured verifier, durable result acceptance, deployment policy, fresh checks before granting authority, replacement selection, Ethereum signing and transaction recovery. |
| vlei-comply | Existing registry, identity adapter and wallet-association policy used by the token-transfer workflow. |

The services have separate identities, configuration and writable stores.
The oracle still needs native KERI key-state support to authenticate its peer;
it must not become another association-credential verifier. The verifier has
no Ethereum posting key. Neither application imports the other at runtime.

## What an assessment means

| Outcome | Meaning | Oracle consequence |
| --- | --- | --- |
| `valid` | Required native credential, relationship, wallet-proof, network and account checks succeeded. | Eligible for consideration under deployment policy; the stored result alone does not authorize a new grant. |
| `invalid` | Evidence establishes a contradiction, revocation or disallowed account code. | Reject initial enrollment; for an already managed association, reconcile the exact invalidated association. |
| `unavailable` | Evidence, trusted state, network access or a required fresh check cannot be established. | Block new grants and granting rebroadcast; absence of evidence alone does not withdraw a confirmed endorsement. |

Preserve the existing verifier's checks: exact ACDC/schema and nested SAIDs,
native accepted association and LE/QVI source chain, issuer/holder relationships,
configured GEDA trust and QVI delegation, untargeted association and I2I edge,
registry ownership/status, and historical witnessed issuance with verified
receipts. Candidate bytes and escrow presence are not native acceptance.

Reconstruct the EIP-712 challenge from the association and verify the canonical
proof against its bound wallet. Keep the existing empty-code/EIP-7702 designation
rule at an identified canonical block; it does not assess delegated code safety.
Recheck native status after an account RPC wait before accepting success.
Wallet control is proved at the ceremony; it is not proof against later key theft.

The existing [EIP-712 profile and vectors][carrier] remain canonical. This
increment references them rather than creating a second signature/vector suite.

## Result shape and identities

The schema fixes only the initial assessment shape. It deliberately omits
transport signatures, delivery IDs, issuance evidence and refresh observations;
those belong to the corresponding implementation boundaries. Consumers must
not treat schema validation or an `outcome` string as cryptographic verification.

- `associationSaid` identifies the association; there is no second ceremony UUID.
- `revision` orders changed decisions within one configured verifier AID and
  association. It is not issuance order or proof of freshness. An unchanged
  decision can receive new observations without becoming a new decision.
- `binding` contains the verified issuer, LE/QVI source identities and canonical
  `extId`. It is required for `valid`; incomplete assessments may omit it.
- The oracle derives the wallet from `eip155:<chainId>:<lowercase-address>` and
  `identityRef = keccak256(UTF-8(issuerAid))`. LEI and LE credential SAID are not
  substitutes for that identity reference.
- `reasonCode` explains the outcome. `VALID`, `ASSOCIATION_REVOKED` and
  `EVIDENCE_UNAVAILABLE` illustrate the examples; this is not the final reason
  taxonomy. Native validation, ordering and reason/outcome consistency remain
  implementation checks beyond this structural schema.

The examples use synthetic identifiers, not accepted credentials. They show
initial success, a later revocation, and a separate incomplete presentation.
A known revoked association must not be downgraded to merely unavailable.

## Workflows

1. **Initial verification:** receive the association and its native evidence;
   check the source chain, wallet proof and account; persist the assessment.
   A successful assessment enrolls continuing management and atomically records
   an event for delivery to the configured webhook destination. The outbox
   identifies the immutable event, its destination and delivery progress; it
   does not encode oracle business logic. A worker sends the HTTP request after
   commit and retries until authenticated acknowledgement. Incomplete or rejected
   presentations remain queryable without a success notification.
2. **Acceptance and endorsement:** authenticate the result, persist acceptance
   and recovery work, then acknowledge. Retrying the same committed event must
   not repeat effects. The oracle obtains fresh status and applies deployment
   policy before signing/submitting a grant; an ACK is not an endorsement.
3. **Revocation and status updates:** continue checking enrolled associations
   and their LE/QVI sources. Native accepted association/source revocation
   remains terminal for that association. Account-profile invalidity may recover
   after a new valid assessment and the normal grant checks. Source revocation
   reaches every affected managed association. Queries and events must agree.
4. **Replacement and recovery:** compare verified issuance facts, not event
   arrival, wall-clock time or revision. Different-issuer/same-anchor ambiguity
   remains unresolved. Withdraw by exact association SAID so a late revocation
   cannot remove its replacement. Preserve signed attempts, nonce reconciliation,
   cancellation and reorg recovery across outages and independent restarts.

See the [verification](../../docs/diagrams/sequence/association-verification-sequence.md),
[endorsement](../../docs/diagrams/sequence/oracle-endorsement-sequence.md) and
[status](../../docs/diagrams/sequence/revocation-status-sequence.md) diagrams. The diagrams describe
workflows; they do not freeze HTTP endpoints or signing encodings.

## Trust and freshness requirements

The webhook receiver is assumed capable of verifying requests signed by the
EOA Verifier's KERI AID. Use the KERI ecosystem's HTTP-signature approach, as in
Sally's webhook sender: `Signature-Input` and `Signature` headers generated with
the verifier's habitat signing keys. Sign each delivery attempt, retaining the
same event on retry. Use an authenticated body digest as part of the signed
request to bind the delivered payload. Exact covered fields and encoding are
settled with the authentication implementation, not a custom JSON envelope here.
`vlei-oracle` is the initial receiver; the outbox targets the configured webhook,
not a particular application type. One configured destination is sufficient.

Authenticate delivery, queries, replies and acknowledgements using configured
service AIDs and native accepted key state. Bind the body, intended peer/action
and request/response relationship; enforce expiry/replay policy across restart
and supported same-AID rotation. Discovery is not authorization. A different
service AID requires an explicit deployment trust change. The initial signing
scope is single-key transferable service AIDs with threshold one; this does not
restrict credential issuers' native verification support.

Each deployment pins the chain, trusted RPC and network checkpoint. URLs and
writer/contract configuration do not come from an association or result.
A fresh status check must observe relevant source and account state within
explicit bounds at use time. A cached decision, new timestamp, queued query or
transport ACK alone cannot establish refresh completion. The native peer path,
contact policy and unchanged-valid completion evidence must be demonstrated
before defining the refresh response. No all-witness replay policy is chosen
here, and no result claims global latest state or proof of non-revocation.

Missing fresh evidence blocks new authority, including granting rebroadcast,
while receipt/nonce/reorg reconciliation and already justified invalidation
continue. Recheck the association and wallet's selected replacement after waits
before granting authority. Preserve known revocation despite subsequent outages
or older messages. Native acceptance and application commits occupy separate
stores; recovery must bridge them without claiming distributed atomicity.

## Contract compatibility and next decisions

The current [registry][registry] accepts wallet, issuer-derived identityRef and
association SAID for publication, and wallet plus exact SAID for withdrawal.
The split is expected to preserve these values and the existing identity adapter,
wallet policy and wrapper ABI. It requires no Solidity interface change.
Contracts do not query the verifier or expire endorsements automatically;
outages can leave endorsements active and unseen revocation can race mining.

The next runtime increment extracts existing verification with native evidence
and restart tests. The authentication increment settles signing bytes and
interoperability vectors and probes real native refresh. Subsequent outbox/inbox,
reassessment and delivery increments settle event/ACK, refresh and replay
contracts alongside the behavior they expose. There is no conformance simulator
or substitute for two-service/native/Anvil qualification in this increment.

[carrier]: https://github.com/GLEIF-IT/vlei-oracle/blob/77849caae048381aee96b42f75053368d8d24c53/protocol/external-association-v1/eoa-v1/README.md
[registry]: https://github.com/GLEIF-IT/vlei-comply/blob/6220cd78411b8b721838ee67f11293ff5504c05c/src/attestation/VLEIOracleRegistry.sol
