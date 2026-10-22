# Verification acceptance and contract compatibility

This matrix defines the claim behind API v1. It is a specification and a guide
to conformance coverage; it does not assert that the two services are already
implemented or that synthetic vectors establish native credential acceptance.
The [wire contract](README.md), [native refresh contract](native-refresh.md) and
this matrix must agree before a consumer may treat a decision as authority.

## Outcome and reason matrix

Only `valid / VALID` permits consideration for enrollment or a grant. Posting
also requires authenticated authority, use-time freshness and deployment policy.
`invalid` requires an established contradiction or deterministic profile failure.
`unavailable` means the claim cannot currently be established, not that a
credential has been revoked. Malformed HTTP and failed service authentication
are transport errors; they do not create association invalidations.

| Outcome | reasonCode | Required evidence or failure | Lifecycle effect |
| --- | --- | --- | --- |
| valid | VALID | All native, relationship, proof, network and account checks below pass. | Eligible for enrollment; a stored decision alone never authorizes posting. |
| invalid | ASSOCIATION_INVALID | Association bytes/SAID/schema contradict the selected profile; targeted association; wrong LE edge schema/operator; invalid nested SAID; registry belongs to another issuer; or a historically unwitnessed issuer. | No initial success event. An enrolled association's established invalidity enters invalidation handling. |
| invalid | SOURCE_INVALID | LE/QVI bytes or schema are invalid; issuer/holder relationships fail; QVI issuer is not configured GEDA; or accepted QVI key state shows a different delegator. | No initial success event; invalidate affected enrolled associations. |
| invalid | ASSOCIATION_REVOKED | Native accepted TEL evidence establishes association revocation. | Terminal for this association SAID, including across restart; schedule exact-association withdrawal/cancellation where applicable. |
| invalid | SOURCE_REVOKED | Native accepted TEL evidence establishes revocation of the association's LE or QVI source. | Terminal for this association SAID; fan out to every affected enrolled association. A replacement source requires a new association/proof. |
| invalid | PROOF_INVALID | Reconstructed EIP-712 proof fails the algorithm/domain, committed identifier, scalar, encoding or recovered-address requirements below. | No initial success event; never send a failed proof to account RPC as if accepted. |
| invalid | ACCOUNT_CONTRACT | Trusted configured RPC successfully reports ordinary contract code at an identified canonical block. | Invalidate existing authority. A later fresh permitted code observation can restore eligibility at a higher revision; this is not terminal credential revocation. |
| unavailable | EVIDENCE_UNAVAILABLE | Association/schema/native acceptance, KEL/TEL state, issuance anchor, historical witness state or sufficient verified receipts are missing or unresolved. | Persist pending/queryable work; no initial success event or new grant. |
| unavailable | SOURCE_UNAVAILABLE | LE/QVI source evidence, configured source contacts or the required successful native refresh responses are missing/unresolved. | Retry bounded work; block new authority, preserve confirmed endorsements unless an independent established invalidity requires withdrawal. |
| unavailable | RPC_UNAVAILABLE | RPC timeout, failure, malformed response, missing block/code, or inability to establish canonicality. | Retry; never convert provider failure or a reorged observation into account invalidity. |
| unavailable | NETWORK_MISMATCH | A canonical association names a chain outside deployment scope; provider chain ID or configured checkpoint differs. | Refuse new authority. Configuration failures also keep readiness false; reconcile a reset rather than reusing its old transaction journal. |
| unavailable | FRESHNESS_UNAVAILABLE | Required source/account observations do not meet the request-bound completion, age, clock or use-time constraints. | Block grant/replacement/granting rebroadcast. Transport failure and expiry do not independently justify withdrawal or cancellation. |

These are the complete reason codes in v1. `EVIDENCE_UNAVAILABLE` includes an
initial pending presentation; there is no separate `pending` outcome. Diagnostic
text may explain the failed check but must not change the code's semantics.
An endpoint may return `422` for a requested unsupported profile/chain without
creating an assessment. A canonical credential on another deployment chain is
not thereby a cryptographically invalid credential.

Established invalidity outranks inability to complete an additional check.
Once known, association/source revocation cannot be erased by an RPC timeout,
an older packet or a later `valid` assessment. If several failures are known,
select deterministically: association revocation, source revocation, association
invalidity, source invalidity, proof invalidity, account invalidity; otherwise
network mismatch, missing association evidence, missing source evidence, RPC
unavailability, then freshness unavailability. Missing evidence never authorizes
inventing the facts needed to identify a revoked source. Keep the evidence and
provenance for the selected reason; a changed decision core requires a new
revision. Account-code recovery does not revive a revoked credential.

## Checks that must survive extraction

The behavioral baseline is GLEIF-IT/vlei-oracle revision
`77849caae048381aee96b42f75053368d8d24c53`, particularly
`src/vlei_oracle/verification/credentials.py` and `eoa.py`. Their native evidence
checks are retained; the service split adds an authenticated boundary and a
stronger, explicit refresh claim. A database row, webhook signature or successful
JSON schema check cannot replace these native checks.

| Boundary | Required positive case | Required negative or incomplete case |
| --- | --- | --- |
| Credential serialization | Reparse exact ACDC bytes with native `SerderACDC`; requested SAID and expected schema match; schema validates the serialized credential. | Candidate/SAID mismatch and malformed/schema-invalid bytes are invalid; missing schema/credential is unavailable. |
| Native acceptance | Association, LE and QVI have native accepted `saved` records and accepted KEL/TEL evidence. | Merely having candidate/Grant/escrow bytes never proves acceptance. Such bytes may establish a contradiction but never a successful claim. |
| Association shape | Untargeted ACDC: no issuee `a.i`; `e.le.s` is LE schema and `e.le.o` is `I2I`. | Targeted association, wrong LE edge schema or operator is invalid. |
| Source chain | Association issuer equals LE holder; LE issuer equals QVI holder; QVI issuer equals configured GEDA; QVI AID's accepted delegation points to that GEDA. | Wrong holder/issuer/delegator is invalid. Unknown accepted QVI state is unavailable. OOBI discovery does not grant root trust. |
| Nested commitments | Independently verify proof, attribute and edge block SAIDs as well as enclosing ACDC SAID. | Recomputing only the outer SAID does not repair a mismatched nested SAID. |
| Registry/status | Each native registry belongs to its credential's issuer and each required credential is currently issued (`iss` or `bis`); preserve accepted revocation. | Unknown registry/TEL state is unavailable; accepted revocation is invalid. Reload native persisted state after restart rather than trusting a transient cache miss. |
| Issuance order | Persist registry SAID, sequence-zero issuance TEL digest and its accepted issuer-KEL anchor sequence/digest. | Latest revocation anchor, event arrival/revision/cursor, SAID lexical order and wall-clock time are not issuance order. Facts remain queryable after revocation. |
| Witnessed issuance | Native `verifyAnchor` validates the issuance seal; `fetchEstEvent` and `fetchWitnessState` provide historical threshold/witnesses at that anchor; verify receipt signatures and count unique verified indices. | No witnessed issuer is invalid. Missing anchor/state or insufficient valid receipts is unavailable. Duplicate indices cannot satisfy the threshold; current witness membership cannot replace historical membership. |
| EIP-712 proof | Fixed `ExternalAssociation` type and fixed domain; reconstruct issuer AID, LE SAID, canonical extId and nonce from the ACDC. Match recovered signer to the exact bound address. | Changed signed field, wrong domain/algorithm, malformed canonical identifier, noncanonical signature or wrong recovered address is invalid. Never accept a sender-supplied challenge as the reconstruction. |
| Signature encoding | Lowercase 65-byte `0x` hex; secp256k1 `1 <= r < n`, `1 <= s <= n/2`, `v` 27 or 28. | High-s, bad scalar, alternate recovery-byte form, unrecoverable signature and trailing data fail. |
| Network/account | Explicit trusted RPC, expected chain and checkpoint; empty code or exactly 23 bytes `0xef0100 || 20-byte address` at an identified canonical block. | Other code is invalid; unavailable, malformed or noncanonical observation is unavailable. A matching chain ID alone does not identify an Anvil deployment. |
| Wait boundaries | Recheck accepted native source status after account RPC; refresh all required sources with the bounded peer claim in `native-refresh.md`. | Revocation accepted during RPC prevents success. A local cache read or a recent HTTP timestamp cannot establish unchanged-valid network refresh. |

The EIP-712 nonce is 1–256 characters and bound as exact ceremony data. Issuer
reservation/consumption prevents reuse in the issuing workflow; the verifier
must not claim that a signature alone proves global nonce non-reuse. The service
envelope's random nonce is a separate anti-replay mechanism. EOA proof establishes
key control at ceremony time; neither fresh account code nor source refresh
detects sale or theft of the private key. EIP-7702 acceptance is only the existing
designation-format rule, not a review of delegated execution behavior.

## Delivery, ordering and recovery acceptance

The executable examples in `vectors.json` cover the wire boundary. Native
runtime and crash/recovery gates remain implementation requirements in PRs
02–11, not claims made by generating those examples.

| Scenario | Required result |
| --- | --- |
| Signed initial valid event | Derive wallet/identity locally; commit inbox, reduction and recovery membership before signed ACK. ACK means durable acceptance, not posting or freshness. |
| Lost ACK / restart / retry | Same immutable event with new authenticated request nonce has the same stored acceptance identity and no repeated domain effects. A replayed request nonce is rejected. |
| Same event ID, changed payload | Reject/quarantine `409`, even if only event creation observations changed. Event payload is immutable. |
| Same association revision, changed decision digest | Reject/quarantine `409`, including previously seen revisions below the current high water. Retain revision/digest history. |
| Same core, newer query observations | Same decision revision is permitted; apply observation freshness separately. Never mutate a previously committed event to carry the new observations. |
| Lower unseen revision | Record and acknowledge stale; do not replace current accepted state or revive revoked authority. |
| Webhook ahead of replay cursor | Accept/reduce idempotently but do not skip replay gaps. Replay alone advances the contiguous cursor atomically with effects. |
| Stream reset, missing history or rolled-back high water | Suspend new grants and reconcile. An empty nonterminal page or a nonconsecutive page is not successful replay. |
| Fresh refresh / unchanged-valid result | Require request-bound completion evidence after refresh start; same decision revision can be fresh. Stored assessment/facts alone cannot satisfy the grant gate. |
| Source revocation or established account invalidity via query | Reduce and persist through the same authority path as events; schedule exact invalidation. A later outage does not discard it. |
| Later candidate B while A awaits RPC/signing | Recompute eligible wallet candidate and on-chain issuance ordering before signing/submission/rebroadcast; unchanged A revision does not prove A remains selected. |
| Same issuer and strictly later verified issuance anchor | B may replace A after fresh validity and deployment checks. Same-anchor ambiguity, different issuers or missing current-on-chain facts remain unresolved. |
| Outage after confirmed endorsement | Block new authority, preserve existing endorsement. Continue receipt/nonce/reorg reconciliation and already justified invalidation/cancellation. |
| Invalidated signed original / same-nonce cancellation | Persist and reconcile both transaction identities; either can mine. Never assume cancellation success from submission alone. |
| Service key rotation / service AID replacement | Same-AID rotation resolves latest accepted establishment state and re-signs retries; old epochs fail closed. A different AID quarantines old authority and requires explicit reconciliation. |

## Diagram-to-contract mapping

The diagrams are proposed workflows, not alternate wire definitions. These
clarifications preserve their intent without editing their independent sources.
All diagram links resolve from this repository.

| Diagram | Contract example / acceptance scenario | Intentional clarification |
| --- | --- | --- |
| [Association creation](../../docs/association-creation-sequence.md) | Canonically owned EIP-712 association/challenge/proof vectors and derived wallet/identity binding. | Ceremony issuance precedes native verification; it is neither an API success event nor an endorsement. Synthetic vector credentials are encoding fixtures only. |
| [Association verification](../../docs/association-verification-sequence.md) | Valid assessment/event and signed ACK; invalid/unavailable reasons above. | Native escrow/proof checks stay verifier-owned. Retry preserves event payload/ID but uses a new signed transport nonce. Initial rejected/pending presentations have no success event. |
| [Oracle endorsement](../../docs/oracle-endorsement-sequence.md) | Event ACK, refresh POST `202`, pending poll `202`, completed assessment `200`, facts lookup. | The chart's status query means request-bound refresh before use, not a stored GET. Immutable facts provide replacement order without granting authority. |
| [Revocation/status](../../docs/revocation-status-sequence.md) | Invalid lifecycle event, refreshed invalid decision, replay, immutable facts after revocation. | Account invalidity can recover; credential revocation cannot. Unavailable does not itself withdraw. Native source-change fan-out and durable transaction cancellation/reconciliation are required behind the arrows. |
| [Local setup](../../docs/local-setup-sequence.md) | Explicit service authority/profile/chain configuration and provider checkpoint checks. | One chain per deployment; peer URLs and RPCs are configuration. Both applications verify their own provider and share intended checkpoint; chain ID alone is insufficient. |
| [End-to-end overview](../../docs/stablecoin-end-to-end-sequence.md) | Independent sender/recipient valid evidence, authenticated events, fresh grant decisions and confirmed exact-wallet endorsements. | Installed two-service HTTP qualification with Anvil comes later. A webhook/ACK or successful transaction receipt alone does not prove the final transfer. |
| [On-chain transfer](../../docs/on-chain-transfer-sequence.md) | ABI mapping below: identity enrichment, both exact-wallet endorsements, underlying allowance and transfer. | Contracts consume stored endorsements; they make no verifier HTTP call. Direct underlying-token transfers bypass this wrapper policy. |
| [Exact-wallet evaluation](../../docs/wallet-endorsement-evaluation-sequence.md) | `isEndorsed(wallet, identityRef)` checks each customer; required originator and beneficiary roles. | Another wallet of the same entity is insufficient. This policy never returns Pending and does not check source freshness or ceremony SAID at transfer time. |
| [Transfer outcomes](../../docs/on-chain-transfer-outcomes-sequence.md) | Fail/Pending false result, Pass transfer event/balances, underlying revert. | Fail overrides Pending, Pending overrides Pass. False can accompany a successful receipt and no transfer. An underlying revert rolls back this transaction, not a prior approval. |

## Unchanged Solidity ABI analysis

Analyzed GLEIF-IT/vlei-comply commit
`6220cd78411b8b721838ee67f11293ff5504c05c`. The split changes who produces the
off-chain decision and how the oracle obtains it. It does not change the values
the oracle must encode into current contract calls. No Solidity interface change
is expected for WBS 2.4.

| Existing source and ABI | Mapping from authenticated assessment / oracle configuration |
| --- | --- |
| `VLEIOracleRegistry.publishEndorsement(address,bytes32,string)` | Address parsed from verified canonical `facts.extId`; `keccak256(UTF-8(facts.issuerAid))`; `associationSaid`. Chain/registry address and Ethereum writer come only from local configuration. |
| `VLEIOracleRegistry.withdrawEndorsement(address,string) returns (bool)` | Exact wallet and invalidated association SAID. Contract compares current SAID before deleting, so a delayed withdrawal of A cannot clear replacement B. `false` is a possible successful transaction outcome. |
| `VLEIOracleRegistry.getEndorsement(address) returns ((bytes32,string))` | Read current identity/SAID for convergence and replacement. If the oracle lacks that SAID's verified issuance facts, it must retrieve them or remain unresolved. |
| `IVLEIOracleRegistry.isEndorsed(address,bytes32) returns (bool)` | Exact current wallet binding; no association input, expiry, credential parsing or HTTP call. |
| `IdentityRegistry.registerIdentity(bytes32,address,bytes)`, `removeIdentity(bytes32,address,bytes)`, `getIdentity(address)` | AID hash is the CCID; wallet is the account; existing configured context remains oracle-owned. Identity mapping is enrichment, not endorsement. Reconcile mapping and endorsement as separate transactions. |
| `ChainlinkCCIDIdentityAdapter.identityRef(address)` / `getBeneficiaryId(address)` | Read the same wallet-to-CCID mapping. `identityRefById(bytes32)` passes through an existing reference; it cannot satisfy the exact-wallet policy for a zero-wallet party. |
| `VLEIEndorsementChecker.validate(PartyPacket)` / `checkEndorsement(PartyPacket)` | Reject zero wallet/identity and ask the configured registry for exact-wallet endorsement. Other entity wallets do not qualify. |
| `VLEIWalletAssociationPolicy.evaluate(TransactionEnvelope)` | Every originator/beneficiary customer must validate and both roles must exist. The policy ignores other party roles; it is not an OOR/ECR, VASP or sanctions policy. |
| `wUSDC.transfer(address,uint256) returns (bool)` | Existing sender/recipient wallet flow, policy enrichment, underlying token allowance and balance checks. New verifier wire fields are not Solidity arguments. |

`publishEndorsement` is writer-role guarded and rejects zero wallet, zero
identityRef and empty SAID. It can overwrite the current wallet binding without
checking issuance order; therefore the oracle must enforce replacement rules.
The role is `AdminControls.COMPLIANCE_ADMIN_ROLE`, not the KERI service AID.
Service authentication does not distribute the Ethereum key or grant that role.
The adapter's optional compatibility enrichment fields do not add authority to
this wallet-association policy.

The pinned `abi/endorsement-vector.json` has publication selector `0x9521f4c4`.
Its wallet, identityRef and associationSaid remain the three inputs after the
split. `test/VLEIOracleRegistryTest.t.sol::testPublicationEncodingVector` compares
the complete calldata; its other tests cover role loss, input validation,
replacement and exact withdrawal. `test/VLEIOracleComplianceTest.t.sol` covers
both wallet roles, missing/mismatched mappings, withdrawal, replacement surviving
late withdrawal, another entity wallet's insufficiency and elapsed time. These
are source references for the compatibility conclusion, not claims of new test
execution in this document.

The oracle's vendored posting ABI provenance names older comply revision
`007f145867749780a4b6296d36fa2c8a665e0e44`. The registry ABI and relevant identity
interfaces/adapter are unchanged between that revision and `6220cd7`; the final
installed-system qualification must still record actual artifact/ABI hashes and
pins. PR 09 must preserve calldata and transaction recovery through the consumer
cutover; PR 11 must prove unchanged contracts with both installed services and
real local Anvil. This PR's analysis begins WBS 2.4; it does not close it.

There is no on-chain expiry or automatic stale-authority bound. Evidence outages
can leave an endorsement active, and unseen revocation can race mining. A
confirmed invalidation removes future gated authority only after withdrawal
confirms; it cannot undo prior transfers. Production audit, contract redesign
and live-store migration are outside this prototype's delivery claim.
