# ADR 0001: EOA association ownership and replacement

Status: Accepted design; implementation pending
Date: 2026-10-22

## Context

The verifier and oracle need deterministic application rules for competing EOA
associations. Transport order and assessment revisions do not establish ownership.
An address claim is scoped to the configured Ethereum chain. LE identity here is
the holder AID in the verified LE ACDC, which must equal the association issuer;
an LE credential SAID or matching LEI is not a substitute for that AID.

## Decision

Every candidate must satisfy the existing verification requirements: EIP-712
wallet signature, native ACDC and source-chain verification through the LE ACDC,
issuer/holder relationship, verified issuance anchoring, and account checks.
These rules do not relax freshness or verification requirements.

1. **Same LE: later issuance wins.** For the same chain/address and LE holder
   AID, a fully verified association supersedes an earlier one only when its
   verified issuance anchor has a strictly higher sequence number in that AID's
   KEL. Use the anchor of TEL issuance, not a later revocation anchor. Delivery
   order, assessment revision and wall-clock time cannot order replacement.
2. **Different LE: revoke before transfer.** Reject a competing claim from a
   different LE while the existing LE's claim is active. Only verified revocation
   releasing the current claim permits transfer; revocation of an older,
   already-replaced association does not release it. Missing evidence, outages
   and application-policy rejection are not revocation. Never compare sequence
   numbers across issuers' KELs. Preserve the existing verified source-revocation
   invalidation path and exact-association withdrawal/transaction recovery.
3. **One issuance event, multiple associations: reject all.** Distinct EOA
   association ACDCs whose verified issuance anchors identify the same issuer
   KEL event are all ineligible for application acceptance and replacement,
   even if they name different addresses. Repeated delivery of one SAID is not
   a conflict. Do not use arrival order, SAID sorting, timestamps or another
   tie-breaker. This is application-policy rejection, not a claim that the
   underlying signatures or native credential evidence are invalid.

If a second association reveals rule 3's conflict after the first was accepted,
mark every known involved association application-invalid using the existing
assessment/invalidation path. Persist and deliver the changed assessment for any
previously accepted association; the oracle must exclude it from selection and
reconcile pending or confirmed effects through existing cancellation, exact-SAID
withdrawal and recovery paths. Do not leave the first accepted because it arrived
first.
Detection uses verified issuer/issuance-event identity and distinct association
SAIDs. No proof that no undiscovered association exists is required, and no
conflict-resolution framework is introduced.

## Consequences

The verifier owns verified issuance facts and rule 3 assessment invalidation;
the oracle uses authenticated facts to enforce claim ownership and replacement.
Retain facts and discovered conflicts across restart. Reuse existing persistence,
status, outbox/acknowledgement and recovery paths. Native acceptance can remain
true while application acceptance is false. New authority still requires fresh
checks; invalidation delivery does not instantly reverse a mined transaction.

## Examples

- LE A issues X at KEL sequence 10 and Y for the same address at 12: fully
  verified Y replaces X, regardless of delivery order. Revoking X leaves Y intact.
- LE B's candidate cannot replace active Y, even at sequence 900. After verified
  revocation releases Y's claim, B may qualify under all normal checks.
- X and Z have distinct SAIDs anchored in A's event 10: reject both, including
  invalidating X if it was previously accepted. A third association in that
  event is rejected too. Delivering X twice alone does not trigger this rule.
