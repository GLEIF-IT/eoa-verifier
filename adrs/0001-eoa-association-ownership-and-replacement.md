# ADR 0001: EOA association ownership and replacement

Status: Accepted design; implementation pending
Date: 2026-10-22

## Context

An Ethereum address on the configured chain needs one selected LE claim.
LE identity is the holder AID in the verified LE ACDC, which must equal the
association issuer. An LEI or LE credential SAID is not that identity.

## Decision

Every candidate must pass initial native KERI/ACDC and LE/QVI relationship
checks, verified issuance anchoring, EIP-712 wallet signature verification and
the configured-chain account check. Accepted associations remain valid indefinitely
until their association ACDC is revoked or they are superseded. Age and outages
do not invalidate them. No refreshes or continuing source/account checks.

1. **Same LE: later issuance wins.** For the same chain/address and holder AID,
   a fully verified association supersedes the earlier one only at a strictly
   higher verified issuance-anchor sequence in that AID's KEL. Do not use a
   revocation anchor, arrival order, assessment revision or timestamps.
2. **Different LE: revoke before transfer.** Reject another LE's competing
   claim until verified revocation of the current association ACDC releases it.
   Revoking an older, replaced association does not release its successor.
   Missing evidence and outages are not revocation. Never compare sequence
   numbers across different issuers' KELs.

## Consequences

Persist acceptance, retirement and selected-claim history across restart. A
superseded association does not become current again when its successor is revoked.
The oracle uses authenticated stored status and checks durable selection/revocation
before acting. Publish the accepted selected association; withdraw a revoked
association by exact SAID. Use ordinary contract submission/result handling;
submission is not confirmation. No new transaction-recovery framework is required.

## Examples

- X at sequence 10, then Y at 12 for the same LE/address: Y wins regardless of
  delivery order. Revoking X does not remove Y.
- Another LE at sequence 900 cannot replace Y until Y's verified revocation.
  Revoking Y releases its claim; it does not restore X.

## Appendix: possible future same-event policy — not implemented

Multiple distinct EOA association ACDCs anchored in one issuer KEL event are
outside ordinary usage and this build. A possible future policy is to reject all
involved associations, including withdrawing earlier application acceptance when
a conflict is discovered later. That would be application-policy rejection, not
signature invalidity; duplicate delivery of one SAID would not be a conflict.
Revisit only if needed. No detection, conflict state, invalidation path, special
tests, tie-breaker or proof-of-absence machinery is required for this case now.
