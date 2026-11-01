# ADR 0001: Verification, acceptance and downstream selection

Status: Accepted; Oracle selection implemented in its own application
Date: 2026-10-22; ownership clarified 2026-10-31

Initial KERI/ACDC, LE/QVI relationship, witnessed issuance, wallet-proof and
configured-chain account checks establish verification. Application acceptance
is a separate local decision and consumes the nonce. Accepted
associations do not expire with age or outages. Verified revocation of that
association revokes it; there is no continuous account/source-chain reassessment.

Oracle's ownership selection and contract publication are downstream decisions.
Selecting a later issuance can supersede a mapping while both associations remain
accepted in Verifier. Oracle supersession does not revoke verifier acceptance.

Selection/replacement rationale belongs to [Oracle ADR 0001](https://github.com/GLEIF-IT/vlei-oracle/blob/main/adrs/0001-wallet-association-selection.md);
its normative rules belong to Oracle's protocol. Verifier's
[service API](../protocol/verifier-api-v1/README.md) owns acceptance/revocation and
[ADR 0005](0005-accepted-association-nonces.md) explains local nonce durability.
