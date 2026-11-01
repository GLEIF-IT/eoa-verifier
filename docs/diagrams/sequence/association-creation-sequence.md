# EOA association creation

The issuer controls its entity AID and holds the referenced LE vLEI. Issuance and Verifier acceptance are separate operations.

![EOA association creation](association-creation-sequence.svg)

<details>
<summary>Editable Mermaid source</summary>

```mermaid
%%{init: {"theme":"base","themeVariables":{"actorBkg":"#003336","actorTextColor":"#FFFFFF","signalColor":"#003336","signalTextColor":"#003336","noteBkgColor":"#E5DCE6","noteTextColor":"#003336","loopTextColor":"#003336","labelTextColor":"#003336","labelBoxBkgColor":"#DFFBC0","labelBoxBorderColor":"#6A7B7F","actorLineColor":"#6A7B7F","lineColor":"#6A7B7F"},"sequence":{"mirrorActors":true,"wrap":true}}}%%
sequenceDiagram
    autonumber
    participant U as Entity operator
    participant I as Issuer KERI wallet
    participant W as Ethereum wallet
    participant E as Witnesses / evidence
    U->>I: Associate wallet and chain with this entity
    I->>I: Select nonce, build canonical EIP-712 challenge
    I->>W: Sign issuer AID, LE credential SAID, extId, nonce
    W->>U: Display challenge for approval
    U->>W: Approve
    W-->>I: EOA signature (no transaction / gas)
    I->>I: Embed proof and LE edge, compute nested and credential SAIDs
    I->>I: Issue untargeted association, anchor TEL issuance in KEL
    I->>E: Publish KEL/TEL and obtain witness receipts
    Note over I,E: Issued evidence is ready for independent verification
```

</details>

The [EOA profile](../../../protocol/external-association-v1/eoa-v1/README.md) owns the signed fields. No issuer nonce ledger is part of this service model. Verifier consumes the exact issuer/nonce on application acceptance. Continue with [verification](association-verification-sequence.md).
