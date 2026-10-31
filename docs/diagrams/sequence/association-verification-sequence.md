# Association verification and acceptance

Verifier independently checks issued evidence before acceptance. The configured consumer may be Oracle or another service.

![Association verification and acceptance](association-verification-sequence.svg)

<details>
<summary>Editable Mermaid source</summary>

```mermaid
%%{init: {"theme":"base","themeVariables":{"actorBkg":"#003336","actorTextColor":"#FFFFFF","signalColor":"#003336","signalTextColor":"#003336","noteBkgColor":"#E5DCE6","noteTextColor":"#003336","loopTextColor":"#003336","labelTextColor":"#003336","labelBoxBkgColor":"#DFFBC0","labelBoxBorderColor":"#6A7B7F","actorLineColor":"#6A7B7F","lineColor":"#6A7B7F"},"sequence":{"mirrorActors":true,"wrap":true}}}%%
sequenceDiagram
    autonumber
    participant I as Issuer
    participant V as EOA Verifier
    participant R as Configured Ethereum RPC
    participant C as Trusted webhook consumer
    I->>V: IPEX Grant + source credentials, KEL/TEL, receipts
    V->>V: Native parse/escrows, durable pending work
    V->>V: Check schemas/SAIDs, LE/QVI trust, issuer/holder and witnessed issuance
    V->>V: Reconstruct challenge, verify canonical EOA proof
    V->>R: Check chain and account code at canonical block
    R-->>V: Block/hash/code observation
    V->>V: Recheck native credential status after RPC wait
    alt Evidence or RPC unavailable
        V->>V: Retain pending work
    else Established invalidity
        V->>V: Store initial rejection
    else Initially verified
        V->>V: Store verification result
        alt Issuer/nonce owned by another accepted SAID
            V->>V: Store local NONCE_REUSED rejection, no webhook
        else Fresh pair or same accepted SAID
            V->>V: Atomically commit nonce claim, acceptance and optional outbox
            opt Webhook configured
                V->>C: Authenticated immutable acceptance event
                C->>C: Commit durable receipt
                C-->>V: Authenticated correlated ACK
                V->>V: Complete delivery, retry same event if ACK is lost
            end
        end
    end
```

</details>

[Verifier API](../../../protocol/verifier-api-v1/README.md) owns events, signatures, ACKs and stored status. An ACK is not downstream selection or endorsement. [Oracle qualification](https://github.com/GLEIF-IT/vlei-oracle/blob/main/docs/two-service-qualification.md) owns the full-system scenario.
