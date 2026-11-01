# Deployment models

Deployment models for the completed buildout. Boxes group wallet applications,
independent services and on-chain contracts; arrows show their interactions.

## 1. EOA Verifier with a third-party webhook

```mermaid
flowchart TB
    subgraph Entity["Legal entity"]
        KW["vLEI / KERI wallet<br/>LE AID and credential registry"]
        EW["Ethereum wallet<br/>EOA signing key"]
        KW -->|"EIP-712 challenge"| EW
        EW -->|"Wallet signature"| KW
    end

    V["EOA Verifier service<br/>Own identity and durable stores"]
    T["Third-party service<br/>Configured webhook destination"]
    ETH["Ethereum node / RPC"]

    KW -->|"IPEX Grant + KERI evidence"| V
    V -->|"Initial account check"| ETH
    V -->|"KERI AID-signed status updates"| T
    T -->|"Authenticated ACK"| V
```

The KERI wallet embeds the EIP-712 proof, issues the untargeted ACDC and presents the
association with its KERI evidence, including the LE/QVI chain. The verifier
performs initial verification and stores acceptance. Later, verified KERIpy
revocation evidence revokes the association and produces a separate status update.
Each webhook event completes on HTTP success after checking any supplied signature; failed
deliveries remain pending and retry with backoff. No Ethereum transaction is needed
for the challenge signature.

Oracle owns the [full-system scenario](https://github.com/GLEIF-IT/vlei-oracle/blob/main/docs/diagrams/sequence/stablecoin-end-to-end-sequence.md) and maintained qualification.
