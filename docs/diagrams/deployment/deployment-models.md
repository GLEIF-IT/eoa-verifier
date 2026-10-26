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

    KW -->|"IPEX Grant + native evidence"| V
    V -->|"Initial account check"| ETH
    V -->|"KERI AID-signed status updates"| T
    T -->|"Authenticated ACK"| V
```

The KERI wallet embeds the EIP-712 proof, issues the untargeted ACDC and presents the
association with its native evidence, including the LE/QVI chain. The verifier
performs initial verification and stores acceptance. Later, verified native
revocation evidence retires the association and produces a separate status update.
Each webhook event requires an authenticated ACK after durable receipt; failed
deliveries remain pending and retry with backoff. No Ethereum transaction is needed
for the challenge signature.

## 2. EOA Verifier, vLEI Oracle and a compliance-gated USDC transfer

```mermaid
flowchart TB
    subgraph Wallets["Legal entity wallets — onboard sender and recipient"]
        KW["vLEI / KERI wallet<br/>LE AID and credential registry"]
        EW["Ethereum wallet<br/>EOA signing key"]
        KW -->|"EIP-712 challenge"| EW
        EW -->|"Wallet signature"| KW
    end

    subgraph Services["Independent off-chain services"]
        V["EOA Verifier<br/>Own identity and stores"]
        O["vLEI Oracle<br/>Own identity, stores and posting key"]
    end

    subgraph Ethereum["Ethereum blockchain — Anvil for local testing"]
        RPC["Node / RPC"]
        R["Identity and<br/>wallet-endorsement registries"]
        C["vLEI Comply contracts<br/>wUSDC + policy checks"]
        U["USDC token<br/>Sender and recipient balances"]
    end

    KW -->|"IPEX Grant + native evidence"| V
    V -->|"Initial account check"| RPC
    V -->|"Signed status updates"| O
    O -->|"Authenticated ACK"| V
    O -->|"Transactions: publish mapping<br/>or withdraw exact association"| R
    EW -->|"Sender: transfer(recipient, amount)"| C
    C -->|"Check both wallets' identities<br/>and current endorsements"| R
    C -->|"All policies pass:<br/>move USDC from sender to recipient"| U
```

Repeat association issuance and verification for both parties before transfer.
The oracle trusts authenticated verifier status and applies ownership/replacement
rules before publishing; it does not repeat verification. Verified association
revocation produces a separately acknowledged webhook and exact-SAID withdrawal.
The same durable delivery and retry behavior from the first model applies here.

The sender first approves `wUSDC` to spend its USDC. Transfer checks use stored
on-chain state, with no HTTP callback. The recipient receives underlying USDC;
the wrapper does not mint wrapped balances. Direct USDC transfers bypass this
wrapper. Local qualification uses the demo USDC contract on Anvil.

See the [transfer sequence](../sequence/on-chain-transfer-sequence.md) for the
individual contract calls and the [service contract](../../../protocol/verifier-api-v1/README.md)
for authentication and status semantics.
