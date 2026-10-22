# Verified wallet associations and stablecoin transfers

Proposed local end-to-end workflow. Both parties first establish an EOA association. `eoa-verifier` owns cryptographic verification and current-status queries; `vlei-oracle` authenticates results and manages on-chain endorsements. Forge deploys the demo; Anvil runs its Ethereum chain.

[Open the rendered chart](stablecoin-end-to-end-sequence.svg). The detailed ceremony is in [EOA association creation and verification](association-verification-sequence.md).

```mermaid
%%{init: {"theme":"base","fontFamily":"Arial, sans-serif","themeCSS":"text { font-family: Arial, sans-serif !important; }","themeVariables":{"fontFamily":"Arial, sans-serif","primaryColor":"#003336","primaryTextColor":"#FFFFFF","primaryBorderColor":"#003336","lineColor":"#6A7B7F","actorBkg":"#003336","actorBorder":"#003336","actorTextColor":"#FFFFFF","actorLineColor":"#6A7B7F","signalColor":"#003336","signalTextColor":"#003336","labelBoxBkgColor":"#DFFBC0","labelBoxBorderColor":"#6A7B7F","labelTextColor":"#003336","loopTextColor":"#003336","noteBkgColor":"#E5DCE6","noteBorderColor":"#6A7B7F","noteTextColor":"#003336","sequenceNumberColor":"#FFFFFF"},"sequence":{"mirrorActors":false,"actorMargin":32,"width":165,"height":55,"messageMargin":25,"noteMargin":12,"diagramMarginX":20,"diagramMarginY":20,"wrap":false,"actorFontFamily":"Arial","messageFontFamily":"Arial","noteFontFamily":"Arial"}}}%%
sequenceDiagram
    autonumber
    participant Setup as Local setup<br/>Forge scripts
    participant A as Sender<br/>Ethereum + vLEI wallets
    participant B as Recipient<br/>Ethereum + vLEI wallets
    participant V as eoa-verifier
    participant O as vlei-oracle
    participant C as vlei-comply contracts<br/>Running on Anvil

    rect rgb(246, 243, 247)
        Note over Setup,C: 1. Prepare one local chain and two associated wallets
        Setup->>C: Deploy registries, policy and demo tokens<br/>Grant oracle writer role, fund test accounts
        Setup->>V: Configure trusted GLEIF root and Anvil RPC/chain ID
        Setup->>O: Configure verifier AID allowlist, same chain<br/>Registry addresses and dedicated posting key
        Note over V,C: Association chain = verifier RPC chain = oracle deployment chain<br/>Different RPC URLs are allowed only for the same intended network
        A->>V: Present newly created sender association + evidence
        B->>V: Present newly created recipient association + evidence
        Note over A,V: Each party completes the two-wallet ceremony in the detailed chart
    end

    rect rgb(223, 251, 192)
        Note over V,C: 2. Verify both parties and establish endorsements
        loop For each party's association
            V->>V: Verify KERI/vLEI chain and EIP-712 proof<br/>Check EOA account state via Anvil RPC
            V->>O: Signed verified-event webhook<br/>Stable ID, revision and chain-bound association
            Note over V,O: Authenticate allowed verifier, deduplicate and persist<br/>Retry until durable acknowledgement
            O->>V: Query fresh credential + account assessment<br/>before authority-granting effects
            V-->>O: Valid / invalid / unavailable<br/>Revision and observation block/time
            opt Valid, fresh and eligible under replacement policy
                O->>C: Register identity hint, then publish<br/>exact-wallet / exact-association endorsement
                C-->>O: Transaction receipts, reconcile confirmations
            end
        end
    end

    rect rgb(246, 243, 247)
        Note over A,C: 3. Execute the local stablecoin demonstration
        A->>C: Approve underlying test USDC allowance for wUSDC
        A->>C: Call wUSDC.transfer(recipient, amount)
        C->>C: Resolve party identities and evaluate policy<br/>Check both exact-wallet endorsements
        alt Both endorsed and token checks pass
            C->>C: USDC.transferFrom(sender, recipient, amount)
            C-->>A: Receipt and token Transfer event
            Note over B,C: Recipient's underlying USDC balance is credited
        else Policy fails or is pending
            C-->>A: Wrapper returns false, no token movement
        end
        Note over O,C: Contracts consume oracle endorsements<br/>They make no HTTP calls and do not verify KERI or EIP-712 proofs
    end

    rect rgb(246, 243, 247)
        Note over A,C: 4. Maintain authority after issuance
        opt Either party's association or source credential is revoked
            Note over V: Reassess on accepted TEL evidence
            V->>O: Signed invalidation webhook<br/>New revision, exact association SAID
            O->>C: Withdraw that exact association<br/>Preserve any newer replacement
            C-->>O: Confirmed withdrawal, later gated transfers fail<br/>unless a valid replacement is endorsed
        end
    end
```

The transfer path is the local **policy-controlled stablecoin wrapper** (`wUSDC`), with test balances prepared in setup; a direct transfer of the underlying mock USDC does not enforce this policy. Check the underlying `Transfer` event and balances: a successful receipt alone does not prove a transfer, because a policy failure can return `false`. Anvil executes the transactions. Forge is deployment/test tooling, not a participant in each transfer.

Freshness checks gate new authority and recovery/rebroadcast. Unavailable evidence blocks new authority but, under the current plan, leaves existing endorsements in place. Revocation has propagation and transaction-confirmation latency; transfers already confirmed are not undone. The contracts do not provide an automatic expiry bound. The oracle retains durable transaction, nonce, cancellation and reorg recovery behind the simplified arrows.

Sources: [EOA profile](/Users/kbull/gleif/projects/vlei-external-association/initial-docs-from-kevin/eoa-profile.docx), [methodology and original color theme](/Users/kbull/gleif/projects/vlei-external-association/initial-docs-from-kevin/methodology.docx), [wallet association policy](../../gl1/vlei-comply/src/policies/VLEIWalletAssociationPolicy.sol), [oracle registry](../../gl1/vlei-comply/src/attestation/VLEIOracleRegistry.sol), and [wrapped token](../../gl1/vlei-comply/src/wrappers/wUSDC.sol). Contract behavior is grounded in local `vlei-comply` commit `6220cd7`; the separate verifier and webhook/query boundary are planned.
