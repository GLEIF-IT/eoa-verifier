# Revocation and continuing status

Proposed lifecycle after initial verification. Freshness checks gate new authority; accepted credential revocation triggers withdrawal of the affected association. These are separate paths, with different effects during an outage.

[Open the rendered chart](revocation-status-sequence.svg) · [Workflow guide](README.md)

![Revocation and continuing status](revocation-status-sequence.svg)

<details>
<summary>Editable Mermaid source</summary>

Render exports on an opaque white canvas to preserve this palette in light and dark viewers. Keep bottom participant labels enabled so lifelines span the full sequence.

```text
%%{init: {"theme":"base","fontFamily":"Arial, sans-serif","themeCSS":"text { font-family: Arial, sans-serif !important; }","themeVariables":{"fontFamily":"Arial, sans-serif","primaryColor":"#003336","primaryTextColor":"#FFFFFF","primaryBorderColor":"#003336","lineColor":"#6A7B7F","actorBkg":"#003336","actorBorder":"#003336","actorTextColor":"#FFFFFF","actorLineColor":"#6A7B7F","signalColor":"#003336","signalTextColor":"#003336","labelBoxBkgColor":"#DFFBC0","labelBoxBorderColor":"#6A7B7F","labelTextColor":"#003336","loopTextColor":"#003336","noteBkgColor":"#E5DCE6","noteBorderColor":"#6A7B7F","noteTextColor":"#003336","sequenceNumberColor":"#FFFFFF"},"sequence":{"mirrorActors":true,"actorMargin":32,"width":165,"height":55,"messageMargin":25,"noteMargin":12,"diagramMarginX":20,"diagramMarginY":20,"wrap":false,"actorFontFamily":"Arial","messageFontFamily":"Arial","noteFontFamily":"Arial"}}}%%
sequenceDiagram
    autonumber
    participant K as KERI evidence<br/>Association and source TELs
    participant V as eoa-verifier
    participant O as vlei-oracle
    participant C as vlei-comply contracts<br/>Configured chain

    rect rgb(246, 243, 247)
        Note over V,C: 1. Check freshness before authority-granting actions
        O->>V: Query current assessment for the association
        V->>V: Refresh credential / source status<br/>Check chain and account code through configured RPC
        V-->>O: Valid / invalid / unavailable<br/>Revision and observation block/time
        Note over O,C: Fresh, valid, eligible: allow grants<br/>Unavailable: block new grants<br/>Existing endorsements remain
    end
    rect rgb(246, 243, 247)
        Note over K,C: 2. Propagate an accepted credential revocation
        K-->>V: Revocation evidence for association or source credential
        V->>V: Validate TEL evidence and reassess affected bindings<br/>Atomically persist invalid revision and outbox event
        V->>O: Signed invalidation webhook<br/>Stable event ID, newer revision, exact association SAID
        O->>O: Authenticate allowed verifier and deployment scope<br/>Deduplicate and durably accept revision
        O-->>V: Durable acknowledgement
        Note over V,O: Retry until acknowledged<br/>Older revisions cannot restore withdrawn authority
    end
    rect rgb(223, 251, 192)
        Note over O,C: 3. Remove the affected on-chain authority
        O->>C: Withdraw the exact association's endorsement<br/>Preserve any newer replacement
        C-->>O: Transaction receipt
        O->>O: Reconcile canonical confirmation<br/>Persist withdrawal state
        Note over O,C: Later gated transfers fail without a valid replacement<br/>Already confirmed transfers are not undone
    end
```

</details>

Credential freshness covers the association and its source chain. Ethereum account freshness checks the configured network and account-code rule; it does not prove that a private key has not been sold or stolen. A query that establishes invalidity enters invalidation handling for existing authority; `unavailable` alone is not proof of revocation.

Under the current plan, unavailable evidence leaves existing endorsements in place. Revocation has evidence-discovery, delivery and transaction-confirmation latency, and the contracts provide no automatic expiry bound. Reassessment cadence and freshness limits still need deployment policy; this chart does not promise continuous observation.

See [oracle endorsement](oracle-endorsement-sequence.md) for the granting path and the [end-to-end flow](stablecoin-end-to-end-sequence.md) for transfers.

Sources: [EOA profile](/Users/kbull/gleif/projects/vlei-external-association/initial-docs-from-kevin/eoa-profile.docx), [methodology and original color theme](/Users/kbull/gleif/projects/vlei-external-association/initial-docs-from-kevin/methodology.docx), [wallet association policy](../../gl1/vlei-comply/src/policies/VLEIWalletAssociationPolicy.sol), [oracle registry](../../gl1/vlei-comply/src/attestation/VLEIOracleRegistry.sol), and [wrapped token](../../gl1/vlei-comply/src/wrappers/wUSDC.sol). Contract behavior is grounded in local `vlei-comply` commit `6220cd7`; the separate verifier and webhook/query boundary are planned.
