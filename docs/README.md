# EOA verifier workflow diagrams

These charts describe the proposed service split. Start with the overview, then open the detail relevant to the stage you are reviewing.

| Chart                                                                            | Scope                                                                      |
| -------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| [End-to-end overview](stablecoin-end-to-end-sequence.md)                         | Association, verification, endorsement and stablecoin transfer             |
| [Local setup](local-setup-sequence.md)                                           | Anvil, contract deployment, trust configuration and network alignment      |
| [Association creation](association-creation-sequence.md)                         | Four-actor ceremony producing the issued association                       |
| [Association verification](association-verification-sequence.md)                 | Joint KERI/Ethereum verification and durable webhook delivery              |
| [Oracle endorsement](oracle-endorsement-sequence.md)                             | Accepted result, fresh status, deployment policy and confirmed endorsement |
| [Revocation and status maintenance](revocation-status-sequence.md)               | Freshness queries, invalidation and exact-association withdrawal           |
| [On-chain compliance and transfer](on-chain-transfer-sequence.md)                | Contract calls for identity resolution, wallet checks and USDC movement    |
| [Exact-wallet endorsement evaluation](wallet-endorsement-evaluation-sequence.md) | Policy role checks and current wallet-to-identity endorsement matching     |
| [Transfer outcomes and failures](on-chain-transfer-outcomes-sequence.md)         | Policy rejection, pending requests and token-transfer reverts              |

Creation, verification, oracle acceptance and on-chain endorsement are distinct milestones. Each document includes its rendered SVG and editable Mermaid source. The exports retain the methodology's palette on an opaque white canvas, with participant labels at both ends of the lifelines.
