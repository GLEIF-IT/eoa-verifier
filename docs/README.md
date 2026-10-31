# EOA Verifier documentation

- [External association v1](../protocol/external-association-v1/README.md): credential/schema, challenge and reference vectors.
- [Verifier API v1](../protocol/verifier-api-v1/README.md): evidence intake, acceptance/public status and shared signed delivery.
- [Operations](operations.md): install, trust introduction, persistence, delivery recovery and limitations.
- [Testing](testing.md): component/function and installed-wheel procedures.
- [Deployment](diagrams/deployment/deployment-models.md), [creation](diagrams/sequence/association-creation-sequence.md) and [verification](diagrams/sequence/association-verification-sequence.md): editable Mermaid with rendered SVG.

Oracle owns selection, posting, revocation-to-withdrawal and the single
[full-system scenario](https://github.com/GLEIF-IT/vlei-oracle/blob/main/docs/diagrams/sequence/stablecoin-end-to-end-sequence.md).
Comply owns [contract transfer/evaluation diagrams](https://github.com/GLEIF-IT/vlei-comply/tree/main/docs/diagrams/sequence).
Verifier acceptance persists until verified revocation; downstream supersession
does not retire it. There is no continuous source/account reassessment.
