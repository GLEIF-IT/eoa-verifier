# EOA Verifier documentation

- [Partner integration quickstart](integration-quickstart.md): wallet signing, issuance/revocation flow, webhook handling, status lookup and a minimal service start.
- [KERI integration guide](keri-integration.md): credential/evidence preparation, IPEX framing, trust introduction, registered HTTP routes and recovery.
- [External association v1](../protocol/external-association-v1/README.md): credential/schema, challenge and reference vectors.
- [Verifier API v1](../protocol/verifier-api-v1/README.md): evidence intake, acceptance/public status and shared signed delivery.
- [Operations](operations.md): install, trust introduction, persistence, delivery recovery and limitations.
- [Application/persistence separation](plans/application-persistence-separation.md): service boundaries, explicit transition saves and review sequence.
- [Testing](testing.md): component/function and installed-wheel procedures.
- [Deployment](diagrams/deployment/deployment-models.md), [creation](diagrams/sequence/association-creation-sequence.md) and [verification](diagrams/sequence/association-verification-sequence.md): editable Mermaid with rendered SVG.

Oracle owns selection, posting, revocation-to-withdrawal and the single
[full-system scenario](https://github.com/GLEIF-IT/vlei-oracle/blob/main/docs/diagrams/sequence/stablecoin-end-to-end-sequence.md).
Comply owns [contract transfer/evaluation diagrams](https://github.com/GLEIF-IT/vlei-comply/tree/main/docs/diagrams/sequence).
Verifier acceptance persists until verified revocation; downstream supersession
does not revoke it. There is no continuous source/account reassessment.
