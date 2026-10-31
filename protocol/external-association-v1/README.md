# vLEI External Association v1

## File reference

- [README.md](README.md): Association purpose, structure, and source documents.
- [packaged association schema](../../src/eoa_verifier/verification/schema_data/external-association-v1.json): Common ACDC schema and field definitions.
- [eoa-v1/](eoa-v1/README.md): Ethereum wallet challenge, EOA profile, examples, and test vector.

## Overview

A vLEI External Association links a Legal Entity's vLEI-controlled AID to an
external identifier. The external controller signs a challenge, and the Legal
Entity embeds that signature in an ACDC it issues. A relying party can then
verify both the entity's authority and the external controller's agreement.

The association nonce `u` contains 1–128 ASCII characters from `[A-Za-z0-9_-]`.
Whitespace, dots, other punctuation and non-ASCII text are rejected. Its exact
case and bytes are signed unchanged. Application acceptance and nonce consumption are defined by
[verifier-api-v1](../verifier-api-v1/README.md), independently of issuance.

The association has an issuer and no issuee. Its LE vLEI edge identifies the
credential held by that issuer and supplies the authoritative LEI. The common
schema leaves identifier and signature formats to profiles such as the
[Ethereum EOA profile](eoa-v1/README.md).

The association stands on its own; an oracle may separately publish a verified
association mapping for on-chain use. See the [schema](../../src/eoa_verifier/verification/schema_data/external-association-v1.json) for field
constraints and the [maintained Oracle qualification](https://github.com/GLEIF-IT/vlei-oracle/blob/main/docs/two-service-qualification.md) for a
complete delegated test chain presented to EOA Verifier. The oracle receives
authenticated accepted/revoked status and publishes selected mappings.

## Sources

- *Associating External Identifiers with a LE vLEI*: common methodology.
- *Associating an Ethereum EOA with a LE vLEI — EOA Implementation Profile*: Ethereum account signing and verification.
- *Associating an ENS Name with a LE vLEI — ENS Implementation Profile*: ENS associations and the distinction between verification and endorsement.

## Schema resource

The sole authored schema is packaged in the verifier wheel at
`eoa_verifier.verification/schema_data/external-association-v1.json`. There is no
second protocol-tree copy. To obtain its exact bytes, select a pinned installed
verifier environment and run:

```python
from importlib.resources import files
raw = files("eoa_verifier.verification").joinpath(
    "schema_data/external-association-v1.json"
).read_bytes()
```

Consumers may serve or copy these bytes as a derived artifact. Select the verifier
revision explicitly and retain its resource bytes/SAID; do not author another schema.
