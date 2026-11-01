# vLEI External Association — Ethereum EOA v1

## File reference

- [README.md](README.md): Wallet challenge purpose, signed fields, verification, endorsements, and fixture reproduction.
- [association.json](association.json): Sample EOA association ACDC in the exact compact bytes used to calculate its SAID.
- [challenge.json](challenge.json): EIP-712 message binding the issuer, LE vLEI credential, Ethereum account, and nonce.
- [test-vector.json](test-vector.json): Known-answer data with a public signing key, challenge, expected hashes, signature, and SAIDs.
- [packaged schema](../../../src/eoa_verifier/verification/schema_data/external-association-v1.json): Common vLEI External Association ACDC schema used by this profile.

This profile applies the [common association structure](../README.md) to an
Ethereum externally owned account. Its profile identifier is
`vlei-external-association/eoa/v1`. The examples use synthetic KERI credential
references and a public test signing key.

## What the wallet challenge means

The wallet holder signs an off-chain EIP-712 challenge agreeing to associate
their account, on a specified chain, with the Legal Entity identified by an AID
and LE vLEI credential. Signing requires no transaction or gas. The signature
is embedded in the association ACDC so a relying party can verify that agreement.

### Why each field is signed

| Message field | What the wallet holder agrees to | Downstream use |
|---|---|---|
| `issuerAid` | Associate the account with **this entity's AID**. | Rebuilt from `i`; checked against the LE credential's holder. Its hash supplies the endorsement's `identityRef`. |
| `leVleiSaid` | Refer to **this particular LE credential**. | Rebuilt from `e.le.n`; followed to establish the LEI, trust chain, and credential status. Signing it prevents substituting another credential while retaining the wallet signature. |
| `extId` | Associate **this account on this chain**. | Rebuilt from `a.extId`; the address must match the recovered signer and supplies the endorsement's `wallet`. The chain scopes signing and registry posting. |
| `nonce` | Authorize **this individual ceremony**. | Rebuilt from `u`; a new nonce requires a new signature. EOA Verifier consumes the exact nonce on application acceptance; another SAID cannot reuse it. |

These fields are the association protocol's signed commitments; EIP-712 supplies
the typed-data format and signing rules. Binding the exact LE credential means
an association referencing a replacement credential requires a fresh wallet
signature. Nonce reuse prevention belongs to the application; EIP-712 does not
provide it automatically.

The verifier reconstructs the challenge from the ACDC and checks the embedded
signature. Contract publication is a separate consumer operation, described [below](#verification-and-endorsement).

### EIP-712 payload

`build_challenge` returns only `types`, `primaryType`, `domain`, and `message`.
The message has four ordered string fields:

```text
ExternalAssociation(string issuerAid,string leVleiSaid,string extId,string nonce)
```

The domain name is `vlei-external-association/v1`, version is `1`, and `chainId` is derived from
`extId`, represented as a decimal JSON string to preserve large integer precision
across JSON clients. EIP-712 encodes it as `uint256`. The domain has no
`verifyingContract` or `salt`.

### Identifier and signature encoding

`a.extId` is canonical CAIP-10: `eip155:<chain ID>:<address>`. The chain ID is a
positive decimal integer without leading zeros, limited to 32 digits. The
address is `0x` followed by 40 lowercase hexadecimal characters. Mixed-case
presentations undergo EIP-55 checksum validation before normalization.

The nonce `u` contains 1–128 ASCII characters from `[A-Za-z0-9_-]`, with no
normalization. Whitespace, dots and non-ASCII text are invalid. The [verifier API](../../verifier-api-v1/README.md) defines application
nonce consumption; storage representation is outside this credential profile.

The proof uses `alg` of `EIP-712/ES256K` and tag
`vlei-external-association/v1`. Its signature is 65 bytes: concatenated 32-byte
`r`, 32-byte `s`, and one-byte `v`, encoded as lowercase `0x` hex.
For secp256k1 order `n`, require `1 <= r < n`, `1 <= s <= n/2`, and
`v` of 27 or 28. The recovered signer must match the bound account.

## Verification and endorsement

EOA Verifier owns challenge reconstruction and proof verification in
`eoa_verifier.verification.eoa`. Issuers deliver native KERI credentials and
supporting evidence to that service, which checks credential trust, wallet proof
and initial account state before application acceptance. Its accepted-nonce
policy is independent of optional webhook delivery and never releases a nonce
on revocation. This is a fresh acceptance-store baseline, not global uniqueness
across independent verifier stores.

The oracle receives authenticated accepted/revoked status and selects the current
wallet association before posting or withdrawing the exact endorsement. It has
no credential issuance, proof verification or association nonce persistence API.
See the root README and the maintained paired qualification.

## Reproducing the examples

Use Python 3.12.6+ and an installed verifier with its test dependencies. The
reference ACDC contains synthetic KERI identifiers and public test key 1; it is an
encoding fixture and must not pass production credential verification.

```sh
python -m pip install '.[test]'
python -m pytest -q tests/verification/test_association_profile.py
python scripts/protocol/generate_vectors.py
```

The generator reads `association.json` (or `--association <path>`), preserves its
exact serialized bytes, and derives only challenge/signature/hash reference data.
It does not issue credentials, change schemas or generate contract fixtures.
[Comply owns publication/calldata fixtures](https://github.com/GLEIF-IT/vlei-comply/blob/main/abi/endorsement-vector.json).
Oracle's maintained qualification constructs live credentials with KERIpy and
retains the complete witnessed chain and process boundaries.

Related standards: [EIP-712](https://eips.ethereum.org/EIPS/eip-712),
[EIP-55](https://eips.ethereum.org/EIPS/eip-55),
[CAIP-10](https://standards.chainagnostic.org/CAIPs/caip-10), and
[EIP-7702](https://eips.ethereum.org/EIPS/eip-7702).
