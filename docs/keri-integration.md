# EOA Verifier KERI integration guide

For vLEI issuers, internal integration teams and operators who prepare KERI
evidence. Start with the [partner quickstart](integration-quickstart.md) for the
end-to-end diagram and receiver workflow. This guide covers the KERI side of that
same integration; the [Verifier protocol](../protocol/verifier-api-v1/README.md)
owns the wire contract.

## Establish the credential chain and service identity

```text
Configured trusted GEDA AID
  | issues QVI credential; delegates the QVI AID
  v
QVI AID, identified as holder of that QVI credential
  | issues LE vLEI credential
  v
Legal Entity AID, identified as holder of that LE credential
  | issues untargeted external-association ACDC
  |   LE edge: e.le.n = LE credential SAID, o = I2I
  |   wallet proof: a.proof = EIP-712 agreement
  v
IPEX Grant addressed to the Verifier AID
```

The association issuer must be the LE credential holder; the LE credential issuer
must be the QVI credential holder. QVI issuance and QVI AID delegation must root
at the configured GEDA. The association has **no issuee**: the Grant recipient is
the Verifier, not an `a.i` field in the ACDC.

Use the packaged schemas pinned in
[`verification/constants.py`](../src/eoa_verifier/verification/constants.py).
The association schema SAID is
`ECg_trM84AAnW4ZILy8XhIrXCVSQYqpQ-hktJdk_x0g8`. Obtain schema bytes from the
installed package as described in the
[association profile](../protocol/external-association-v1/README.md#schema-resource).
Recompute nested block and enclosing credential SAIDs; do not edit reference
fixtures into supposedly valid credentials.

Start as in the quickstart, with the agreed GEDA, chain and trusted RPC. The
startup line prints `eoa-verifier serving <aid> ...`. Reuse store name/base/root,
habitat alias and passcode on restart. `--incept-file` supplies options for a new
service identity only; if using witnesses, arrange the required receipts before
expecting its OOBI to be available. The service's HTTP signatures currently require
a transferable Ed25519 AID with one signing key and threshold one.

Give the issuer the Verifier AID and evidence intake URL. KERI peers can introduce
the Verifier through `GET /oobi/{verifier-aid}`. OOBI resolution obtains validated
key state; it does not replace credential/TEL evidence or authorize an arbitrary
producer. Startup uses OOBIs for peer introduction, not imported public KEL files.

## Build the wallet proof and issue the association

Use the installed challenge builder with real issuer/credential identifiers:

```python
import json
import os
from uuid import uuid4
from eoa_verifier.verification.eoa import build_challenge

typed_data = build_challenge(
    issuer_aid=os.environ["ISSUER_AID"],
    le_vlei_said=os.environ["LE_SAID"],
    ext_id=os.environ["EXT_ID"],
    nonce=uuid4().hex,
)
print(json.dumps(typed_data))  # Send this exact typed data to the Ethereum wallet.
```

`EXT_ID` is canonical `eip155:<positive-decimal-chain-id>:0x<40-lowercase-hex>`.
The nonce contains 1–128 characters from `[A-Za-z0-9_-]`, with exact case/bytes
preserved. Choose a fresh nonce for every new credential, across issuers sharing
this Verifier store. Issuance itself does not reserve or consume it.

The EIP-712 primary type is `ExternalAssociation`; its ordered string fields are
`issuerAid`, `leVleiSaid`, `extId`, `nonce`. The domain is
`vlei-external-association/v1`, version `1`, with the chain derived from `extId`.
The builder emits domain `chainId` as decimal text to preserve JSON precision;
EIP-712 still encodes it as `uint256`. There is no `verifyingContract` or `salt`.

Have the bound Ethereum wallet sign typed data. Embed the returned proof in the
association, then compute its SAIDs and issue it through the issuer's registry:

| ACDC field | Required content |
| --- | --- |
| `i`, `ri`, `s` | LE issuer AID, its registry identifier, pinned association schema SAID. |
| `u` | The exact signed nonce. |
| `a.extId` | The exact signed wallet/chain identifier. |
| `a.proof` | SAID-bearing block with `alg: EIP-712/ES256K`, `tag: vlei-external-association/v1`, and `sig`. |
| `e.le` | LE source credential SAID in `n`, LE schema in `s`, and `o: I2I`. |

`sig` is lowercase `0x` hex for 65 bytes (`r || s || v`), with valid `r`, low `s`
and `v` of 27 or 28. The recovered signer must match the bound wallet. The
[EOA profile](../protocol/external-association-v1/eoa-v1/README.md) supplies exact
encoding and known-answer examples; those synthetic examples are not accepted
production credential chains.

Anchor issuance in the issuer's KEL and obtain its required witness receipts.
Build a signed `/ipex/grant` EXN addressed to the Verifier AID, carrying the ACDC
and applicable `iss`/`anc` embeds with attachments. Supply the source credentials,
their registry/KEL evidence, delegation evidence and witness receipts needed to
validate the whole chain. The Verifier replays authenticated `anc`, `iss`, `acdc`
embeds through KERIpy; a valid Grant signature alone does not validate its credential.
The live fixture's
[`grant` and issuance helpers](../scripts/integration/issuers.py) demonstrate the
pinned KERIpy APIs; they are test tooling, not an installed issuer service.

## Deliver complete evidence over HTTP

Prefer a complete finite CESR presentation for streams containing multiple messages:

```sh
curl --fail-with-body -X PUT "$VERIFIER_URL/" \
  -H 'Content-Type: application/cesr' --data-binary @presentation.cesr
```

`PUT /` queues the body bytes unchanged. Alternatively, send one KERI JSON message
and its CESR attachment text using the split framing:

```sh
curl --fail-with-body -X POST "$VERIFIER_URL/" \
  -H 'Content-Type: application/cesr+json' \
  -H "CESR-ATTACHMENT: $GRANT_ATTACHMENTS" \
  --data-binary @grant.json
```

Here `grant.json` is the serialized EXN JSON object and `GRANT_ATTACHMENTS` is that
message's complete attachment text, prepared by the KERI stack. POST reconstructs
the JSON serialization before appending attachments. It rejects explicit query
envelopes; no query/SSE response service exists.

Both forms return `204` for in-memory intake only. They do not acknowledge durable
credential acceptance. Requests are independent: do not split a CESR message or
its attachments across requests. An incomplete remainder is discarded when the
parser yields for missing bytes; preceding complete messages may already have
entered KERIpy state. Missing supporting evidence uses native escrows. The pinned
KERIpy receipt-couple parser also has a known non-yielding shortage path; see
[intake limitations](operations.md#optional-signer-key-state-and-credential-evidence).

## Follow initial verification and acceptance

```text
KERIpy-accepted Grant notice
  -> grant-active. -> pending. -> verifying.
       |                           |
       +-> grant-waiting.           +-> waiting.
       +-> grant-dead.              +-> verification-dead.
                                   |
                     completed initial result (results.)
                       | rejected: public status only
                       v verified
                    accepting. -> associations. + accepted_nonces.
                                      + outbox. + delivery-ready. if configured
```

Each worker advances one item at a time. KERIpy validates signatures, KEL/TEL and
credential evidence. `VerificationService` checks accepted LE/QVI relationships,
GEDA trust/delegation, schema/nested SAIDs and witnessed association issuance.
`WalletCheckDoer` runs `WalletVerifier` with `EthAccountReader`: EIP-712 proof
validation precedes RPC; account reads check chain ID, an identified canonical
block and wallet code at that block. Empty code or an EIP-7702 designation is
accepted; delegated-code safety is not assessed. Local credential evidence is
rechecked before a successful initial result commits.

`verified` is a completed initial result, not acceptance. Acceptance consumes the
exact nonce globally within this store, atomically with association status and any
configured event. A different credential reusing it becomes `rejected` with
`NONCE_REUSED`; same-SAID replay returns stored status. Without a webhook, acceptance
still consumes the nonce, but `delivery` is null and no later backfill is created.

## Deliver credential revocation

Use the issuer's KERI tooling to create the credential TEL revocation, anchor it
in the issuer KEL and obtain the required evidence. Deliver that TEL event and
anchored/witnessed issuer KEL material to the same `PUT /` or `POST /` intake.
A Grant resend, a bare ACDC, a JSON `status` field or a wallet signature is not
revocation proof. A fresh wallet EIP-712 signature is not required for revocation.

```text
Issuer creates/anchors revocation -> HTTP evidence intake
  -> KERIpy validates TEL rev/brv
  -> accepted TEL index + verifier-revocations. commit in VerifierReger
  -> revoked association status + optional revision-2 outbox event commit
  -> acknowledge the separate registry revocation record
  -> webhook -> optional Oracle endorsement withdrawal
```

For an accepted association, revocation preserves its initial association facts,
account observation and original webhook destination. It never releases its nonce
or revokes a replacement credential. Registry and application environments commit
separately; restart safely replays the gap. Revocation known before acceptance
prevents acceptance rather than creating an accepted-then-revoked event pair.
The Verifier applies an issuer revocation; it does not issue that revocation itself.

## HTTP surface and signature options

| Method and route | Meaning |
| --- | --- |
| `PUT /` | Finite CESR evidence stream; `204` is intake only. |
| `POST /` | JSON/CESR-attachment framing; same asynchronous intake semantics. |
| `GET /v1/associations/{said}/status` | Stored credential status/progress; `200` when known, `404` when unknown; no signature or RPC refresh. |
| `GET /health` | Process liveness, not readiness. |
| `GET /oobi`, `/oobi/{aid}`, `/oobi/{aid}/{role}`, `/oobi/{aid}/{role}/{eid}` | KERIpy public key/endpoint introduction, subject to available accepted evidence. |
| `POST /ext/oobi` | Queue native peer introduction with JSON `{"url":"https://peer.example/oobi/..."}`; `202` is queued, not resolved. |
| Outbound `POST <configured-webhook-url>` | Immutable accepted/revoked event JSON; a complete `2xx` completes delivery after any supplied response signature verifies. |

The pinned KERIpy loader additionally mounts `/end/{aid}/{role}`, `/loc`, `/admin`.
These are upstream endpoint/admin scaffolding, not association APIs; do not build
an enrollment or revocation integration against them. Select externally exposed
routes at the deployment boundary. There is no challenge, issuance, revocation,
REST retry, Oracle-posting or continuous-reconciliation endpoint in this service.

Verifier signs webhook `@method`, `@path`, and SHA-256 `content-digest` using
KERIpy `Signature-Input`/CESR `Signature`. `keyid` identifies the signer; a
receiver opting into verification must resolve accepted Verifier key state and
authorize the expected AID. Do not trust `keyid` alone. Oracle does both. Ordinary
webhook targets may ignore signatures and return unsigned `2xx` with no JSON ACK.

For signed responses, configure `--webhook-oobi <response-signer-oobi>` at Verifier
startup. Delivery waits for accepted key state without consuming attempts; intake
and verification continue. Restart refreshes that configured introduction after
rotation. If either signature header appears on a response, both must be complete
and valid with a matching digest. Unknown keys are not discovered from headers.
Response signature context uses the initiating request method/path. HTTP status,
origin/query and a unique attempt ID are not covered; use HTTPS. Read the
[exact signature contract](../protocol/verifier-api-v1/README.md#transport-signature-profile)
before implementing an independent verifier.

## Recovery and a local rehearsal

Grant replay and initial verification allow three attempts with five-second
persisted cooldowns; interrupted attempts count. Webhook delivery defaults to three
attempts with persisted backoff. Inspect public `reason`, `phase` and `delivery`
diagnostics. Grant failures can occur before a credential SAID is known; inspect
local `grant-dead.` records for the notice ID.

After correcting missing evidence, RPC, keys or receiver failures, stop the service
and resume only the affected dead letter using the original store selectors.
Set `STATE_DIR` to the original `--head-dir`:

```sh
eoa-verifier retry-grant "$NOTICE_ID" --name verifier --head-dir "$STATE_DIR"
eoa-verifier retry-verification "$SAID" --name verifier --head-dir "$STATE_DIR"
eoa-verifier retry-acceptance "$SAID" --name verifier --head-dir "$STATE_DIR"
eoa-verifier retry-delivery "$EVENT_ID" --name verifier --head-dir "$STATE_DIR"
```

Add the original `--base` if nonempty, then restart with the same configuration.
Retry does not bypass validation or revocation and does not erase nonce history,
retarget events or reset destination cooldown. Preserve the full store set; do
not share writable stores between processes. Changed trust/network settings warn
and continue: the operator owns whether retained state belongs to that deployment.
See [operations](operations.md) for detailed recovery and persistence guidance.

To rehearse with real local issuance, Grant delivery, restart and revocation,
use Python 3.12.6+ and Foundry/Anvil 1.5.1 from the repository root:

```sh
python -m scripts.integration.env qualify \
  --run-dir /tmp/eoa-verifier-rehearsal --witness-count 1
```

Choose a fresh run directory. This is a local test environment with public test
wallet keys, not production provisioning. Its source chain, receiver and processes
are independent of Oracle/Comply. See the
[fixture guide](../scripts/integration/README.md) for individual operations and
the [Oracle-owned paired qualification](https://github.com/GLEIF-IT/vlei-oracle/blob/main/docs/two-service-qualification.md)
for downstream endorsement publication and withdrawal.
