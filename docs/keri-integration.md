# EOA Verifier KERI integration guide

For vLEI issuers, internal integration teams and operators who prepare KERI
evidence. Start with the [partner quickstart](integration-quickstart.md) for the
end-to-end diagram and receiver workflow. This guide covers the KERI side of that
same integration; the [Verifier protocol](../protocol/verifier-api-v1/README.md)
owns the wire contract.

## Setup and dependencies

For a hosted integration, prepare the LE holder's KERI issuer stack and an
Ethereum wallet capable of signing EIP-712; receive results at your HTTPS endpoint.
To run the Verifier yourself, use Python 3.12.6+, libsodium, a trusted Ethereum RPC,
and the agreed GEDA/network configuration. Use a fresh virtual environment so the
pinned GLEIF KERI/HIO packages own their imports; see [operations](operations.md).

For the turnkey demo, use macOS or glibc Linux (Intel/ARM), Bash, Git, libsodium
and Python 3.12.6+ or uv. For example:

```sh
# macOS, with Homebrew already installed:
brew install git uv libsodium

# Debian/Ubuntu: install native prerequisites, then uv if needed:
sudo apt-get update
sudo apt-get install git curl libsodium-dev
curl -LsSf https://astral.sh/uv/install.sh | sh
# Open a new shell so uv is on PATH.
```

See [uv installation](https://docs.astral.sh/uv/getting-started/installation/) for
other installation methods. The Bash launcher supplies Homebrew's libsodium search
path on macOS. For manual Python/service startup outside the launcher, set
`DYLD_FALLBACK_LIBRARY_PATH` to include `$(brew --prefix libsodium)/lib` if the
loader cannot find libsodium. First start needs network access to Python packages
and GitHub releases. The demo builds/installs a wheel in a run-owned venv and
reuses matching Foundry 1.5.1 tools or downloads/verifies the official archive into
`~/.cache/eoa-verifier/foundry` (or `$XDG_CACHE_HOME/eoa-verifier/foundry`). It does
not change your global Foundry installation or shell profile. Forge is included;
no contracts need compiling/deploying for this Verifier-only flow.

## Turn on the local demo

From the repository root, one command prepares a witnessed GEDA/QVI/LE test chain,
starts the witness/schema host, Anvil, installed Verifier and independent signed
webhook receiver, then signs/issues/presents an association:

```sh
./scripts/demo.sh run
./scripts/demo.sh status
./scripts/demo.sh revoke
./scripts/demo.sh events
```

Success waits for public `accepted`/`revoked` status **and** `delivery.delivered`.
The receiver logs each authenticated, stored event as `Webhook received {...}`:

```sh
./scripts/demo.sh logs --follow                 # Receiver, including full payloads
./scripts/demo.sh logs --service verifier       # Current Verifier log
./scripts/demo.sh down                          # Stop; preserve stores and chain
./scripts/demo.sh up                            # Reopen the same run
./scripts/demo.sh clean                         # Only after down; delete demo state
```

Anvil runs on chain 31337 and funds public test wallets 1 and 2 with 1,000 test ETH
once. Their keys are explicitly public in
[`wallet.py`](../scripts/integration/wallet.py); never send real assets to them.
Restart retains balances, identities, credentials, consumed nonces and received
events. `status` lists dynamically selected loopback URLs, AIDs and artifact paths.
No fixed ports or external Oracle/Comply checkout are required. One controller
operates a run at a time; a foreign listener/process is never adopted or killed.

For a second demo, put the global option before the command:

```sh
./scripts/demo.sh --run-dir /tmp/another-eoa-demo run
./scripts/demo.sh --run-dir /tmp/another-eoa-demo revoke
./scripts/demo.sh --run-dir /tmp/another-eoa-demo down
```

The default root is `~/.local/share/eoa-verifier/demo`. Preparation snapshots source
and records wheel/content hashes. Restart uses that snapshot; after code changes,
choose a fresh root or stop/clean/recreate the disposable demo. It creates a local
test LE credential/holder; it does not import an existing production holder's keys
or claim GLEIF production authority. Existing LE holders use their own KERI stack
with the protocol steps below.

## Drive the wallet and issuer separately

To inspect every step instead of using `run`:

```sh
./scripts/demo.sh up
./scripts/demo.sh challenge --wallet 1  # Prints the exact challenge/signature paths
./scripts/demo.sh sign                 # Public test wallet signs challenge.json
./scripts/demo.sh issue                # Local LE holder issues the association
./scripts/demo.sh present              # IPEX Grant -> acceptance -> webhook
./scripts/demo.sh revoke               # Issuer TEL revocation -> revoked webhook
./scripts/demo.sh events
```

Each challenge defaults to a fresh nonce and gets its own directory under
`ceremonies/`; previous signed artifacts stay available. `--nonce` can deliberately
reuse one to exercise Verifier rejection; the issuer does not claim nonces. `issue` prints the credential SAID; `revoke --said SAID`
selects an earlier accepted demo association. Repeated revocation of an already
delivered revocation is harmless. `run --wallet 2` starts another independent
ceremony. The Verifier's permanent nonce policy remains unchanged.

For an external Ethereum wallet, generate typed data for its lowercase address:

```sh
./scripts/demo.sh challenge --wallet-address 0xYOUR_LOWERCASE_40_HEX_ADDRESS
# Sign the returned challenge.json through your wallet's EIP-712 interface.
# Save its result as JSON: {"signature":"0x..."} in /tmp/wallet-signature.json.
./scripts/demo.sh issue --signature-file /tmp/wallet-signature.json
./scripts/demo.sh present
./scripts/demo.sh revoke
```

Use the RPC URL from `status` and chain 31337 when connecting an external wallet.
`sign` accepts only the numbered public test keys. The external wallet's private
key never enters the issuer process. Its signature must match the exported
challenge, local LE holder and chain before TEL issuance starts. Revocation is
performed by that LE issuer and needs no new Ethereum wallet signature.

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
