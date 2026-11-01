# Operate EOA Verifier

EOA Verifier is an independent Python application. It needs a trusted GEDA AID,
chain ID/RPC endpoint and persistent KERIpy stores. It does not need the oracle
package, contract addresses or an Ethereum posting key.

## Install and start

Use Python 3.12.6+ and a fresh environment containing GLEIF KERI/HIO, not upstream
packages owning the same `keri`/`hio` imports. Build/install a wheel:

```sh
python -m pip wheel --no-deps --wheel-dir dist .
python -m venv /opt/eoa-verifier/venv
/opt/eoa-verifier/venv/bin/pip install dist/eoa_verifier-0.1.0-py3-none-any.whl
/opt/eoa-verifier/venv/bin/eoa-verifier server start \
  --name verifier --alias verifier --head-dir /var/lib/eoa-verifier \
  --trusted-geda-aid "$GEDA_AID" --chain-id 31337 --rpc-url "$RPC_URL" \
  --webhook-url "$WEBHOOK_URL"
```

Use writable paths appropriate to the service account. Start from any working
directory; schemas ship in the wheel. The pinned runtime is `gleif_keri==1.2.19`,
`gleif_hio==0.6.22`, `eth-account==0.14.0`. Runtime imports do not require a sibling
checkout. CI installs the wheel outside the checkout and runs the integration tests with
Foundry 1.5.1.

Reuse name, base, alias, store root and passcode on restart. `--incept-file` supplies
KERIpy options for a new identity only. Each nonce is a direct key, consumed
permanently across all issuers in that store. Nonces contain 1–128 ASCII characters
from `[A-Za-z0-9_-]`; no normalization is applied. There are no old-format readers,
migrations or backfills. Preserve the store across restart.
Enabling webhook delivery with the same root/chain remains supported, but does not
create deliveries for associations accepted without a configured target. Preserve the entire KERIpy/application
store set together; do not copy live LMDB files or share writable stores between
processes. Stop the process before copying/reopening stores for maintenance.

The HTTP listener defaults to loopback on 9724. Put TLS at the deployment boundary.
`GET /health` is liveness only. Public `GET /v1/associations/<said>/status` requires
no signature, reads stored status/initial account observation and performs no RPC.
It exposes delivery attempts and blocked/error state for that association's event.
Shared destination timing and failure counts stay local. The returned observation
is not a continuous account check.

## Configuration changes and stored state

Selecting a store compatible with the configured trust root and network is the
operator's responsibility. Startup compares the trusted GEDA AID and chain ID
with its last recorded settings. A change emits a logger warning containing the
previous and current public values, then startup continues. The new values become
the baseline, so an unchanged restart is quiet; changing back warns again.
A missing baseline is initialized without inspecting historical results or
associations. The advisory record lives in `startup.` and has no nonce-policy
version marker or old-format reader.

The warning does not revalidate results, replay acceptance, clear consumed
nonces, or rewrite pending deliveries and their original destinations. Inspect
outstanding work before repurposing a store. Use separate stores for an
independent deployment and retain the previous stores for its work and permanent
nonce history. A fresh store has independent nonce history; it is not a way to
reset the nonce policy of an existing deployment. Preserve the KERIpy and
application stores together.

Normal configuration syntax, credential verification, nonce rejection and peer
authentication still apply. This warning only replaces rejection of changed
startup settings; it does not grant trust to invalid credentials or messages.

## Optional signer key state and credential evidence

A plain webhook target needs only its URL. If it signs responses, deliver its
public KEL with CESR attachments through `PUT /` before delivery and after key
rotation. Verifier accepts only KERIpy-validated key state, never a header-provided
key or an arbitrary discovery URL. Unknown response signers leave delivery blocked
for operator correction and retry. A receiver choosing request verification needs
Verifier's accepted key state, available from `GET /oobi/<verifier-aid>/controller`.
No receiver AID setting is required. Current signatures support a single
transferable Ed25519 key at threshold one.

Present the untargeted association through IPEX Grant with its source credentials,
KEL/TEL and witnessed issuance evidence. `POST /` accepts JSON body/CESR-attachment header
framing; `PUT /` accepts a finite CESR stream. HTTP 204 acknowledges intake only.
Each request is parsed independently as remote evidence. When KERIpy yields for missing
message or attachment bytes, the incomplete
remainder is discarded at that request boundary. The pinned KERIpy receipt-couple
parser has a known non-yielding shortage path; this remains an unresolved intake
liveness defect. Complete preceding messages can already have entered KERIpy state;
request processing is not an atomic batch. Missing verification evidence still
uses KERIpy escrows.
Initial checks must finish before acceptance. Without webhook configuration, the
service accepts locally and consumes the exact nonce, but creates no delivery
obligation. Public `delivery` is null. Another SAID reusing an accepted pair becomes
locally rejected with `NONCE_REUSED`, even after revocation or downstream supersession. Initial
verification remains visible separately in the application store. See
[ADR 0005](../adrs/0005-accepted-association-nonces.md) for transaction boundaries and
the per-store scope of this policy.

Accepted status remains valid indefinitely. The issuer issues the credential's
TEL revocation. To apply it to local association status, deliver that TEL event
and its anchored/witnessed issuer KEL evidence through the
same CESR HTTP transport. Receiving a Grant or ACDC bytes alone are not revocation proof.
KERIpy must validate the evidence before the verifier records revoked status.
The verifier does not issue the TEL revocation. Revoked status persists across
restart and creates its own immutable event requiring its own successful delivery
when the association had an original outbox obligation. Local-only acceptance
becomes revoked locally without an event.
Revoking an old association does not revoke its replacement.

## Verification and intake failures

The service progresses one item per worker through dedicated durable phases:

| Work | Ready / active | Waiting | Manual intervention |
| --- | --- | --- | --- |
| Grant replay | native Noter / `grant-active.` | `grant-waiting.` with `grant-due.` deadline index | `grant-dead.` |
| Initial verification | `pending.` / `verifying.` | `waiting.` with `verification-due.` deadline index | `verification-dead.` |
| Acceptance | `accepting.` | none: local evidence was already verified | `acceptance-dead.` |
| Verified revocation | `verifier-revocations.` in the native registry | none | unexpected storage errors stop the worker and retain work |

Grant replay and verification allow three attempts with five-second UTC cooldowns.
The attempt commits before processing; an interruption consumes that attempt.
Due retries take precedence over fresh work. No batch paging, completed-history
scanning or in-memory retry timing participates. A missing Grant moves out of
native notifications so it cannot block later notices. Invalid Grants retain
diagnostics immediately; invalid credential proofs become terminal rejections.

Public association GET distinguishes `pending`, `verifying`, `waiting` and
`dead-letter`, including attempts and the next eligible time. Acceptance failures
show `phase: acceptance`. Grant failures can precede knowing the credential SAID;
inspect `grant-dead.` records in the local application store for their notice ID,
Grant attributes and reason. Correct the missing material or RPC configuration,
stop the service, and explicitly resume the affected phase:

```sh
eoa-verifier retry-grant "$NOTICE_ID" --name verifier --head-dir /var/lib/eoa-verifier
eoa-verifier retry-verification "$SAID" --name verifier --head-dir /var/lib/eoa-verifier
eoa-verifier retry-acceptance "$SAID" --name verifier --head-dir /var/lib/eoa-verifier
```

Retry renews only the selected operation's budget; it does not bypass validation,
revocation guards or nonce ownership. Known revocation cannot be repaired by retry.
These queues require fresh stores. There are no compatibility readers or migration.
The native `putTel` boundary is qualified against `gleif_keri==1.2.19`; upgrading
that dependency requires checking its accepted-event write order and requalifying.

## Delivery failures

Transient network/HTTP failures retry automatically with persisted destination
cooldown, up to `--webhook-max-attempts` (default three). Exhaustion moves the event
to the durable dead-letter queue. Each attempt signs the same immutable event bytes anew. Only an expected
authenticated HTTP 200 ACK completes it. Observation age never triggers refresh.
Malformed HTTP chunk framing closes the affected client without stopping sibling
tasks. RPC observations use a three-attempt verification budget; malformed webhook responses leave their
events blocked and undelivered for correction and explicit resumption.
Permanent failures remain blocked until the cause is corrected; restart alone
does not unblock them. Inspect public status and fix peer keys, authorization,
receiver configuration or malformed responses before retrying. Stored events
retain their original destination; changing startup settings does not retarget them.

Local operators can inspect `store.destinations.get(keys=(event.destination,))`
for the destination's failure count and `nextAttemptAt` (UTC Unix seconds). These
scheduling records remain durable and drive the sender; they are absent from public GET.

Acceptance and delivery are distinct durable phases. `accepting.` contains only
unfinished acceptance; `delivery-ready.` and the single `delivery-active.` slot
contain unfinished outbound work. `delivery-dead.` retains exhausted/permanent
failures. Completed verification/results and immutable outbox history are not
scanned to discover delivery work. These are breaking storage changes; use fresh
stores rather than expecting backfill or migration.

After correcting the cause, stop the service and resume the current dead letter:

```sh
eoa-verifier retry-delivery "$EVENT_ID" --name verifier --head-dir /var/lib/eoa-verifier
```

Use the same name/base/head directory as startup, then restart. An embedding
application can call `service.sender.request(event_id)`. Both paths explicitly
requeue a dead letter and reset its bounded attempt budget, retaining immutable
event bytes and destination cooldown. They never mark an ACK. An obsolete event
remains ineligible for delivery even if an operator retries it.

Do not edit event bytes, delete replay records or clear accepted/revoked status to
retry delivery. There is no retry REST route. Undelivered revocation can leave a
downstream mapping active until delivery and withdrawal finish. Source-chain
monitoring, periodic account rechecks and advanced Ethereum recovery are outside
this build. The [paired launcher](https://github.com/GLEIF-IT/vlei-comply/blob/main/docs/gl1-vlei-local-infra-setup.md)
provides the local verifier/oracle/Anvil setup and qualification.

## Protocol and store baseline

Use the current [Verifier API](../protocol/verifier-api-v1/README.md) with a compatible
consumer. Application stores use the current record layout and have no
old-format readers, migrations or backfill. Preserve operator data and select
fresh demonstration stores deliberately. Oracle selection/supersession does not
revoke Verifier acceptance; verified association revocation does.

## Optional webhook verification

Configure only `--webhook-url`. Requests are signed with the Verifier AID and a
signed body digest, but the target may ignore signatures and return any ordinary
2xx response. No receiver AID or JSON ACK schema is required. `delivery.delivered`
means the target returned HTTP success.

If a response supplies either signature header, Verifier requires a valid complete
signature and matching digest. Provision that signer's KEL through the existing
CESR intake before enabling signed responses, and supply validated rotations when
keys change. Unknown keys fail verification; no arbitrary key discovery occurs.
Unsigned responses require no KERI setup. Use HTTPS for destination authentication
and transport integrity; optional signatures do not provide downgrade resistance.
See the [transport contract](../protocol/verifier-api-v1/README.md#transport-signature-profile) for exact coverage and limitations.
