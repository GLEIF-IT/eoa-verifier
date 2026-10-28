# Operate EOA Verifier

EOA Verifier is an independent Python application. It needs a trusted GEDA AID,
chain ID/RPC endpoint and persistent native stores. It does not need the oracle
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
  --webhook-url "$WEBHOOK_URL" --webhook-aid "$RECEIVER_AID"
```

Use writable paths appropriate to the service account. Start from any working
directory; schemas ship in the wheel. The pinned runtime is `gleif_keri==1.2.17`,
`gleif_hio==0.6.21`, `eth-account==0.14.0`. Runtime imports do not require a sibling
checkout. CI installs the wheel outside the checkout and runs native tests with
Foundry 1.5.1.

Reuse name, base, alias, store root and passcode on restart. `--incept-file` supplies
native options for a new identity only. Preserve the entire native/application
store set together; do not copy live LMDB files or share writable stores between
processes. Stop the process before copying/reopening stores for maintenance.

The HTTP listener defaults to loopback on 9724. Put TLS at the deployment boundary.
`GET /health` is liveness only. Public `GET /v1/associations/<said>/status` requires
no signature, reads stored status/initial account observation and performs no RPC.
It exposes delivery attempts, blocked/error state and the next destination attempt
time (UTC seconds). The returned observation is not a continuous account check.

## Introduce the webhook peer and present evidence

Configure the peer AID explicitly. Deliver its public native CESR KEL and required
attachments through `PUT /`, or resolve its native OOBI through the supported
native endpoint. A header-provided key is never trusted. The receiver likewise
needs this verifier's accepted current key state; export it from
`GET /oobi/<verifier-aid>/controller`. Current service authentication supports one
transferable Ed25519 key at threshold one. On rotation, introduce the new native
key events before resuming delivery. Missing keys leave events blocked.

Present the untargeted association through IPEX Grant with its source credentials,
KEL/TEL and witnessed issuance evidence. `POST /` accepts native CESR JSON/header
framing; `PUT /` accepts a finite CESR stream. HTTP 204 acknowledges intake only.
Initial checks must finish before acceptance. Without webhook configuration, the
service retains verification-only results and does not create delivery obligations.

Accepted status remains valid indefinitely. To retire it, deliver the association's
native revocation TEL and its anchored/witnessed issuer KEL evidence through the
same native transport. Grant receipt or ACDC bytes alone are not revocation proof.
Native validation/escrows must accept the revocation. Retirement persists across
restart and creates its own immutable event requiring its own authenticated ACK.
Retiring an old association does not retire its replacement.

## Delivery failures

Transient network/HTTP failures retry automatically with persisted destination
cooldown. Each attempt signs the same immutable event bytes anew. Only an expected
authenticated HTTP 200 ACK completes it. Observation age never triggers refresh.
Permanent failures remain blocked until the cause is corrected; restart alone
does not unblock them. Inspect public status and fix peer keys, authorization,
receiver configuration or malformed responses before retrying. Stored events
retain their original destination; changing startup settings does not retarget them.

An embedding application can call `service.sender.request(event_id)`. For a
standalone process, stop it and use its installed Python to unblock the **current**
event with the same store coordinates, then restart. This preserves the event and destination cooldown, recording the
retry request as its current reason; it does not mark an ACK:

```python
from keri.db import dbing
from eoa_verifier.basing import VerifierBaser

with dbing.openLMDB(cls=VerifierBaser, name="verifier", base="",
                   headDirPath="/var/lib/eoa-verifier", temp=False) as store:
    event_id = "<association-said>:<revision>"  # From the public status response.
    event = store.outbox.get(keys=(event_id,))
    if event is None or event.delivered:
        raise ValueError("event is unknown or already delivered")
    status = store.associations.get(keys=(event.associationSaid,))
    if status.eventId != event_id:
        raise ValueError("only the current association event can resume")
    store.delivery_result(event_id, error="operator requested retry after correction",
                          blocked=False)
```

Do not edit event bytes, delete replay records or clear accepted/revoked status to
retry delivery. There is no retry REST route. Undelivered revocation can leave a
downstream mapping active until delivery and withdrawal finish. Source-chain
monitoring, periodic account rechecks and advanced Ethereum recovery are outside
this build. The [paired launcher](https://github.com/GLEIF-IT/vlei-comply/blob/f61846512bbc75255b82c25b1c4ac71bc2127c57/docs/gl1-vlei-local-infra-setup.md)
provides the local verifier/oracle/Anvil setup and qualification.
