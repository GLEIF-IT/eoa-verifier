# EOA Verifier integration quickstart

EOA Verifier checks a Legal Entity's vLEI authority and an Ethereum wallet holder's
signed agreement to an association. Receive accepted/revoked results through an
ordinary JSON webhook without implementing KERI. On-chain publication is a separate
Oracle step.

## Agree on the integration

The deployment operator supplies the Verifier URL and configures your HTTPS webhook
URL. The Legal Entity's KERI integration team prepares and presents the association
credential. Your application requests the wallet signature and handles status events.

An **AID** identifies an entity/service; a **SAID** identifies a credential/event.
Look up status using the **association credential SAID** supplied by the issuer.

## How issuance and revocation reach your application

```text
ISSUE
Ethereum wallet -- EIP-712 signature --> Legal Entity (issuer)
                                            |
                          Issue association credential containing proof
                          Send IPEX Grant + supporting KERI evidence
                                            |
                                     POST / or PUT /
                                            v
                                      EOA Verifier
                         Check vLEI chain + proof + Ethereum RPC
                         Accept and permanently consume the nonce
                                            |
                      POST your webhook: accepted, revision 1
                                            v
                         Your application (or vLEI Oracle)

REVOKE an accepted association
Entity issuer -- credential revocation + anchored/witnessed evidence
                                            |
                                     POST / or PUT /
                                            v
                         EOA Verifier validates and records revocation
                                            |
                       POST your webhook: revoked, revision 2
                                            v
                         Your application (or Oracle -> withdrawal)

CHECK STATUS: your app -> GET /v1/associations/{said}/status
CHECK PROCESS: monitor -> GET /health
INTRODUCE KEYS: KERI peer -> GET /oobi/{verifier-aid}
RESOLVE PEER: operator -> POST /ext/oobi
```

An IPEX Grant presents the credential to the Verifier. Revocation uses issuer-signed
evidence. There is no REST issue, challenge, or revoke command. Rejected/unfinished
checks appear in GET status, not webhooks.

## Connect in four steps

Set `VERIFIER_URL` to the agreed base URL and `SAID` to the credential ID from
the issuer. The [advanced guide](keri-integration.md#http-surface-and-signature-options)
lists all HTTP routes, including infrastructure handlers outside this workflow.

1. **Sign the wallet agreement.** Have the issuer integration prepare the exact
   [EIP-712 typed data](../protocol/external-association-v1/eoa-v1/README.md).
   It binds the entity, LE credential, wallet/chain and fresh nonce. Use typed-data
   signing, not a plain-text signature; no transaction or gas is required. Return
   the signature to the issuer.
2. **Have the issuer present the credential.** The issuer creates the association,
   gathers its evidence and sends the Grant to the Verifier AID. For a complete
   presentation file, HTTP delivery is:

   ```sh
   curl --fail-with-body -X PUT "$VERIFIER_URL/" \
     -H 'Content-Type: application/cesr' \
     --data-binary @presentation.cesr
   ```

   `204` means queued for processing, **not verified or accepted**. A bare JSON
   credential or wallet signature is insufficient.
3. **Receive accepted and revoked events.** Your endpoint accepts JSON POSTs.
   An acceptance event contains these fields, among others:

   ```json
   {
     "version": "1",
     "eventId": "<credential-said>:1",
     "associationSaid": "<credential-said>",
     "statusRevision": 1,
     "status": "accepted"
   }
   ```

   Full events also include `association` and `accountObservation`. Revocation
   retains those initial facts and uses the same credential SAID, revision `2`,
   event ID ending `:2`, status `revoked` and `reasonCode: "REVOKED"`.
4. **Store before acknowledging.** Durably store/deduplicate by `eventId` before
   returning any `2xx`; no response body is required. Identical redelivery must be
   harmless; reject an event ID reused with different bytes. Keep revisions per
   credential; delayed acceptance must never undo revocation. Default delivery has three attempts; unresolved failures require
   operator recovery. See the [complete event contract](../protocol/verifier-api-v1/README.md).

Signature verification is optional. Your receiver needs no AID, registration,
shared secret or signed response. If you skip verification, restrict/authenticate
the sender through deployment controls; HTTPS alone does not authenticate callers.
Coordinate optional signed responses with the operator first.

## Check progress

```sh
curl --fail-with-body "$VERIFIER_URL/health"
curl --fail-with-body "$VERIFIER_URL/v1/associations/$SAID/status"
```

Wait for `accepted`; `verified` means initial checks finished, before application
acceptance. `pending`, `verifying` and `waiting` mean unfinished work. Inspect
`reason` for `rejected` or `dead-letter`. An unknown SAID returns `404`.
`delivery.delivered` reports webhook HTTP success, not on-chain publication.
Health is process liveness, not dependency readiness.

Acceptance has no automatic expiry. The issuer must deliver validated revocation
evidence to change it. No periodic wallet or source-chain checks run. A consumed
nonce cannot be reused by another credential, even after revocation.

## Run your own Verifier

From a reviewed repository checkout, use Python 3.12.6+ in a fresh virtual
environment. Set `GEDA_AID`, `CHAIN_ID`, `RPC_URL` and `WEBHOOK_URL` to your agreed
deployment values, then:

```sh
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install .
eoa-verifier server start \
  --name verifier --alias verifier --head-dir "$PWD/verifier-state" \
  --trusted-geda-aid "$GEDA_AID" --chain-id "$CHAIN_ID" --rpc-url "$RPC_URL" \
  --webhook-url "$WEBHOOK_URL" --http-port 9724
```

The listener defaults to loopback; expose it through HTTPS. Startup prints the
Verifier AID. Reuse identity/storage settings on restart. Configure the webhook
before presenting credentials; enabling it later does not backfill earlier acceptances.

Continue with the [KERI integration guide](keri-integration.md) for exact evidence
framing, all registered HTTP routes and optional signature verification, or the
[operator guide](operations.md) for deployment and recovery.
