# ADR 0002: Verifier result as an ordinary API object

Status: Design direction; payload fields provisional
Date: 2026-10-22

## Context

The existing association ACDC schema defines the credential being verified.
The split services also need a small result object for HTTP delivery. No runtime
currently consumes the proposed result shape, so a standalone JSON Schema is premature.

## Decision

Define an ordinary JSON object alongside its producer and consumer implementation.
This illustrative success payload preserves the proposed shape for that work:

```json
{
  "version": "1",
  "profile": "vlei-external-association/eoa/v1",
  "associationSaid": "example-association",
  "revision": 1,
  "outcome": "valid",
  "reasonCode": "VALID",
  "binding": {
    "issuerAid": "example-issuer",
    "leSaid": "example-le",
    "qviSaid": "example-qvi",
    "extId": "eip155:31337:0x1111111111111111111111111111111111111111"
  }
}
```

These are synthetic identifiers, not verified credentials or a frozen API contract.
Settle necessary fields, retirement representation, duplicate handling and ordinary
input validation with the webhook implementation. The public status response may
have a different shape. HTTP request signatures remain separate from this object.

## Consequences

No standalone result JSON Schema, generated validators or example-vector suite in
this increment. The existing association ACDC schema remains authoritative for
credential structure; native verification still establishes acceptance. A JSON
object or `valid` string alone proves nothing. Revisit machine-readable result
schemas only if an actual consumer needs them.
