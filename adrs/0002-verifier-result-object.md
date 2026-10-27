# ADR 0002: Verifier result as an ordinary API object

Status: Accepted; acceptance and retirement delivery implemented
Date: 2026-10-27

## Context

The association ACDC schema defines the credential. The webhook needs a separate,
small status object; it does not need a standalone JSON Schema or validator framework.

## Decision

Persist one immutable JSON body per status event. The initial acceptance shape is:

```json
{
  "version": "1",
  "eventId": "example-association:1",
  "associationSaid": "example-association",
  "revision": 1,
  "outcome": "valid",
  "association": {
    "issuerAid": "example-issuer",
    "leSaid": "example-le",
    "extId": "eip155:31337:0x1111111111111111111111111111111111111111",
    "issuance": {"sequenceNumber": 3, "said": "example-issuer-kel-event"}
  },
  "observation": {
    "wallet": "0x1111111111111111111111111111111111111111",
    "chainId": 31337,
    "blockNumber": 42,
    "blockHash": "0x2222222222222222222222222222222222222222222222222222222222222222",
    "code": "0x",
    "observedAt": "2026-10-23T12:00:00Z"
  }
}
```

Identifiers above are illustrative. Issuance identifies the verified anchor in the
issuer's KEL, not receipt order. The observation records the initial check only;
its age never expires acceptance. `eventId` combines association SAID and revision.

Verified association revocation creates a second event: `revision: 2`,
`eventId: "example-association:2"`, `outcome: "invalid"`, and
`reasonCode: "REVOKED"`. Keep the original `association` and `observation` objects;
the issuance anchor must not become the revocation anchor. Commit retirement and
this event together, using the original delivery destination. Retirement is terminal
for that SAID and requires its own ACK; the initial event’s ACK cannot complete it.

POST the exact stored bytes to the configured destination with the service
signature profile. Completion requires an authenticated HTTP 200 response bound
to that attempt, with exactly this JSON object (`accepted` is a boolean):

```json
{"eventId": "example-association:1", "accepted": true}
```

The receiver signs only after durable acceptance. Redelivery keeps the event/body
and gets a fresh transport signature; the receiver acknowledges duplicates without
repeating effects. A signature on an error response does not complete delivery.

## Consequences

The producer owns serialization and the delivery component owns ACK validation.
The public GET response is a separate stored-state view. Native verification
remains required before acceptance; JSON alone is never evidence. Retirement
requires accepted native association TEL revocation. Revisit a
machine-readable result schema only when an actual consumer needs it.
