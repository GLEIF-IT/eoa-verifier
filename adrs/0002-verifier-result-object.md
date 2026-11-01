# ADR 0002: Verifier status as an ordinary API object

Status: Accepted
Date: 2026-10-27

The association ACDC and a delivery event serve different purposes. Use a small
ordinary JSON status object, not another credential or validator framework.

Persist immutable event bytes with acceptance or verified revocation. Keep
mutable attempt progress separate. A retry preserves event identity/body and
uses fresh transport authentication. A complete HTTP 2xx response completes
delivery after verification of any supplied signature; unsigned responses are
accepted. The target needs no KERI identity or ACK payload. Public GET is a
separate stored-state view.

[verifier-api-v1](../protocol/verifier-api-v1/README.md) is the single normative
owner of event fields, accepted/revoked vocabulary, signatures and delivery completion. The
producer owns serialization; consumers own their status-event storage and effect policies. JSON
alone never proves credential validity, selection or an on-chain endorsement.
