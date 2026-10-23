# Regression tests

Run `python -m pytest -q tests` with the package and test extra installed. Anvil
must be available on PATH; native integration fails rather than skips without it.
CI builds a wheel and tests it outside the source checkout on Python 3.12.

Read the suite in this order:

| File | Contract protected |
| --- | --- |
| `test_native.py` | Real witnessed issuance, verification, restart and critical rejection paths over POST and PUT. |
| `test_account.py` | Wallet/account outcomes, canonical-block RPC observation and client lifetime. |
| `test_authing.py` | Native signatures, covered HTTP context, rotation and durable replay protection. |
| `test_intake.py` | Decode/replay/enqueue boundaries, malformed-input containment and coordinator-owned rejection. |
| `test_coordinating.py` | Bounded work discovery, retry pacing and completion. |
| `test_basing.py` | Duplicate-safe records and atomic completion. |
| `test_directing.py` | CESR HTTP framing and direct receiver wiring. |
| `test_runtime.py` | Store/task lifetime and CLI configuration. |

`native_helpers.py` constructs real issuer evidence and owns test resource contexts.
Its `entered_service` fixture enters HIO tasks but does not advance the scheduler.
The RPC test endpoint supplies deterministic network responses; it is not a substitute
for the Anvil integration. Failure injection is limited to boundaries whose error
handling belongs to this application.

Prefer observable outcomes over exact scheduling traces, helper call counts or
incidental cleanup counts. Keep a representative malformed input per behavior;
do not expand permutations without a concrete regression or new production path.
A synthetic input is useful when it isolates a real contract, not merely because
we can imagine another possible failure.

## Future tests, when the feature arrives

- Acceptance/outbox and webhook delivery: commit/restart, authenticated ACK,
  duplicate delivery and lost acknowledgement.
- Automatic retry: controlled clock/random tests for pacing, backoff and restart.
- Retirement and selection: native revocation, replacement and exact-SAID withdrawal.

Do not add broad parser fuzzing, exhaustive exception matrices or a second native
verification simulator to this suite now. Revisit extra malformed-version/RPC
variants only for a concrete regression. Deferred freshness, same-event conflict
and advanced Ethereum recovery behavior have no current test obligation.
