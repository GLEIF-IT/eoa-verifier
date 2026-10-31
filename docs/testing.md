# Regression tests

Run `python -m pytest -q tests` with the package and test extra installed. Anvil
must be available on PATH; KERI/IPEX integration fails rather than skips without it.
CI checks component dependencies with `python tools/check_architecture.py`, then
builds a wheel and tests it outside the source checkout on Python 3.12.

Read the suite in this order:

| File                       | Contract protected                                                                             |
| -------------------------- | ---------------------------------------------------------------------------------------------- |
| `test_ipex_integration.py` | Witnessed issuance, delayed-anchor retirement/restart and critical rejections over POST/PUT.   |
| `test_account.py`          | Wallet/account outcomes, canonical-block RPC observation and client lifetime.                  |
| `test_authing.py`          | KERIpy signatures, covered HTTP context, rotation and durable replay protection.               |
| `test_intake.py`           | Decode/replay/enqueue boundaries, malformed-input containment and coordinator-owned rejection. |
| `test_coordinating.py`     | Bounded work discovery, retry pacing and completion.                                           |
| `test_basing.py`           | Duplicate-safe records and atomic completion.                                                  |
| `test_accepting.py`        | Atomic acceptance/retirement outbox, rollback/reopen and public stored status.                 |
| `test_delivering.py`       | Signed HTTP/ACK boundaries, retirement ACKs and fresh signatures after a lost ACK.             |
| `test_directing.py`        | CESR HTTP framing and direct receiver wiring.                                                  |
| `test_retry.py`            | Controlled-clock pacing, backoff/cap, Retry-After, cooldown restart and permanent errors.      |
| `test_runtime.py`          | Store/task lifetime and CLI configuration.                                                     |

`keripy_helpers.py` constructs real issuer evidence and owns test resource contexts.
Its `entered_service` fixture enters HIO tasks but does not advance the scheduler.
The RPC test endpoint supplies deterministic network responses; it is not a substitute
for the Anvil integration. Failure injection is limited to boundaries whose error
handling belongs to this application.

Prefer observable outcomes over exact scheduling traces, helper call counts or
incidental cleanup counts. Keep a representative malformed input per behavior;
do not expand permutations without a concrete regression or new production path.
A synthetic input is useful when it isolates a real contract, not merely because
we can imagine another possible failure.

## Paired system qualification

The oracle's [two-service test](https://github.com/GLEIF-IT/vlei-oracle/blob/7d82d04cd444cb21e1da1e6ec0408cc40105d4f4/docs/two-service-qualification.md)
runs both installed CLIs, witnessed KERIpy issuance, signed webhooks, Anvil
publication/replacement/withdrawal and actual USDC balances. Keep contract and
consumer-selection assertions there rather than duplicating them in this package.

Do not add broad parser fuzzing, exhaustive exception matrices or a second KERIpy
verification simulator to this suite now. Revisit extra malformed-version/RPC
variants only for a concrete regression. Deferred freshness, same-event conflict
and advanced Ethereum recovery behavior have no current test obligation.
