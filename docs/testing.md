# Find and run verifier tests

Run from the repository root with the installed verifier and pytest. Tests are an
explicit tests package; pytest.ini selects importlib mode. No PYTHONPATH or
sys.path edits are required. The verifier also owns the
external-association profile conformance suite and reference vectors.

| Production subject | Test location / example |
|---|---|
| Credential/schema/proof profile | python -m pytest tests/verification/test_association_profile.py |
| runtime/cli.py | python -m pytest tests/runtime/test_cli.py |
| runtime/config.py | python -m pytest tests/runtime/test_config.py |
| runtime/serving.py | python -m pytest tests/runtime/test_serving.py -k cleanup |
| receiving/directing.py and grants.py | tests/receiving/test_directing.py and test_grants.py |
| verification/eoa.py | python -m pytest tests/verification/test_eoa.py |
| EoaVerifierDoer / timeout | python -m pytest tests/verification/test_worker.py -k timeout |
| VerificationService / VerificationCoordinator | tests/verification/test_coordinating.py |
| StatusQuery / StatusEnd | python -m pytest tests/associations/test_statusing.py |
| AcceptanceService and atomic acceptance writes | python -m pytest tests/persistence/test_basing.py -k acceptance |
| Detached readers | tests/integration/test_ipex_verification.py and tests/delivery/test_delivering.py |
| LMDB nonce claims/durability | tests/persistence/test_accepted_nonces.py |
| Delivery authentication and sender | tests/delivery/test_authing.py and test_delivering.py |
| Acceptance/revocation workers with witnessed evidence | tests/integration/test_ipex_verification.py |
| Atomic revocation plus public visibility | tests/integration/test_acceptance_status.py |

Use ::test_function_name for one function and -k expression for a class or method.
Reusable issuer, service ownership, network and acceptance construction is in
tests/support. Fixtures live in their narrowest common conftest. Tests never
import other test modules. The complete suite includes component tests plus the 69 association-profile cases
moved from Oracle. Contract mapping/calldata conformance remains at Oracle's
Comply integration boundary.

Run python -m pytest. Full tests require
Foundry 1.5.1 including Anvil. CI builds a fresh wheel and copies tests, protocol fixtures and
pytest.ini outside the checkout before running python -m pytest. Test support is
excluded from wheels. Run one repository's test package per invocation. The sole
paired-system scenario belongs to the oracle; launchers invoke it without copies.

## Regression discipline

The issuer support constructs real evidence; services.entered_service enters HIO
tasks without advancing the scheduler. Deterministic RPC endpoints isolate the
HTTP boundary and do not replace the Anvil integration. Failure injection stays
at boundaries whose error handling belongs to this application.

Prefer observable outcomes over exact scheduler traces or incidental cleanup
counts. Keep representative malformed inputs; expand matrices only for a concrete
regression or production path. Do not add broad parser fuzzing, exhaustive
exception permutations or a second KERIpy verification simulator. Deferred
freshness, same-event conflict and advanced Ethereum recovery have no additional
test obligation in this organization refactor.

The oracle's maintained two-service qualification owns contract and consumer
selection assertions. Keep them there rather than duplicating the workflow here.

## Object names in source and tests

Name the domain object and distinguish its representation: `credSaid` and
`telEvtSaid` are identifier strings, `telSerder` is a parsed TEL event, and
`presentationCesr` is encoded presentation material. Keep these names through
callers, fixtures and assertions. `VerificationRecord`, `GrantReplayRecord`,
`AssociationStatus` and `Delivery` identify different records; phase-table
membership supplies their lifecycle state. Use state qualifiers with a noun
when needed, such as `revokedStatus`, rather than labels such as `handoff` or
`accepted` that conceal the object or become false as it advances.

Feature persistence lives in grants.py, verification.py, associations.py and
delivery.py. ScopeStore reads/saves advisory startup settings only. HTTP signature
verification is stateless; there is no transport replay store. Test-only verification setup
lives in tests/support/persistence.py; production enqueue is GrantWriter.complete.
