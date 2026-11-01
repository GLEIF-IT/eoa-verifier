# Standalone Verifier environment

Run from this repository root with Python 3.12.6+ and Anvil 1.5.1 on PATH. No
Oracle, Comply, Solidity checkout or external schema service is required.
Application code runs from an installed wheel in a run-owned virtual environment.

```sh
python -m scripts.integration.env prepare --run-dir /tmp/verifier-demo
python -m scripts.integration.env start --run-dir /tmp/verifier-demo
python -m scripts.integration.env flow --run-dir /tmp/verifier-demo
python -m scripts.integration.env status --run-dir /tmp/verifier-demo
python -m scripts.integration.env logs --run-dir /tmp/verifier-demo --service verifier
python -m scripts.integration.env stop --run-dir /tmp/verifier-demo
python -m scripts.integration.env start --run-dir /tmp/verifier-demo
python -m scripts.integration.env stop --run-dir /tmp/verifier-demo
python -m scripts.integration.env clean --run-dir /tmp/verifier-demo
```

`qualify --run-dir FRESH` performs prepare/start/flow/stop. Add `--local-only`
for target-free acceptance; use a fresh directory when changing mode. `flow`
requires an unused scenario: it issues associations, proves nonce reuse rejection,
loses one post-commit ACK, reopens persistent stores and verifies exact revocation.
Stop retains all state and logs. Start reuses identities, chain and acceptance;
it does not repeat issuance. Clean refuses live owned processes and removes only
the explicit stopped run. Never use an operator's KERI directory as a run root.
One controller operates a run at a time; there is no concurrent controller API.

Prepare defaults to six real native witness identities/listeners in one HIO
process. Issuance uses the first witness, matching the maintained credential
profile. `--witness-count 1` is the automated qualification topology. Six available
witnesses do not establish a six-witness credential qualification.

The run manifest records ports, public identities, source revision/content hash,
wheel hash and selected interpreter. Run-owned directories contain native issuer,
witness, receiver and Verifier stores, Anvil state, public CESR/JSON credentials,
source snapshots, wheels and append-only service logs. Source snapshots use Git's
tracked/unignored inventory, omit Git internals and ignored data, and reject
symlinks. Private keys remain inside native stores; the two numbered wallet keys
are public local test constants. Only loopback Anvil URLs are supported.

For a local candidate use `--verifier-source PATH` during preparation. For an
already built wheel supply `--verifier-wheel FILE --tool-revision REVISION` with
its matching tooling source. Those inputs are fixed for the lifetime of a run.
The installed-wheel suite uses this same interface outside the source checkout.

## Fixture boundary

```sh
python -m scripts.integration.env issue --run-dir RUN --wallet 1 --nonce fresh_nonce
python -m scripts.integration.env present --run-dir RUN --said SAID
python -m scripts.integration.env revoke --run-dir RUN --said SAID
```

Issue/revoke open native issuer contexts, wait for witnessed completion, export
exact bytes under `credentials/`, close the contexts, and return a JSON descriptor
on stdout. Progress goes to stderr. Present sends source-chain and credential
bytes to the public CESR endpoint. Neither operation writes application acceptance
records. Nonces are passed unchanged; issuance permits reuse so Verifier policy
can reject it during acceptance.

A caller owning the full stack can start this fixture with `--rpc-url URL
--webhook-url URL --webhook-aid AID --peer-kel FILE`. The caller owns that chain
and receiver; this mode starts neither Anvil nor the focused receipt fixture.
Repeat the original options on restart. Configuration changes require a new run.

The modules keep CLI dispatch, artifact/build selection, process lifetimes,
native infrastructure, issuer ceremonies and scenario assertions separate. Native
Habery/Regery contexts and Doist task ownership follow the pinned KERIpy patterns.
No tooling is included in the application wheel.
