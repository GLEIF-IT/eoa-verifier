# ADR 0004: Organize code into sibling responsibility-based components

Status: Accepted
Date: 2026-10-30

## Context

Intake and verification already had packages, while runtime, storage, association
lifecycle and delivery modules shared the root namespace. The application remains
small enough for one process and one application LMDB environment. Navigation and
ownership need clearer boundaries without changing persistence or protocol behavior.

## Decision

Keep the src layout and six sibling leaf component packages:

| Component | Owns |
| --- | --- |
| runtime | CLI, validated ServiceConfig, service composition and resource lifetime |
| receiving | CESR HTTP intake, shared parser/escrows, Grant replay and enqueue |
| verification | Initial credential-chain, wallet-proof and account checks, including RPC |
| associations | Acceptance, retirement and public stored-status projection |
| delivery | HTTP authentication, nonce claims, webhook attempts, retries and ACK policy |
| persistence | Durable record schemas and atomic application transitions |

Component packages contain implementation modules, with minimal initializers.
The root groups components and contains no application implementation. Resource
folders are data, not components. Keep related functions/classes together; neither
one class per file nor a fixed line limit is required. Helpers stay with their
owner until a real caller justifies sharing them. No generic models/services/utils
layer or additional concurrency runtime is introduced.

Runtime may import all components. Receiving, verification, associations and
delivery may import persistence, but do not import runtime or one another.
Persistence does not import other application components. These are application
import rules, not a claim of runtime isolation: injected stores, decks and native
KERIpy evidence remain explicit shared contracts. Review component edges, leaf
responsibilities and dependency cycles when changing imports.

ServiceConfig lives in runtime/config.py; service composition and store lifetime
remain together in runtime/serving.py. Persistent dataclasses live in
persistence/records.py; table setup and transitions stay in persistence/basing.py.
They are stored schemas, not a general collection of application models.

Retain one VerifierBaser and one application LMDB transaction boundary. Completion
writes results/removes pending work atomically. Acceptance and retirement each
commit association status and its immutable outbox event together. Event creation
stays beside these transitions; delivery sends stored bytes. KERIpy evidence
stores remain separate, with bounded recovery scans bridging commit gaps.

Keep authentication separate from ACK policy, verification separate from
acceptance, and oracle ownership/chain publication outside this application.
Preserve the coordinator's native-state recheck after RPC waits and the existing
HIO task/store lifetime. Table names, record fields and wire formats do not change.

## Import migration

This pre-1.0 reorganization moves Python import paths; the installed
`eoa-verifier` command and options retain their behavior. Update embedding code:

| Previous import module | Current import module |
| --- | --- |
| eoa_verifier.cli | eoa_verifier.runtime.cli |
| eoa_verifier.serving (ServiceConfig) | eoa_verifier.runtime.config |
| eoa_verifier.serving (VerifierService/run_service) | eoa_verifier.runtime.serving |
| eoa_verifier.basing (record dataclasses) | eoa_verifier.persistence.records |
| eoa_verifier.basing (VerifierBaser) | eoa_verifier.persistence.basing |
| eoa_verifier.accepting/retiring/statusing | eoa_verifier.associations.accepting/retiring/statusing |
| eoa_verifier.authing/delivering | eoa_verifier.delivery.authing/delivering |
| eoa_verifier.rpc | eoa_verifier.verification.rpc |

No compatibility implementation is left at the root. Existing receiving and
verification module paths and packaged schema resource paths remain available.
Tests, operator examples and the console entry point use the current paths.
After updating an existing editable checkout, reinstall it with
`python -m pip install --no-deps -e .` to regenerate the console script: editable
source changes alone do not update installed entry-point metadata.

## Validation and future changes

Organize tests by production component, with named shared support and integration
scenarios in their own packages. Use pytest importlib mode and preserve the
witnessed KERI/IPEX/Anvil integration topology.
Run affected contract tests, then the full suite against a built wheel outside
the checkout, including CLI help and packaged schemas. Record extraction must
preserve field order/defaults and serialization, and moves must preserve methods.

Introduce meaningful persistence read operations only when a concrete caller
needs them; do not add one wrapper or repository interface per table. Revisit a
shared authentication component only when another production capability uses it.
