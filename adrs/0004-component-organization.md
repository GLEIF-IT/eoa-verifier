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
| persistence | Durable schemas, detached reads and atomic saves of prepared records |

Component packages contain implementation modules, with minimal initializers.
The root groups components and contains no application implementation. Resource
folders are data, not components. Keep related functions/classes together; neither
one class per file nor a fixed line limit is required. Helpers stay with their
owner until a real caller justifies sharing them. No generic models/services/utils
layer or additional concurrency runtime is introduced.

Runtime may import all components. Receiving, verification, associations and
delivery may import persistence, but do not import runtime or one another.
Persistence does not import other application components. These are application
import rules, not a claim of runtime isolation: injected stores, decks and KERIpy
KERIpy evidence remain explicit shared contracts. Review component edges, leaf
responsibilities and dependency cycles when changing imports.

ServiceConfig lives in runtime/config.py; service composition and store lifetime
remain in runtime/serving.py; runtime/bootstrap.py prepares scope, schemas and
identity before task assembly. Persistent dataclasses live in
persistence/records.py. VerifierBaser binds tables and owns their lifecycle;
persistence/reading.py returns detached snapshots and persistence/writing.py
commits prepared records. Feature services choose transitions and construct events.
They are stored schemas, not a general collection of application models.

Retain one VerifierBaser and one application LMDB transaction boundary. Completion
writes results/removes pending work atomically. Acceptance and retirement each
commit association status and its immutable outbox event together. Event creation
belongs to association services; delivery sends stored bytes. KERIpy evidence
stores remain separate. Durable phase queues bridge commit gaps; the KERIpy
accepted-TEL index and its revocation record commit atomically in VerifierReger.
No completed-result or association-history scans schedule work.

Keep authentication separate from ACK policy, verification separate from
acceptance, and oracle ownership/chain publication outside this application.
Preserve the coordinator's KERIpy-state recheck after RPC waits and the existing
HIO task/store lifetime. The subsequent durable-phase refactor changes storage
without compatibility readers; the authenticated event format remains unchanged.

## Application operations

Each feature service reads detached records, decides the next phase, prepares its
records, and calls a concrete atomic save. Clock, retry, trust and outcome policy
run outside write transactions. No transaction spans KERIpy parsing or RPC. Each persistence method names one
legal transition and fixes its source/destination tables. For example,
`defer_grant` moves active to waiting, `retry_dead_grant` moves dead to waiting,
and `acknowledge_delivery` removes only the matching scheduling references.
Do not pass source/target phase strings or outcome flags to a catch-all save.
Keep the short transaction bodies explicit even when some code repeats.

Queue reads are phase-specific and do not consume work. Verification exposes
`next_verifying`, `next_waiting` and `next_pending`; its coordinator explicitly
chooses interrupted work, then a due retry, then new work. Grant replay and
delivery use the same separation of phase reads from named transitions. A dead
letter still consumes the turn: never interpret an exhausted item as permission
to start a second item. Status queries may read several named phases for one
identifier because they neither select nor advance work.
The Grant replay service commits verification enqueue and active-Grant removal
together after KERIpy replay; a rollback preserves the active Grant.

See the [five-slice implementation plan](../docs/plans/application-persistence-separation.md)
for the extraction boundaries, review links and qualification evidence.

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
preserve field order/defaults and serialization. Replaced workflow methods are
deleted rather than retained as compatibility APIs.

Introduce meaningful persistence read operations only when a concrete caller
needs them; do not add one wrapper or repository interface per table. Revisit a
shared authentication component only when another production capability uses it.
