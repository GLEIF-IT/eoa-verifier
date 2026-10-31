# ADR 0003: Use HIO structured concurrency

Status: Accepted
Date: 2026-10-22

## Context

KERI intake, escrow processing and HTTP clients already use HIO. The
verifier needs one coordinated runtime with explicit task and resource ownership.

## Decision

Embrace HIO as eoa-verifier's structured concurrency runtime. Compose service
work as Doers under one Doist; use DoDoers to own child tasks and their lifetimes.
Network waits and retries yield to the scheduler so intake and escrows keep moving.

Use HIO HTTP clients and servers. Each component owns and closes its
clients; service composition owns KERIpy stores and unwinds them on shutdown or
setup failure. Assign one scheduling owner to each parser and escrow processor.
Do not introduce a parallel asyncio, thread-pool or background-task runtime for
service work without revisiting this decision.

## Consequences

New delivery and status work must fit this runtime. Tests exercise real HIO
scheduling and cleanup. Blocking I/O, sleeps and unbounded work inside a Doer
would stall the service and must be replaced by yielding operations or bounded
scheduler turns.
