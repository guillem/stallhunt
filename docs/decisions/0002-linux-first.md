# ADR-0002: Linux-first rather than cross-platform-first

- Status: Accepted
- Date: 2026-08-17

## Context

The core value depends on operating-system-specific evidence about:

- scheduler pressure,
- process accounting,
- memory reclaim,
- block I/O,
- cgroups,
- future eBPF/tracepoints.

A portability-first design would either hide useful Linux semantics or multiply project scope before the diagnostic model is proven.

## Decision

Build a Linux-first implementation.

Do not promise macOS, Windows or BSD support during the initial milestones.

Keep platform-specific collection separated from normalized analysis where reasonable, but do not reduce Linux-specific semantics to a lowest common denominator.

## Consequences

Positive:

- access to PSI,
- cgroup v2,
- rich procfs/sysfs telemetry,
- future eBPF path,
- smaller scope,
- stronger diagnoses.

Costs:

- reduced initial audience,
- some normalized concepts may remain Linux-specific,
- later ports may require new analyzers rather than just collectors.

## Alternatives considered

### Cross-platform abstraction from day one

Rejected because it would optimize for hypothetical portability over diagnostic quality.

### eBPF-only Linux tool

Rejected separately by ADR-0003 because it would impose unnecessary complexity and privileges on the MVP.
