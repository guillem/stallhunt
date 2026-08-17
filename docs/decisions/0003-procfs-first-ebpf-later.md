# ADR-0003: Use simple Linux telemetry first; add eBPF later

- Status: Accepted
- Date: 2026-08-17

## Context

eBPF can provide excellent scheduler, off-CPU, lock, block-I/O and network attribution.

However, making eBPF foundational would introduce:

- kernel/toolchain complexity,
- privilege/capability concerns,
- deployment compatibility issues,
- verifier/debugging work,
- higher implementation scope.

Linux already exposes strong first-order evidence through PSI, procfs, sysfs and cgroups.

The project's unproven innovation is the **inference model**, not data collection.

## Decision

The first useful release must not require eBPF.

Start with:

- PSI,
- `/proc`,
- `/sys`,
- cgroup v2,
- existing kernel accounting interfaces.

Add eBPF only to answer concrete diagnostic questions that simpler telemetry cannot answer with sufficient confidence.

## Consequences

Positive:

- faster path to useful output,
- easier installation,
- lower privilege requirements,
- simpler testing,
- clearer validation of inference design.

Costs:

- weaker causal attribution in early releases,
- lower temporal resolution,
- some victims/suspects can only be identified heuristically.

This cost must be visible through confidence and qualifiers rather than hidden.

## Future decision

Before introducing an eBPF framework, create an ADR evaluating current options at that time, including Rust-native tooling such as Aya and libbpf-based approaches.
