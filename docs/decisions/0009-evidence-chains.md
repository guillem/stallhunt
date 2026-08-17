# ADR-0009: Evidence chains require independent mechanism evidence

- Status: Accepted
- Date: 2026-08-17

## Context

Milestones 1–3 already emit independent host CPU, memory, and I/O findings.
Operators still have to decide whether two findings in the same window are
related. The documented long-term model is an evidence graph, for example
memory reclaim generating storage pressure.

Co-occurrence of two PSI signals is not enough. ADR-0004 forbids presenting
correlation as certainty. A generic graph of every coincident finding would
reintroduce false causality. Waiting for eBPF would delay a path that current
collectors can already support conservatively: memory PSI, I/O PSI, and
same-window VM counters.

## Decision

An evidence chain is a **relation between existing findings**, not a new
resource verdict and not a merged bottleneck.

- Emit a chain only when a memory mechanism label (`memory_reclaim_pressure`,
  `memory_swap_pressure`, or `memory_possible_thrashing`) and an I/O pressure
  finding are both present.
- The relation vocabulary is `consistent_with`. Human and JSON output must not
  say that reclaim or swap caused the I/O stalls.
- Confidence is never `high` in this slice. Possible thrashing may reach
  `medium`; reclaim and swap remain `low`.
- Coincident memory and I/O PSI without a VM-counter mechanism does not create
  a chain. Healthy, insufficient, or missing findings on either side also do
  not.
- The chain does not map processes to devices, identify reclaim/swap I/O, or
  relate host findings to cgroup findings.
- Hunt text and hunt/replay JSON expose chains. Watch does not track chain
  identities; recordings remain observation-only and pick up chains on replay.

## Consequences

Positive:

- operators see a defensible same-window path without losing independent
  resource verdicts
- coincidence of two PSI signals stays visible as two findings, not a fake
  causal story
- later chains can reuse the same relation/confidence rules

Costs:

- the first chain covers only memory mechanism plus I/O pressure
- low/medium confidence will often be the honest answer
- watch lifecycle still treats the two resources as separate identities

## Alternatives considered

### Emit a chain whenever two resources show PSI pressure

Rejected: that equates temporal overlap with a path and violates ADR-0004.

### Merge memory and I/O into one finding when they co-occur

Rejected: each resource still has its own PSI verdict, severity, and
qualifiers. A relation must not erase those independent conclusions.

### Wait for eBPF before any multi-resource relation

Rejected: PSI plus VM counters already support a conservative
`consistent_with` claim. eBPF remains the way to raise confidence or prove a
device/process path, not a prerequisite for mentioning the path at all.
