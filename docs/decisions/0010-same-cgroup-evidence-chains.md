# ADR-0010: Same-cgroup evidence chains stay on one path

- Status: Accepted
- Date: 2026-08-17
- Extended by: ADR-0011, which additionally permits selected `memory.stat`
  direct-reclaim and swap-in deltas as the independent mechanism gate

## Context

ADR-0009 added a host-only `consistent_with` relation when a memory mechanism
label and I/O pressure coexist. Operators on service/container hosts still see
independent per-cgroup memory and I/O findings and have to guess whether those
two scoped verdicts are related.

Coincident PSI in the same cgroup is still not a path. Parent and child cgroups
overlap, and host PSI is a different scope from cgroup PSI. Linking those
scopes would reintroduce the false causality ADR-0004 and ADR-0009 rejected.

The M4 collector already stores per-cgroup PSI plus `memory.events` high/max
deltas. Those limit-reclaim counts are independent of I/O PSI. They are not
host `pgscan`/`pswpin` proof and may include descendant activity.

## Decision

A second evidence-chain kind, `cgroup_memory_consistent_with_io`, may relate
already-produced findings when all of the following hold:

- both findings are `pressure` verdicts,
- both findings share the same cgroup path,
- one finding is memory and the other is I/O,
- that memory finding has a positive `memory.events` `high` or `max` delta.

ADR-0011 later extends the final gate with selected `memory.stat` page deltas.
The same-path, pressure-verdict, confidence, output, and non-causality rules in
this ADR remain in force.

The relation vocabulary remains `consistent_with`. Confidence is always `low`
and never `high`. Hunt text and hunt/replay JSON expose these chains beside the
host chain. Watch still does not track chain identities.

The chain must not:

- form from coincident cgroup PSI without a high/max event delta or the
  additional independent mechanism evidence accepted by ADR-0011,
- link a host finding to a cgroup finding,
- link two different cgroup paths, including ancestor and child,
- relate CPU pressure to I/O pressure,
- map processes to devices or identify reclaim I/O,
- become a merged resource verdict.

At most 16 same-cgroup chains are emitted, ordered by PSI severity then path.

## Consequences

Positive:

- a service/container scope can show a defensible memory-plus-I/O path without
  collapsing the two findings
- host and cgroup remain separate evidence graphs
- later chains can reuse the same same-scope rule

Costs:

- cgroups without `memory.high`/`memory.max` activity will not chain even when
  both PSI files are elevated
- `memory.events` may count descendant reclaim, so same-path is still not
  exclusive ownership
- confidence stays low until stronger per-cgroup reclaim/swap telemetry exists

## Alternatives considered

### Chain any same-cgroup memory PSI with I/O PSI

Rejected: that is coincident PSI with a narrower window and still violates
ADR-0004 and ADR-0009.

### Link host memory mechanism findings to cgroup I/O findings

Rejected: host and cgroup PSI answer different questions. Overlap is not
evidence that the host reclaim path is that cgroup's I/O.

### Collect `memory.stat` pgscan/pswpin before any cgroup chain

Rejected for this slice. Existing `memory.events` high/max deltas already
provide an independent limit-reclaim signal. Page-level cgroup VM counters can
raise confidence later without being a prerequisite for mentioning the path.

### Treat ancestor/child pairs as the same scope

Rejected: overlapping hierarchy is already a cgroup qualifier. A relation must
stay on one path.
