# ADR-0011: Same-cgroup chains may use memory.stat page deltas

- Status: Accepted
- Date: 2026-08-17

## Context

ADR-0010 related same-cgroup memory and I/O pressure only when `memory.events`
high or max increased. That is a limit-reclaim signal. Many cgroups never hit
`memory.high` or `memory.max`, so the chain would not fire even when
`memory.stat` showed direct reclaim or swap-in in the same window.

ADR-0010 rejected collecting `memory.stat` as a prerequisite for mentioning
the path. The page counters are now justified because they close that
false-negative gap with independent mechanism evidence already exposed by
cgroup v2. They are the scoped analogue of host `pgscan_direct` /
`pgsteal_direct` / `pswpin`.

Coincident PSI remains insufficient. Host findings are still not linked to
cgroup findings.

## Decision

A same-cgroup `consistent_with` chain may form when memory and I/O pressure
share one path and **any** of these independent mechanisms is present:

- a positive `memory.events` `high` or `max` delta,
- positive `memory.stat` `pgscan_direct` **and** `pgsteal_direct` deltas,
- a positive `memory.stat` `pswpin` delta.

Unknown `memory.stat` keys are ignored. Background kswapd aggregates are not
collected. Confidence remains `low` and never `high`. The relation is still
not causal, not a merged verdict, not a host–cgroup link, and not a watch
identity.

Recordings store the selected `memory.stat` deltas additively. A missing field
on an older schema-1 recording is treated as unavailable.

## Consequences

Positive:

- cgroups without memory limits can still show a defensible memory-plus-I/O
  path when page-level reclaim or swap-in occurred
- the gate stays aligned with the host VM-counter rule

Costs:

- one additional bounded file read per retained cgroup
- `memory.stat` is hierarchical and may include descendant activity
- kernels without the selected keys still depend on `memory.events`

## Alternatives considered

### Keep high/max as the only cgroup mechanism

Rejected: it systematically misses reclaim on unlimited cgroups.

### Treat aggregate `pgscan`/`pgsteal` as sufficient

Rejected: those include kswapd background reclaim. Direct scan and steal match
the host mechanism conjunction.

### Raise confidence to medium because page counters exist

Rejected for this slice. Same-window cgroup counters remain correlation. Host
reclaim and swap labels are also low confidence.
