# ADR-0006: Use bounded cgroup-v2 scoped attribution

- Status: Accepted
- Date: 2026-08-17

## Context

M4 must group existing host CPU, memory, and I/O observations by services,
containers, and workloads. A cgroup hierarchy may be large, mutable, partially
visible in a namespace, or only partly readable. Walking an arbitrary tree
would add observer cost and make an unbounded hierarchy an input hazard.

Membership or per-cgroup activity cannot prove that one cgroup caused another
cgroup to stall. cgroup v2 has a unified hierarchy and per-cgroup PSI, but
controller availability and permissions vary by mount and cgroup.

## Decision

M4 supports **cgroup v2 only**. Discover the cgroup2 mount from
`/proc/self/mountinfo` and unified membership from the `0::` line in
`/proc/self/cgroup`; do not assume `/sys/fs/cgroup` is correct in every mount
namespace.

Collection starts from a bounded selected process set. It maps each process by
`stat` → `/proc/<pid>/cgroup` → `stat`, retaining membership only when PID and
start-time identity remain stable. Read mapped cgroups and ancestors, not a
recursive arbitrary tree.

The first implementation budgets at most 1,024 PID membership checks and 2,048
distinct mapped cgroups including ancestors per endpoint, plus explicit
normalized path-depth, path-byte, and individual cgroup-file-byte bounds.
Selection is deterministic; caps, read/parse failures, disappearance, identity
changes, and permission limits become qualifiers.

Exact per-cgroup PSI is a verdict only about that **cgroup scope**. `cpu.stat`,
memory, and I/O controller files are resource context, not independent pressure
verdicts. Host findings remain host-scoped; membership and same-window activity
never establish cross-cgroup causality.

Systemd metadata is optional presentation context. A recognizable `.service`,
`.scope`, or `.slice` path component may yield an explicitly inferred unit
candidate. No D-Bus, libsystemd, running systemd manager, or systemd-specific
hierarchy is required.

Pre-1.0 JSON gains additive cgroup fields and explicit capability/collection
qualifiers. Missing mount visibility, controllers, permissions, or files
degrade only cgroup context and cannot erase a valid host PSI verdict.

## Consequences

Positive:

- useful service/container grouping without eBPF, D-Bus, or a full-tree scan;
- bounded membership-first collection suits stressed and multi-tenant hosts;
- scoped PSI distinguishes local from host-wide observations;
- partial visibility remains explainable.

Costs:

- cgroup v1 and arbitrary tree discovery are unsupported;
- short-lived or moved processes are omitted rather than attributed unsafely;
- caps can leave scope incomplete;
- path-derived systemd metadata is a candidate, not authoritative;
- coarse counters cannot establish process-to-cgroup or cross-cgroup causality.

## Alternatives considered

### Recursively scan every cgroup

Rejected: size, depth, permissions, and churn are unbounded, and a full scan is
not needed to contextualize the bounded processes selected by a hunt.

### Support cgroup v1 and v2 together

Rejected for M4: v1 controller-specific hierarchies would complicate scope
identity before v2 attribution is proven.

### Resolve systemd units through D-Bus or libsystemd

Rejected: this adds runtime and permission dependencies. Explicitly limited
path-derived candidates provide context first.

### Treat cgroup activity as causal attribution

Rejected under ADR-0004: membership, PSI, and coarse counters cannot show that
one cgroup caused another cgroup's delay.
