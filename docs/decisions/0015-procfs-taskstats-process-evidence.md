# ADR-0015: Use bounded procfs evidence with optional taskstats delay evidence

- Status: Accepted
- Date: 2026-08-24

## Context

Existing process attribution is deliberately narrow: stable procfs identities
provide CPU consumption, scheduler runnable delay, and process-I/O activity.
It cannot distinguish all delayed work from likely resource consumers, and it
has no direct memory-delay evidence. Linux task delay accounting can expose
additional per-task CPU, block-I/O, swap-in, reclaim, thrashing, compaction,
and write-protect-copy delay counters through the generic-netlink `TASKSTATS`
interface. It is often disabled and access to GET requests is permission-gated.

The next slice needs richer evidence without making eBPF, privileges, a second
unbounded process walk, or a background netlink listener prerequisites. It must
also stay safe on an already stressed machine and avoid treating a zero delay
counter as proof that no delay occurred.

## Decision

Procfs remains the baseline collection path. Extend the existing bounded
process walk to retain leader RSS, RSS growth, minor/major-fault deltas, and
stable-task block-I/O delay ticks. Aggregate thread counters only when the task
identity is stable across the interval; never sum per-thread RSS.

Add an optional, bounded `TASKSTATS` GET collector using `netlink-sys` 0.9
without async features and Rustix socket timeouts. Its local codec uses checked
byte parsing only: no unsafe code, bindgen, C-layout casts, background thread,
or exit listener. Resolve the family and query by TGID, bracketing every query
with `/proc/<pid>/stat` identity checks. Version and message-length gate CPU,
block-I/O, swap-in, reclaim, thrashing, compaction, and write-protect-copy
counters against the official UAPI.

Every endpoint is bounded to the 512 lowest selected TGIDs, 20 ms send and
receive timeouts, 100 ms total taskstats time, and 1 MiB of replies. `ESRCH` is
normal process churn. Permission denial, timeout, malformed protocol, and
exhausted budgets are typed partial or unavailable states. Raise the cgroup
membership ceiling from 256 to 512 PIDs while retaining the existing cgroup,
path, read, and byte bounds; validate the resulting overhead before release.

Expose delay-accounting state separately from taskstats transport capability.
Stallhunt never enables `kernel.task_delayacct`, changes sysctls, elevates
itself, or infers an absence of delay from zero taskstats counters. Procfs is
therefore still useful on rootless, disabled, permission-denied, unsupported,
or budget-limited hosts.

For inference, taskstats is direct evidence where available but does not
replace conservative procfs fallbacks. CPU runnable delay remains schedstat
evidence, with taskstats CPU delay only as corroboration or fallback; the two
are never summed. Block-I/O taskstats delay can be corroborated or fall back to
procfs block-I/O delay. Memory delay uses taskstats components; major faults
are an explicitly low-confidence fallback. Memory components may overlap, so
the model retains their breakdown and ranks by the largest component instead of
claiming their sum is wall-clock time lost.

See the [Linux delay-accounting documentation](https://docs.kernel.org/accounting/delay-accounting.html), the [taskstats interface documentation](https://www.kernel.org/doc/html/latest/accounting/taskstats.html), and the [taskstats UAPI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/taskstats.h).

## Consequences

Positive:

- richer delay evidence can improve victim attribution while procfs remains a
  useful ordinary-user baseline;
- bounded requests and typed degradation keep collection observable and safe;
- the normalized model can retain source-specific evidence instead of merging
  incompatible counters into a misleading lost-time total.

Costs:

- generic-netlink parsing and protocol validation add collector and test
  complexity;
- taskstats results vary with kernel support, delay-accounting configuration,
  and permissions, so capability reporting and qualifiers are mandatory;
- the higher cgroup membership cap and taskstats request budget require
  controlled overhead validation before release.

## Alternatives considered

### Procfs only

Rejected: it remains the baseline, but cannot provide the planned direct memory
delay categories and has weaker block-I/O delay evidence.

### eBPF as the first source of richer attribution

Rejected: it conflicts with ADR-0003's procfs-first delivery strategy and
would make the first useful scoped roles depend on more privilege and setup.

### Enable delay accounting or elevate automatically

Rejected: changing host policy or privileges violates the tool's observational,
least-privilege model and would make collection behavior surprising.

### Unbounded taskstats queries or an event listener

Rejected: the tool needs a bounded interval snapshot, not continuous task exit
events, and unbounded netlink work would be unsafe during contention.
