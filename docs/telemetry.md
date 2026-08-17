# Linux telemetry design

## Principle

Collect the least expensive evidence that answers the diagnostic question.

The first implementation should use kernel/user-space interfaces that are already exposed as files or counters. eBPF is a later precision instrument, not the foundation of the MVP.

## Initial telemetry matrix

| Area | Source | Scope | Early priority | Purpose |
|---|---|---:|---:|---|
| CPU pressure | `/proc/pressure/cpu` | host | P0 | direct contention/stall signal |
| Memory pressure | `/proc/pressure/memory` | host | P1 | direct reclaim/thrash pressure signal |
| I/O pressure | `/proc/pressure/io` | host | P1 | direct I/O stall signal |
| CPU counters | `/proc/stat` | host | P0 | utilization/context and interval CPU capacity |
| Load | `/proc/loadavg` | host | P0 | runnable/uninterruptible queue context |
| Process CPU/state | `/proc/<pid>/stat` | process | P0 | consumption, state, identity start time |
| Process status | `/proc/<pid>/status` | process | P0/P1 | metadata/context switches/memory metadata |
| Scheduler accounting | `/proc/<pid>/schedstat` | process | P0 if available | runtime/runnable delay |
| Process I/O | `/proc/<pid>/io` | process | P1 | I/O attribution |
| Disk counters | `/proc/diskstats` | device | P1 | device-level activity/queue context |
| Memory | `/proc/meminfo` | host | P1 | occupancy/reclaim/swap context |
| VM counters | `/proc/vmstat` | host | P1 | reclaim, swap, fault context |
| cgroups | discovered cgroup2 mount | cgroup | P1/P2 | bounded service/container grouping |

Priority:
- P0: CPU vertical slice
- P1: first broad release
- P2: later enhancement

## PSI

Pressure Stall Information is central because it measures time during which tasks are delayed due to resource contention.

For each PSI resource, parse:

```text
some avg10=... avg60=... avg300=... total=...
full avg10=... avg60=... avg300=... total=...
```

Host-level CPU PSI has a special case: Linux defines CPU `some`, but CPU
`full` is undefined and may be exposed as a compatibility-only zero line. The
CPU collector recognizes at most one optional `full` line but deliberately
ignores its fields, so compatibility data cannot invalidate usable `some`
evidence. It does not include `full` in observations, interval calculations, or
conclusions.

Important design point:

For a bounded `hunt`, prefer calculating pressure over the **actual observation interval** using changes in `total`, rather than relying only on rolling `avg10`/`avg60`/`avg300`.

The rolling averages are still useful context.

### Interpretation

- `some`: at least one task is stalled on the resource.
- `full`: all non-idle tasks are stalled simultaneously, where defined by PSI semantics; this must not be interpreted for host-level CPU PSI.

Do not make raw PSI thresholds universal truths.

Severity should consider:

- fraction of observed time,
- duration,
- number/type of victims,
- corroborating metrics.

### Implemented host-memory collection

M2 reads `/proc/pressure/memory` with a mandatory `some` line and optional
`full` line. It rejects malformed endpoint records, then normalizes each
cumulative total over the completed monotonic memory-PSI interval. Valid `some`
is retained when an otherwise valid `full` interval is missing, regresses,
exceeds elapsed time, or exceeds `some`; those cases are explicit full-state
qualifiers. `full` is a subset of `some` and is never added to it.

The same bounded hunt performs one requested sleep between start and end reads.
Memory PSI, CPU PSI, CPU/process, and memory context are collected
sequentially, so each pair has an independent measured interval rather than an
atomic shared snapshot. M6 `watch` reuses the previous end endpoint as the next
window start so rolling PSI totals stay contiguous and collection is not
doubled.

## `/proc/stat`

Collect at least:

- CPU time counters,
- context switches if useful,
- process creation count if useful.

Normalize CPU time over the observation window.

The aggregate guest and guest_nice counters must not be added again because
Linux already includes them in user and nice. Linux also documents iowait as
unreliable and capable of decreasing; interval idle time should therefore be
derived from aggregate total minus busy deltas rather than treating a declining
iowait counter as a collector failure.

CPU utilization contextualizes a CPU contention finding but does not create one by itself.

## `/proc/loadavg`

Use cautiously.

Load average is context, not a bottleneck verdict.

The instantaneous runnable/total task field may be useful for the CPU slice.

Do not interpret load average without CPU count.

Load collection is best effort. An unreadable or malformed `/proc/loadavg` is
explicit context loss, not a reason to discard otherwise valid CPU counters.

## `/proc/<pid>/stat`

Fields of interest may include:

- PID,
- comm,
- state,
- PPID,
- minor/major faults,
- user time,
- system time,
- priority/nice,
- thread count,
- start time,
- processor,
- delayacct block I/O ticks where appropriate.

Parsing must correctly handle `comm` enclosed in parentheses, including spaces and unusual characters.

Do not parse by naive whitespace splitting from the beginning of the line.

PID reuse protection should use `starttime`.

For the initial collector, enumerate numeric `/proc` entries once per snapshot,
retain only the lowest 4,096 PIDs with bounded heap storage, and read only
`stat`. Missing entries after enumeration, permission-denied or unreadable
reads, directory iteration errors, malformed entries, and hitting the cap are
retained as collection qualifiers. Only matching `(pid, starttime)` pairs
produce process CPU deltas; appearing, exiting, or reused PIDs do not.

## `/proc/<pid>/schedstat`

Scheduler accounting is task/thread-scoped. The schedstats sysctl is not used
as a capability gate: it does not reliably control this per-task interface.
The collector probes the `schedstat` files directly and reads
`/proc/<tgid>/task/<tid>/stat` and `schedstat`, preserving task identity as
`(tid,starttime)` and comparing only identities stable at both endpoints.

The existing 4,096-PID selection remains in force. Across those processes,
task samples are globally capped at 16,384 per endpoint; selection is
deterministic by selected PID then lowest TID. Each successful sample brackets
one `schedstat` read with two task `stat` reads so TID reuse during collection
cannot fabricate identity-bound counters. Endpoint matching excludes tasks
that appeared, exited, or reused a TID. Process delay is a checked sum of
stable-thread deltas, so it may exceed wall-clock time. Enumeration/read
issues and cap truncation remain qualifiers. Tasks whose full lifetime occurs
between snapshots remain unobservable. Direct task reads are authoritative.
This is raw scheduler evidence, not a severity, victim, suspect, or causal
conclusion.

Expected concepts include:

- time executing on CPU,
- time waiting on run queue,
- scheduler timeslice count.

Kernel/configuration behavior varies; capability discovery and fixture coverage are required.

A CPU diagnosis can be useful without this source, but victim attribution confidence should be lower.

## `/proc/<pid>/io`

Potential values:

- `rchar`,
- `wchar`,
- `syscr`,
- `syscw`,
- `read_bytes`,
- `write_bytes`,
- `cancelled_write_bytes`.

Distinguish logical I/O from storage-layer accounting. `read_bytes` counts
storage-layer reads; `write_bytes` is charged at page-dirtying time and does not
prove writeout. `cancelled_write_bytes` records dirty-byte cancellation and may
refer to bytes charged to another task, so it is not a safe per-process net
subtraction. `rchar`/`wchar` are logical syscall-oriented context.

Permissions may prevent access to other users' processes.

## `/proc/meminfo`

Values of interest may include:

- MemTotal,
- MemAvailable,
- SwapTotal,
- SwapFree,
- Dirty,
- Writeback,
- Slab-related values.

Memory occupancy alone is not a finding.

Use this data to explain pressure findings and rule out simplistic interpretations.
M2 retains end gauges for occupancy and swap-allocation context only; they
cannot create or override a memory-pressure verdict.

## `/proc/vmstat`

Potentially important counters:

- page faults,
- major faults,
- swap in/out,
- scan/reclaim activity,
- steal-related/reclaim counters as kernel exposes them,
- dirty/writeback context.

Choose only counters that support explicit memory/I/O hypotheses.

M2 retains bounded deltas for faults, `pswpin`/`pswpout`, direct and kswapd
scan/steal counters. A direct scan plus direct steal conjunction can classify
correlated reclaim context; positive swap-in can classify correlated active
swap context. These mechanism labels carry confidence separately from the
PSI-backed pressure verdict. Background kswapd activity and swap-out without
swap-in remain qualifiers. These are host-wide counters, not process
attribution, and page counts remain pages rather than being presented as bytes
without a page-size contract. Rates use the independent vmstat interval, never
the PSI interval.

## `/proc/diskstats`

### Implemented M3 block-I/O collection

M3 parses `/proc/pressure/io` with `some` as the exact-interval verdict source
and optional `full` as separately-qualified, non-additive subset context.
Diskstats input is byte-bounded to 1 MiB and retains at most 4,096 major/minor
devices per endpoint. A name change for a reused major/minor is rejected as
lifecycle churn; same-name reattachment remains indistinguishable. Its
sectors retain the kernel's raw 512-byte unit; `in_flight` is an end gauge, while
busy and weighted I/O times retain their distinct kernel semantics. Each counter
delta is independently omitted on reset instead of fabricating a zero or
discarding unrelated fields.

Process I/O is bounded to 1,024 lowest PIDs per endpoint and reads
`stat` → `io` → `stat` for stable identity, at most 3,072 reads per endpoint.
`read_bytes` records storage-layer reads. `write_bytes` is charged when pages
are dirtied and does not prove writeout; `cancelled_write_bytes` is retained
separately because a truncating task can cancel dirty bytes charged to another
task. `rchar`/`wchar` remain distinct logical-I/O context. Device and process
data are same-window accounting activity only, not backing-device attribution.
Process-I/O attribution is disabled on 32-bit targets because the kernel
documents that these 64-bit proc counters may tear there; an upward torn read
could otherwise fabricate a dominant candidate.

Use device major/minor identity.

Derive interval quantities such as:

- reads completed,
- writes completed,
- sectors transferred,
- time spent doing I/O,
- weighted I/O time,
- in-flight I/O at snapshot.

Beware:

- device mapper,
- partitions vs whole devices,
- NVMe semantics,
- layered storage,
- filesystems hiding application-to-device causality.

Device-level saturation can be high confidence while process attribution remains lower confidence.

## Cgroup v2

M4 implements ADR-0006 with cgroup v2 only: it locates the mount from
`/proc/self/mountinfo`, uses the unified `0::` record from
`/proc/<pid>/cgroup`, and validates membership as `stat` → cgroup → `stat`.
It selects at most 256 PIDs and retains at most 512 mapped cgroups including
ancestors; it never recursively scans an arbitrary tree. Path/depth, file,
snapshot-byte, and read-attempt limits are explicit. Caps, namespace
visibility, permissions, controller absence, movement, and parse errors are
typed qualifiers and make cgroup context partial.

For retained cgroups, it collects best-effort:

- CPU statistics,
- memory events/current,
- selected `memory.stat` page counters (`pgscan_direct`, `pgsteal_direct`,
  `pswpin`, `pswpout`),
- I/O statistics,
- PSI files where available.

Exact per-cgroup PSI `some` establishes a verdict for that scope only. `full`
remains non-additive subset context, while `cpu.stat`, memory, and I/O
controller deltas explain a scoped finding without creating it. A positive
`memory.events` `high` or `max` delta, or positive `memory.stat` direct-reclaim
or swap-in deltas, can independently support a same-cgroup `consistent_with`
relation to that cgroup's I/O pressure; they still do not create a memory
verdict or a host/cgroup link. Membership and
counters cannot establish cross-cgroup causality. Recognizable systemd-looking
path components may produce an explicitly inferred unit candidate; no D-Bus,
libsystemd, or manager is required.

Benefits:

- systemd service attribution,
- containers,
- stable grouping across process churn.

The MVP need not fully resolve container runtime metadata.

## Collection consistency

A full snapshot cannot be perfectly atomic.

Record per-collector or per-snapshot monotonic timestamps.

M1.3 timestamps each completed PSI and CPU/process snapshot separately and
normalizes each counter pair over its own elapsed interval. The snapshots are
sequential, so there is bounded collection skew; no equivalence stronger than
concurrent observation context is claimed.

For initial polling, acceptable skew should be documented and bounded.

If skew becomes diagnostically significant, run independent collectors concurrently or adjust the architecture.

## Process enumeration

Expected race:

1. enumerate `/proc`,
2. PID exits,
3. subsequent file open fails.

This is normal.

Treat process disappearance as a normal condition, not an error worth surfacing to the user unless loss is widespread enough to reduce confidence.

## Overhead strategy

Avoid reading every expensive per-process file at high frequency.

Possible staged collection:

1. enumerate process identity and CPU counters cheaply,
2. rank relevant processes,
3. read richer scheduler/I/O data for a bounded candidate set.

However, do not optimize prematurely if simple full sampling is already cheap enough on realistic hosts.

Measure before complicating.

## Future event telemetry

Potential eBPF/tracepoint additions:

### CPU

- wakeup-to-run latency,
- run queue latency histograms,
- scheduler migration,
- steal/IRQ context where useful.

### Off-CPU

- blocked duration,
- kernel/user stack at blocking point,
- blocking syscall category.

### Locks

- futex waits,
- mutex contention where observable.

### Block I/O

- request latency,
- queue/service split,
- process/cgroup attribution.

### Network

- retransmits,
- socket queue delay,
- connection-level blocking.

Each addition requires a diagnostic use case and an ADR if it materially changes deployment/privilege architecture.

## Capability report

The tool should eventually offer a diagnostics command such as:

```bash
bottleneck capabilities
```

Example:

```text
CPU PSI                  yes
Memory PSI               yes
I/O PSI                  yes
Per-process schedstat    yes
Per-process I/O          partial (permission-limited)
cgroup v2                yes / partial / unavailable
eBPF tracing             unavailable (not required)
```

Capability reporting is important for trustworthy negative findings.
