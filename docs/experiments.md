# Experiments and validation log

This document is for **durable experimental conclusions**, not routine command transcripts.

Use it to record controlled tests that establish or challenge diagnostic behavior.

## Why keep this in Git?

The inference engine will contain heuristics and thresholds whose validity must be established empirically.

A later developer or coding agent should be able to answer:

- Why is this threshold here?
- Which kernels/machines were tested?
- What workload generated this finding?
- Which false positives have been observed?
- How much overhead did collection add?

Git history will preserve evolution; this file preserves current durable conclusions and links to fixture/test names.

## Experiment template

Copy this section for a meaningful experiment.

```markdown
## EXP-NNNN: Short title

Date:
Commit:
Host/kernel:
CPU:
Memory:
Storage:
Container/cgroup setup:
Relevant privileges/config:

### Question

What are we trying to determine?

### Setup

Exact workload shape and important commands/configuration.

### Expected behavior

What should the tool conclude, and why?

### Observed telemetry

Only the values needed to support the conclusion.

### Tool finding

What did Bottleneck Finder report?

### Result

Pass / fail / ambiguous.

### Conclusion

What durable design conclusion follows?

### Follow-up

Tests, threshold changes, missing telemetry, or open questions.
```

## Planned CPU experiments

### CPU-1: idle/healthy

Goal:

Ensure low CPU activity produces no contention finding.

### CPU-2: busy but not meaningfully pressured

Goal:

Demonstrate that high utilization alone does not necessarily trigger a severe finding.

Exact workload will depend on CPU topology and scheduler behavior.

### CPU-3: oversubscribed CPU

Setup concept:

- determine available logical CPUs,
- run more CPU-bound workers than CPUs,
- observe sustained CPU PSI,
- include at least one identifiable victim process.

Expected:

- CPU contention found,
- elevated severity,
- major CPU consumers appear as suspects,
- schedstat-capable victims show runnable delay.

### CPU-4: missing schedstat

Goal:

Verify CPU resource diagnosis remains possible while victim attribution confidence decreases.

### CPU-5: short transient spike

Goal:

Determine how observation duration and transient PSI should affect severity/confidence.

## Planned memory experiments

- high cache/occupancy with negligible pressure,
- constrained cgroup with reclaim pressure,
- swap pressure if safe and reproducible,
- memory churn/thrashing scenario.

## EXP-0003: M2 healthy-host memory smoke

Date: 2026-08-17. The M2 deterministic fixture and executable healthy-host
smoke paths passed with readable memory PSI. This validates parsing, independent
bounded intervals, JSON/text degradation, and the conservative no-harmful-
pressure path on that host. It is not a controlled harmful-memory-pressure
experiment: no reclaim, swap-pressure, or possible-thrashing conclusion is
validated by it. The required follow-up is a safe, bounded controlled scenario
that produces exact memory PSI `some` with relevant reclaim and/or swap context.

## EXP-0005: M2 harmful-memory validation prerequisite check

Date: 2026-08-17. Host/kernel: Linux 7.1.5.

### Question

Can this session safely create controlled harmful memory pressure without
affecting an arbitrary host cgroup?

### Setup

The caller's unified membership was
`/user.slice/user-1000.slice/user@1000.service/app.slice/app-org.chromium.Chromium-334038.scope`.
The unified hierarchy exposed the `memory` controller and zram swap, and
`stress-ng` was installed. Memory PSI, meminfo, and vmstat were readable.
However, neither the current cgroup's `cgroup.procs` nor
`cgroup.subtree_control` was writable, so the session could not create or move
work into a uniquely owned memory-limited subtree.

A safe one-second `hunt --json` smoke observed memory PSI `some` of 0% over
1,209,764 µs and produced `memory_no_harmful_pressure` with available memory
telemetry. This is healthy-path evidence only.

### Result

Blocked safely. Running an unconstrained `stress-ng --vm` workload would put
the shared host/container under pressure and cannot validate the M2 acceptance
criterion safely.

### Follow-up

Run a bounded allocator/reclaim workload inside a caller-provided writable,
uniquely owned delegated cgroup with an explicit memory limit. Assert an exact
memory PSI `some` finding; retain `full`, meminfo, and vmstat as non-additive
context only.

## Planned I/O experiments

Do not run destructive tests against arbitrary real devices.

Prefer:

- disposable test files,
- controlled filesystem,
- cgroup limits where useful,
- bounded workload durations.

Cases:

- high sequential throughput without severe stalls,
- competing readers/writers with measurable I/O PSI,
- process attribution incomplete due to permissions.

## EXP-0004: M3 healthy-host and controlled competing-I/O validation

Date: 2026-08-17. M3 deterministic fixtures and an executable healthy-host
smoke validate parser/interval/output paths and the conservative
high-activity-with-low-PSI no-contention behavior. The live smoke had all I/O
capabilities available, six stable disk devices, and four stable process-I/O
intervals.

`cargo test --locked --offline --test io_acceptance -- --ignored --nocapture`
then ran without skipping on Linux 7.1.5. It owned exactly two `stress-ng` HDD
workers, 64 MiB each, using direct, sync, and fsync I/O in a
checkout-local temporary path. The coordinator was bounded to eight seconds;
the hunt ran for two seconds. It found `io_pressure` with PSI `some`
0.13602988901958982 (13.6029889%), PSI window 2,002,876 us, diskstats window
2,000,947 us, and process-I/O window 2,000,534 us; it ranked three device
candidates and two process suspects. The workload remained alive after the
measurement and owned cleanup passed.

This establishes the M3 controlled PSI/resource and qualified-candidate exit.
It does not validate I/O victims, a process-to-device mapping, or causality.
The release baseline short run reported wall 1.00s, max RSS 2592 KiB, PSI skew
1.231 ms, and user/system time displayed as 0.00s; high-visible-PID overhead
remains unvalidated.

## Overhead experiments

At minimum measure:

- idle host,
- typical developer workstation,
- many-process host,
- rapid process churn,
- already CPU-stressed host.

Record:

- Bottleneck Finder CPU time,
- peak RSS,
- number/size of procfs reads if measurable,
- observation timing skew,
- impact of richer per-process sampling.

## EXP-0001: Serialized rootless CPU acceptance scenarios

Date: 2026-08-17. Host/kernel: Linux 7.1.5 with 8 available logical CPUs.
The two ignored `tests/cpu_acceptance.rs` tests ran rootlessly with readable CPU
PSI. They are serialized because they create host workloads. The clean case
uses sleeping threads; the oversubscribed case starts nine owned shell busy loops
(one more than the available CPUs), waits 150 ms, then runs
`bottleneck hunt --duration 1s --json`. Both have an eight-second controller
timeout and RAII cleanup; the oversubscribed case also has an
at-most-eight-logical-CPU safety gate before it creates CPU workers.

The clean sleeping-thread run reported controller wall time 1027 ms; PSI duration
1,006,184 us (skew 6,184 us); CPU PSI `some` 0.400920706%; 146 schedstat
endpoint reads; 73 stable tasks; and no contention. The clean oversubscribed
run reported controller wall time 1025 ms; PSI duration 1,004,875 us (skew
4,875 us); CPU PSI `some` 28.466525687%; high severity; CPU/process duration
1,001,939 us; host `/proc/loadavg` total tasks 986; 34 schedstat reads; five
runnable-delay victim candidates; and three same-window suspect candidates.
Together these pass the intended clean and heavy-oversubscription acceptance
scenarios. They exercise the none and high bands, but do not prove portable
threshold boundaries.

`loadavg` total tasks was host-wide (roughly 977--987 across these measurements),
whereas visible procfs processes/tasks were namespace-limited. It is context,
not a direct count of the collector's visible task universe.

## EXP-0002: Release-binary collector-overhead and CPU-pressure profiles

Date: 2026-08-17. Host/kernel: Linux 7.1.5 with 8 available logical CPUs.
`tools/measure-overhead.sh` measured a pre-built release binary for three
one-second repetitions, using separate baseline, one-sleeper/process, process
churn, and CPU-stress scenarios. It uses `stress-ng` only if already installed
and never installs it. A helper-heavy `max_workers=4` setup hit sandbox fork
limits, so safe `max_workers=1` process/churn selection and isolated optional
CPU measurements were used.

| Scenario | Peak RSS | PSI skew | `tasks_read` | Wall time |
|---|---:|---:|---:|---:|
| baseline | 2440--2472 KiB | 0.856--0.903 ms | 10 | 1.00 s |
| one-sleeper process | 2348--2672 KiB | 0.724--0.875 ms | 12 | 1.00 s |
| churn | 2416--2472 KiB | 0.641--0.786 ms | 12--13 | 1.00 s |
| CPU stress | 2328--2480 KiB | 1.750--4.862 ms | 21--30 | 1.00--1.01 s |

Separate three-second release `stress-ng` profiles exercised the provisional
none, low, moderate, high, and severe bands:

| CPU load profile | CPU PSI `some` | Finding | Peak RSS | PSI skew |
|---|---:|---|---:|---:|
| 10 | 1.010491% | low | 2288 KiB | 1.313 ms |
| 25 | 1.575299% | low | 2536 KiB | 1.081 ms |
| 50 | 2.416146% | low | 2208 KiB | 1.764 ms |
| 75 | 13.943777% | moderate | 2476 KiB | 1.805 ms |
| 100 | 34.308187% | severe | 2432 KiB | 3.219 ms |

The clean acceptance scenario supplies the none band, and the earlier
oversubscribed scenario supplies the high band. These profiles exercise all
five bands, but do not prove that the exact boundaries are portable across
machines, kernels, workloads, or namespaces.

`/usr/bin/time` reported user and system time as `0.00s` at its displayed
resolution. This means the cost was below that resolution, not zero CPU cost.
The small-process results show low observed RSS and sub-5-ms PSI skew, but do
not validate overhead on hosts with a high visible PID/task count. The harness
is opt-in and has no CI timing gate.

## Deterministic negative coverage

Busy-but-not-pressured avoidance is deterministic normalized analyzer coverage,
not a host experiment: high utilization/runnable context cannot independently
create a CPU contention finding when exact-interval PSI remains below threshold.

## Current experimental conclusions

M1.6 validates the concise renderer, serialized bounded rootless acceptance
path, and controlled collector-overhead scenarios. The controlled runs exercise
the provisional none/low/moderate/high/severe bands, while thresholds remain
provisional rather than portable universal boundaries. High-visible-PID/task
overhead remains open CPU follow-up work; it does not make M1.6 incomplete or
block beginning Milestone 2 memory pressure.
