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

What did Stallhunt report?

### Result

Pass / fail / ambiguous.

### Conclusion

What durable design conclusion follows?

### Follow-up

Tests, threshold changes, missing telemetry, or open questions.
```

## CPU experiment status

### CPU-1: idle/healthy

Complete through the clean rootless acceptance path in EXP-0001 plus
deterministic healthy fixtures.

### CPU-2: busy but not meaningfully pressured

Goal:

Demonstrate that high utilization alone does not necessarily trigger a severe finding.

Deterministic busy-but-not-pressured coverage passes. A controlled live workload
that is busy while remaining below the PSI threshold has not been recorded.

### CPU-3: oversubscribed CPU

Complete through the bounded rootless oversubscription path in EXP-0001.

### CPU-4: missing schedstat

Deterministic missing-schedstat fixture coverage verifies that the resource
diagnosis remains while victim attribution is omitted or reduced.

### CPU-5: short transient spike

Goal:

Determine how observation duration and transient PSI should affect severity/confidence.

Still open as a controlled transient host experiment.

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

`tests/memory_acceptance.rs` supplied the bounded opt-in harness used by
EXP-0006. That later run closed the M2 controlled harmful-pressure gap on this
host.

## EXP-0006: M2 delegated-cgroup harmful-memory acceptance

Date: 2026-08-17. Commit: `26f7321`. Host/kernel: Linux 7.1.5-ogc5.1.fc44.x86_64
with 8 logical CPUs, 16,003,232 KiB RAM (~8.3 GiB MemAvailable during the
runs), and 7.6 GiB unused zram swap. Privileges: ordinary uid 1000 with
systemd user-delegation on `user@1000.service`.

### Question

Can a uniquely owned, memory-limited child under a caller-provided delegated
cgroup produce exact host-memory PSI `some` of at least 1% and a PSI-backed
harmful-memory finding without an unconstrained host-wide allocator?

### Setup

`STALLHUNT_MEMORY_ACCEPTANCE_PATH` named the already-delegated parent
`/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice`, which
already had `memory` in `cgroup.subtree_control`. The ignored test created one
generated child, set `memory.max=256 MiB` and `memory.high=128 MiB` only on
that child, moved an owned `stress-ng --vm 1 --vm-bytes 192MiB --vm-keep
--vm-populate --timeout 8` allocator into it, and ran
`stallhunt hunt --duration 2s --json` with a five-second hunt timeout.

The first Drop implementation called `rmdir` immediately after killing the
dispatcher, so it failed while `stress-ng` workers were still in the child; an
empty leftover directory remained after those workers exited and was then
removed. The harness now drains remaining members of that uniquely named child
before `rmdir`. A second run left no leftover directory.

### Expected behavior

Exact-interval host memory PSI `some` at least 1%, and a finding of
`memory_pressure`, `memory_reclaim_pressure`, `memory_swap_pressure`, or
`memory_possible_thrashing`. `full`, meminfo, and vmstat remain non-additive
context. No process or cgroup-causality claim.

### Observed telemetry

Two consecutive passing runs:

| Run | PSI `some` fraction | PSI window | Finding |
|---|---:|---:|---|
| 1 | 0.2441984367166301 (24.4198%) | 2,148,171 µs | `memory_swap_pressure` |
| 2 | 0.2127021436849555 (21.2702%) | 2,144,205 µs | `memory_swap_pressure` |

After the first run, host swap remained unused (`SwapFree` equaled
`SwapTotal`) and MemAvailable stayed about 8.3 GiB. Rolling PSI later decayed
(`avg10` 3.98% immediately after run 1, 3.91% after run 2). The swap-pressure
label therefore reflects same-window `pswpin`, not leftover host swap
occupancy.

### Tool finding

Both hunts reported `memory_swap_pressure`. At 21–24% `some` over a ~2.15 s
window that is high severity and medium resource confidence. The swap
mechanism label remains low-confidence same-window correlation.

### Result

Pass. This satisfies the M2 controlled harmful-pressure exit on this host.

### Conclusion

A 192 MiB allocator inside a 128/256 MiB delegated child is enough to stall
tasks and raise host memory PSI `some` above 1% without filling the 16 GiB
host. The diagnosis stayed PSI-backed and host-wide. It does not validate a
reclaim-only label, possible thrashing, process attribution, or portable
severity boundaries.

### Follow-up

Reclaim-only and possible-thrashing remain fixture-covered rather than
live-validated. Workstation-scale collector overhead is recorded in EXP-0007.

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
1.231 ms, and user/system time displayed as 0.00s. Workstation-scale PID/task
overhead is in EXP-0007.

## Overhead experiments

At minimum measure:

- idle host,
- typical developer workstation (EXP-0007: ~370 PIDs / ~1,600 tasks),
- many-process host (caps still unreached),
- rapid process churn,
- already CPU-stressed host.

Record:

- Stallhunt CPU time,
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
`stallhunt hunt --duration 1s --json`. Both have an eight-second controller
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
is opt-in and has no CI timing gate. EXP-0007 records that follow-up on this
workstation.

## EXP-0007: Workstation-scale visible PID/task collector overhead

Date: 2026-08-17. Host/kernel: Linux 7.1.5-ogc5.1.fc44.x86_64 with 8 logical
CPUs. A current release binary (cgroup + evidence-chain inference) was
measured with `tools/measure-overhead.sh` for three one-second repetitions.
The host already exposed about 370 `/proc` PIDs and about 1,587 stable tasks.
No root, affinity, or cgroup mutation was used. `many_pids` now spawns
sleepers from a Python helper so a fork `EAGAIN` stops the batch; bash
background `sleep` is not used for that scenario because it retries failed
forks.

### Question

On a workstation with hundreds of visible PIDs and thousands of tasks, how
large is collector wall time, CPU time, RSS, and PSI-window skew relative to
the small-process EXP-0002 profiles?

### Setup

```bash
cargo build --release --locked --offline
tools/measure-overhead.sh --binary target/release/stallhunt --duration 1 --repetitions 3 --scenario baseline
tools/measure-overhead.sh --binary target/release/stallhunt --duration 1 --repetitions 3 --scenario many_pids --sleepers 64
tools/measure-overhead.sh --binary target/release/stallhunt --duration 1 --repetitions 3 --scenario many_tasks --tasks 512
```

Helpers were owned and cleaned up. CPU PID (4,096), schedstat task (16,384),
and process-I/O (1,024) caps were not reached. This pre-v0.4 run used the
then-current 256-PID cgroup selection cap, so it is historical context only;
it does not validate the v0.4 512-PID/member or taskstats bounds.

### Expected behavior

RSS and skew should rise versus EXP-0002. Caps should remain explicit. The
observer must stay cheap enough for a 10-second hunt. A one-second hunt may
show collection skew as a substantial fraction of the window.

### Observed telemetry

| Scenario | Peak RSS | PSI skew | Wall | user+system | Visible PIDs | CPU intervals | `tasks_read` | Stable tasks | Process I/O | Cgroup PID cap |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| baseline | 5960--6384 KiB | 112--188 ms | 1.13--1.20 s | 0.13--0.19 s | 372 | 371 | 3172--3174 | 1586--1587 | 129 | reached (94 groups) |
| +64 sleepers | 6180--6624 KiB | 155--205 ms | 1.17--1.22 s | 0.16--0.21 s | 437 | 372--436 | 3238--3302 | 1587--1651 | 130--194 | reached (94 groups) |
| +512 tasks | 6192--6448 KiB | 206--214 ms | 1.22--1.23 s | 0.19--0.22 s | 373 | 372 | 3742--4198 | 1643--2099 | 130 | reached (94 groups) |

CPU PSI `some` was 1.7--2.8% (low) on baseline and +64 PIDs. The +512-task
runs were 4.4--5.3% `some`; the last repetition crossed the 5% moderate
boundary. That is observer-plus-workload effect on a one-second window, not a
host saturation scenario. Extra high PIDs did not increase cgroup groups
because that collector selects the lowest 256 PIDs.

EXP-0002's small-process baseline was 2440--2472 KiB RSS, 0.856--0.903 ms
skew, and `tasks_read` 10, with user/system displayed as `0.00s`.

### Result

Pass for workstation-scale overhead. The 4,096-PID and 16,384-task caps remain
unexercised. A one-second hunt on this host spends roughly 110--210 ms of the
PSI window in sequential collection.

### Conclusion

Hundreds of visible PIDs and ~1,600--2,100 stable tasks keep peak RSS around
6 MiB and CPU time around 0.13--0.22 s per one-second hunt. That is acceptable
for the default 10-second hunt (about 2% window skew) and visible on 1-second
smoke hunts (about 11--21% skew). Cgroup completeness is already partial on
this host because of the 256-PID selection cap. Extra schedstat task walks can
raise short-window CPU PSI enough to cross a provisional boundary.

### Follow-up

Do not spawn thousands of helper PIDs with bash background `sleep`; the
Python many_pids helper is the supported path. Measuring the 4,096-PID or
16,384-task caps would require a dedicated, quota-aware setup and is not
justified by this workstation result.

## EXP-0010: v0.4 enabled-delayacct rootless and 512-TGID validation

Date: 2026-08-24. Commit: `872c4cd` plus this documentation update.

Host/kernel: Fedora workstation, Linux 7.2.0-ogc4.1.fc44.x86_64, 8 logical
CPUs, 16 GiB RAM, NVMe through dm-crypt. Relevant configuration:
`kernel.task_delayacct=1` was enabled by the operator before all owned
workloads; Stallhunt ran as UID 1000 without elevation or file capabilities.

### Result

The enabled state is reported independently as `delay_accounting: enabled`,
but TASKSTATS GET is permission-gated on this host. Two bounded endpoint
attempts returned permission denial, after which Stallhunt reported
`taskstats_capability: permission_denied`, queried no TGIDs, and retained its
procfs baseline. A separate run with 512 newly started sleeper processes
selected exactly the lowest 512 TGIDs, reported `tgid_limit_reached: true`,
and again stopped on the two endpoint permission denials without exhausting
the time or 1 MiB reply budgets. This passes the required rootless degradation
behavior, not the positive-taskstats gate.

The ignored CPU acceptance produced 46.51% exact host CPU PSI `some`, a severe
finding, five victim candidates, and three suspects. The sleeping-thread case
completed, but observed 1.02% host CPU PSI interference and therefore did not
assert a no-contention verdict. The bounded I/O workload produced 12.69% exact
host I/O PSI `some` and two procfs block-I/O delay victims; its existing
acceptance assertion deliberately degraded because unrelated
`/proc/<pid>/io` reads made process-I/O capability partial. Neither result
contained taskstats evidence because GET remained denied.

Release-binary overhead with 64 extra processes and 512 extra threads was
1.10–1.13 s wall time, 0.01–0.03 s user time, 0.08–0.10 s system time, and
7,004–7,904 KiB maximum RSS for a requested one-second observation. A true
512-extra-process profile was 1.14–1.17 s wall time, 0.02–0.03 s user time,
0.11–0.14 s system time, and 8,476–11,040 KiB maximum RSS. It exposed 859 PIDs
and kept the general process walk within its bounds.

### Remaining gap

This login session cannot complete the release experiment. The executable has
no effective `CAP_NET_ADMIN`, so positive taskstats CPU, block-I/O, and memory
delays remain unavailable. Cgroup discovery also fails conservatively because
the mount namespace exposes two cgroup-v2 mounts (`/sys/fs/cgroup` and
`/run/bpftune/cgroupv2`); the collector rejects ambiguous mounts. Consequently
no cgroup-scoped positive evidence or 512-member completeness measurement was
claimed. Completing the gate requires an operator-provided taskstats-capable
execution context and a controlled namespace with one unambiguous cgroup-v2
mount (or a separately reviewed mount-selection change).

Delay accounting remains enabled while this controlled validation is in
progress. Restoring the operator's original `kernel.task_delayacct=0` state is
still required when the experiment ends.

## EXP-0009: v0.4 taskstats and terminal-validation status

Date: 2026-08-24.

### Result

Deterministic tests cover the bounded taskstats selection/query loop with 512
lowest TGIDs, identity bracketing, PID reuse/churn, `ESRCH`, permission,
unsupported, timeout, malformed, reply-budget, total-time, version, padding,
nesting, and counter-regression outcomes. The local PTY command
`tools/check-tui-pty.sh --binary target/debug/stallhunt` passed: one bounded
TUI window emitted alternate-screen enter/leave sequences and restored the
original `stty -g` state.

### Controlled-host gap

At the time of EXP-0009, this was not the v0.4 release acceptance experiment:
no operator-approved host had enabled `kernel.task_delayacct` before owned
workloads or recorded v0.4 512-TGID/member overhead. EXP-0010 subsequently
closed only the enabled-state, rootless degradation, and host-side 512-TGID
procfs-overhead portions. Permitted positive CPU, block-I/O, and memory
taskstats evidence for host and cgroup scopes, capable-query overhead, and the
512-member cgroup measurement remain open. Do not treat the historical
256-member EXP-0007 measurement or a skipped capable-host run as satisfying
those gates.

### Dependency-audit status

On 2026-08-24, `cargo audit` from cargo-audit 0.22.2 scanned the full current
`Cargo.lock` and exited 0 with three allowed warnings: unmaintained `paste`
(`RUSTSEC-2024-0436`) and unsound `lru` (`RUSTSEC-2026-0002` and
`RUSTSEC-2026-0253`). The latter dependencies are transitive through ratatui
0.29. This cargo-audit version does not accept the planned `--omit=dev` flag,
so no dev-dependency-excluded claim is made. Ratatui 0.30.0 requires Rust 1.86,
and 0.30.1 or newer requires Rust 1.88, so all conflict with the Rust 1.85
MSRV. The warnings require a reviewed
dependency/MSRV decision before v0.4.0 may be released.

## EXP-0008: Deterministic scoped possible-thrashing validation

Date: 2026-08-17. Commit: `9583404`.

### Question

Can already-collected cgroup PSI and `memory.stat` counters label an existing
scoped memory-pressure verdict as possible thrashing without creating pressure
or claiming causality?

### Setup

Deterministic analyzer inputs supplied high or severe cgroup PSI `some`, valid
`full` of at least 1%, a PSI window of at least five seconds, and direct-scan,
direct-steal, swap-in, and swap-out deltas at or above 1,024 pages/second over
the independent cgroup observation interval. Negative cases varied the
observation rate, PSI duration/severity, `full` validity, reclaim conjunction,
and presence of a PSI-backed pressure verdict.

### Result

Pass. Analyzer coverage accepted only the full conjunction, assigned medium
mechanism confidence, retained `CgroupAssessmentKind::Pressure`, and rejected
short, moderate, missing/invalid-`full`, scan-without-steal, and no-pressure
cases. Hunt text/JSON and watch kind
`cgroup_memory_possible_thrashing` were also validated. The full deterministic
gate then contained 148 unit tests and ten CLI tests; five Linux acceptance
tests remained ignored by default.

### Conclusion

The scoped label is a fixture-validated heuristic using existing telemetry. It
is not a causal claim, a new verdict, or a new evidence chain. Page rates use
the cgroup observation interval rather than the PSI interval.

### Follow-up

No controlled live scoped-thrashing result exists. Do not substitute
unconstrained host pressure; any live follow-up requires a caller-owned,
bounded delegated cgroup setup.

## Deterministic negative coverage

Busy-but-not-pressured avoidance is deterministic normalized analyzer coverage,
not a host experiment: high utilization/runnable context cannot independently
create a CPU contention finding when exact-interval PSI remains below threshold.

## Current experimental conclusions

M1.6 validates the concise renderer, serialized bounded rootless acceptance
path, and controlled collector-overhead scenarios. The controlled runs exercise
the provisional none/low/moderate/high/severe bands, while thresholds remain
provisional rather than portable universal boundaries. EXP-0007 records
workstation-scale PID/task collector cost; the 4,096-PID and 16,384-task caps
were not reached.

M2 now has both a healthy-host smoke (EXP-0003) and a delegated-cgroup
harmful-pressure acceptance (EXP-0006). The latter produced high-severity
`memory_swap_pressure` from exact host PSI `some` without unconstrained
host-wide allocation. Host reclaim-only and host possible-thrashing labels
remain fixture-validated. EXP-0008 records deterministic scoped possible-
thrashing validation, not a live pressure run. M3's competing-I/O acceptance
(EXP-0004) remains the block-I/O exit evidence.
