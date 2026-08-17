# Technical references

These are starting points for implementation research, not a frozen specification.

When kernel semantics matter, prefer current upstream Linux documentation and source over secondary articles.

## Linux kernel

### Pressure Stall Information (PSI)

Upstream documentation:

- <https://docs.kernel.org/accounting/psi.html>

Relevant to:

- `/proc/pressure/cpu`
- `/proc/pressure/memory`
- `/proc/pressure/io`
- `some` / `full`
- cumulative `total`
- PSI triggers
- per-cgroup pressure

For M2, this is the authoritative source for memory PSI `some`/`full` subset
semantics and cumulative microsecond `total`; rolling averages are context, not
the bounded-hunt verdict source.

### Scheduler statistics / `/proc/<pid>/schedstat`

- <https://docs.kernel.org/scheduler/sched-stats.html>

Relevant to per-task:

- execution time,
- run-queue wait time,
- timeslice count.

Verify kernel configuration/version behavior during implementation.

### procfs

- <https://docs.kernel.org/filesystems/proc.html>

Also consult the kernel source/UAPI when field semantics are ambiguous.

Important implementation warning:

`/proc/<pid>/stat` cannot be parsed correctly by naïvely splitting the entire line on whitespace because the command name is parenthesized and may contain spaces.

The same upstream procfs documentation is the primary reference for the
host-wide `/proc/meminfo` gauges and `/proc/vmstat` counters used by M2. Retain
vmstat page counters in pages unless a page-size contract is explicitly added.

### Kernel accounting

- <https://docs.kernel.org/accounting/index.html>

Useful index for:

- delay accounting,
- PSI,
- taskstats,
- per-task statistics.

### cgroup v2

- <https://docs.kernel.org/admin-guide/cgroup-v2.html>

Relevant to:

- cgroup hierarchy semantics,
- `cpu.stat`,
- `memory.current`,
- `memory.events`,
- `io.stat`,
- per-cgroup pressure files.

### VM sysctls / memory subsystem context

- <https://docs.kernel.org/admin-guide/sysctl/vm.html>

Use as supporting documentation when interpreting reclaim/writeback behavior. Avoid turning tuning recommendations into automatic remediation.

## eBPF — future milestone

### Aya

- <https://aya-rs.dev/>
- <https://aya-rs.dev/book/>

Aya is a Rust eBPF option worth evaluating when the project reaches the eBPF milestone.

Do not treat this bootstrap document as a decision to use Aya. ADR-0003 requires a fresh evaluation when a concrete probe is needed.

## Performance-analysis methodology

The project concept is compatible with the general principle that utilization alone is insufficient and saturation/queueing must be examined.

Useful background literature/tools to study during implementation:

- Brendan Gregg's USE Method and Linux performance materials.
- `perf sched`
- BCC/BPF performance tools such as scheduler/off-CPU/block-I/O tracers.
- Performance Co-Pilot inference/rule tooling.
- Meta's `below` for a modern Rust Linux monitor/recorder design reference.

These are inspiration/reference points, not dependencies and not product requirements.

## Reference discipline

When implementation relies on a specific kernel field:

1. identify the upstream semantic definition,
2. note relevant units,
3. note whether it is cumulative or instantaneous,
4. note configuration/permission requirements,
5. add a parser fixture,
6. add a concise source reference near non-obvious code or in `docs/telemetry.md`.

Do not copy undocumented assumptions from another monitoring tool without verifying them.
