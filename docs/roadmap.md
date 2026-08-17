# Roadmap

The roadmap is ordered by learning value and useful vertical slices, not by collecting every possible metric.

## Milestone 0 — Repository bootstrap

Status: documentation prepared; code not started.

Deliverables:

- project docs,
- AGENTS.md,
- ADR framework,
- status tracking.

Exit condition:

A fresh coding agent can understand what to build without external chat history.

## Milestone 1 — CPU contention vertical slice

Goal:

> Detect active CPU scheduling contention and identify likely contributors and victims using non-eBPF Linux telemetry.

### M1.1 Rust/CLI bootstrap

Deliver:

- minimal Rust binary,
- `hunt` command,
- `capabilities` command,
- duration parsing,
- text + JSON output scaffolding,
- CI or documented local quality gates.

### M1.2 PSI collector

Deliver:

- `/proc/pressure/cpu` parser,
- raw snapshot model,
- interval pressure derived from `total`,
- parser fixtures/tests.

### M1.3 CPU/process collector

Deliver:

- `/proc/stat`,
- CPU count/capacity,
- process enumeration,
- robust `/proc/<pid>/stat` parser,
- process identity via PID + start time,
- process CPU deltas.

### M1.4 Scheduler-delay attribution

Deliver:

- `/proc/<pid>/schedstat` capability detection,
- runnable delay deltas where available,
- graceful fallback where unavailable.

### M1.5 CPU inference

Deliver:

- CPU contention finding,
- severity,
- confidence,
- victim ranking,
- suspect ranking,
- evidence and qualifiers,
- healthy/no-contention result.

### M1.6 CLI polish and validation

Deliver:

- concise default renderer,
- structured JSON,
- golden fixtures,
- synthetic CPU contention script/test,
- measured collector overhead,
- documentation update.

Milestone exit condition:

On a controlled CPU-saturation scenario, the tool identifies CPU contention and useful suspects/victims. On a busy-but-not-pressured scenario, it avoids a false bottleneck diagnosis.

## Milestone 2 — Memory pressure

Goal:

Distinguish high memory usage from harmful memory pressure.

Telemetry:

- `/proc/pressure/memory`,
- `/proc/meminfo`,
- selected `/proc/vmstat`,
- process RSS/context as supporting evidence,
- cgroup memory signals where practical.

Findings:

- no harmful memory pressure despite high occupancy,
- reclaim pressure,
- swap pressure,
- possible thrashing.

Exit condition:

The tool can explain both harmful and benign high-memory scenarios.

## Milestone 3 — Block I/O pressure

Telemetry:

- `/proc/pressure/io`,
- `/proc/diskstats`,
- `/proc/<pid>/io`,
- cgroup I/O stats where useful.

Findings:

- active I/O pressure,
- affected workloads,
- device-level contributors,
- process/cgroup suspects with explicit confidence limits.

Exit condition:

Synthetic competing I/O workload produces a meaningful device + workload diagnosis.

## Milestone 4 — Cgroup/systemd awareness

Goal:

Make findings useful on modern service/container hosts.

Deliver:

- cgroup v2 discovery,
- per-cgroup CPU/memory/I/O/PSI where available,
- mapping processes to cgroups,
- aggregate findings,
- optional systemd unit metadata without hard dependency if feasible.

## Milestone 5 — Recording and replay

Goal:

Capture incidents and analyze them later.

Deliver:

- versioned recording schema,
- `record`,
- `replay`,
- redaction/privacy design,
- deterministic re-analysis,
- support-bundle workflow.

Create ADR before promising format compatibility.

## Milestone 6 — Continuous watch mode

Goal:

Track rolling bottlenecks without becoming a generic TUI monitor.

Deliver:

- rolling windows,
- finding lifecycle (new/persistent/resolved),
- terminal refresh,
- bounded history.

## Milestone 7 — eBPF precision probes

Do not start this milestone merely because eBPF is interesting.

Add probes to resolve concrete uncertainty.

Candidate sequence:

1. scheduler wakeup-to-run latency,
2. off-CPU blocking attribution,
3. block I/O request latency,
4. futex/lock contention,
5. network/socket latency evidence.

Potential Rust ecosystem: Aya, subject to a current technical evaluation and ADR at implementation time.

## Milestone 8 — Evidence graph / multi-resource chains

Goal:

Connect findings when there is defensible evidence.

Examples:

```text
memory reclaim
  -> storage pressure
  -> database I/O stalls
```

or:

```text
CPU-heavy build
  -> scheduler pressure
  -> database request latency risk
```

Avoid overclaiming causality.

## Future possibilities

Not committed:

- daemon/client architecture,
- remote fleet analysis,
- Prometheus/OpenTelemetry export,
- plugins,
- policy/config DSL,
- target-aware SLO thresholds,
- Windows/macOS backends,
- AI-generated natural-language explanations.

These should not distract from local Linux triage.
