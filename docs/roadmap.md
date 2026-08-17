# Roadmap

The roadmap is ordered by learning value and useful vertical slices, not by collecting every possible metric.

## Milestone 0 — Repository bootstrap

Status: complete.

Deliverables:

- project docs,
- AGENTS.md,
- ADR framework,
- status tracking.

Exit condition:

A fresh coding agent can understand what to build without external chat history.

## Milestone 1 — CPU contention vertical slice

Status: complete.

Goal:

> Detect active CPU scheduling contention and identify likely contributors and victims using non-eBPF Linux telemetry.

### M1.1 Rust/CLI bootstrap

Status: complete.

Deliver:

- minimal Rust binary,
- `hunt` command,
- `capabilities` command,
- duration parsing,
- text + JSON output scaffolding,
- CI or documented local quality gates.

### M1.2 PSI collector

Status: complete.

Deliver:

- `/proc/pressure/cpu` parser,
- raw snapshot model,
- interval pressure derived from `total`,
- parser fixtures/tests.

### M1.3 CPU/process collector

Status: complete.

Deliver:

- `/proc/stat`,
- CPU count/capacity,
- process enumeration,
- robust `/proc/<pid>/stat` parser,
- process identity via PID + start time,
- process CPU deltas.

### M1.4 Scheduler-delay attribution

Status: complete.

Deliver:

- `/proc/<pid>/schedstat` capability detection,
- runnable delay deltas where available,
- graceful fallback where unavailable.

### M1.5 CPU inference

Status: complete.

Deliver:

- CPU contention finding,
- severity,
- confidence,
- victim ranking,
- suspect ranking,
- evidence and qualifiers,
- healthy/no-contention result.

### M1.6 CPU validation and overhead measurement

Status: complete.

Deliver:

- concise default finding-first renderer and structural/golden output fixtures,
- controlled CPU-pressure experiments that validate the provisional PSI
  severity boundaries,
- safe, bounded, rootless synthetic CPU acceptance coverage,
- measured collector overhead across representative process/task counts and
  under CPU pressure,
- documented experiment results and any resulting threshold or collection
  changes.

Completed scope:

- concise finding-first renderer with structural JSON assertions and a checked-in
  golden text fixture;
- ignored, rootless, bounded CPU-pressure acceptance coverage with an at-most-
  eight-logical-CPU safety gate, timeout, and RAII cleanup;
- opt-in release-binary overhead harness with baseline, process, churn, and
  CPU-stress scenarios; optional existing `stress-ng` is never installed;
- controlled 2026-08-17 evidence recorded in `experiments.md`.

Milestone exit condition:

On a controlled CPU-saturation scenario, the tool identifies CPU contention and useful suspects/victims. On a busy-but-not-pressured scenario, it avoids a false bottleneck diagnosis.

## Milestone 2 — Memory pressure

Status: in progress. The first host-memory collector/analyzer/output slice and
deterministic fixtures exist; safe controlled harmful-pressure validation is
still required.

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

Status: complete. The bounded rootless competing-I/O acceptance run established
a PSI-backed pressure finding with qualified same-window candidates. It did not
validate victim attribution, process-device mapping, or causality.

Telemetry:

- `/proc/pressure/io`,
- `/proc/diskstats`,
- `/proc/<pid>/io`,
- cgroup I/O stats where useful.

Findings:

- active I/O pressure,
- same-window device activity candidates,
- same-window process I/O-accounting candidates,
- explicit absence of victim, process-device, and causal mapping.

Exit condition:

Synthetic competing I/O workload produces a meaningful PSI-backed pressure
finding and qualified same-window device/process activity candidates without
overclaiming victim or causal mapping.

## Milestone 4 — Cgroup/systemd awareness

Status: in progress (design accepted in ADR-0006; implementation and validation
are not yet complete). M2's controlled harmful-memory-pressure validation
remains an outstanding cross-cutting validation debt.

Goal:

Make findings useful on modern service/container hosts.

Deliver:

- cgroup-v2 mount discovery using mountinfo and `0::` unified membership only;
- stat-cgroup-stat stable mapping for at most 1,024 selected PIDs;
- mapped cgroups plus ancestors only, capped at 2,048 groups with depth/path/
  file-byte budgets;
- scoped per-cgroup PSI verdicts plus CPU/memory/I/O controller context where
  readable;
- additive pre-1.0 JSON and explicit partial-permission/controller qualifiers;
- optional path-derived, explicitly inferred systemd unit candidate without
  D-Bus or a runtime dependency;
- no whole-tree scan, cgroup-v1 support, or cross-cgroup causal attribution.

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
