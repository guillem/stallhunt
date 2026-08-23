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

Status: complete. The delegated-cgroup acceptance produced a PSI-backed
harmful-memory finding (`memory_swap_pressure`) without unconstrained host-wide
allocation. Reclaim-only and possible-thrashing labels remain fixture-validated;
the slice still makes no process attribution.

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

Status: implementation complete; live validation is opt-in because it requires
a caller-owned delegated cgroup that already contains the test process.

Goal:

Make findings useful on modern service/container hosts.

Deliver:

- cgroup-v2 mount discovery using mountinfo and `0::` unified membership only;
- stat-cgroup-stat stable mapping under ADR-0006's 1,024-PID ceiling; the
  implementation currently selects at most 256 PIDs;
- mapped cgroups plus ancestors only under ADR-0006's 2,048-group ceiling; the
  implementation currently retains at most 512 groups with depth/path/
  file-byte, snapshot-byte, and read-attempt budgets;
- scoped per-cgroup PSI verdicts plus CPU/memory/I/O controller context where
  readable;
- additive pre-1.0 JSON and explicit partial-permission/controller qualifiers;
- optional path-derived, explicitly inferred systemd unit candidate without
  D-Bus or a runtime dependency;
- no whole-tree scan, cgroup-v1 support, or cross-cgroup causal attribution.

## Milestone 5 — Recording and replay

Status: complete. Normalized-observation recordings, `record`/`replay`/`redact`,
identifier redaction, and deterministic re-analysis are implemented. ADR-0007
withholds a pre-1.0 compatibility promise.

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

Status: complete. Finding-lifecycle watch over contiguous rolling windows is
implemented. ADR-0008 records the output and lifecycle contract; ADR-0013
supersedes its presentation clause in Milestone 9 with a ratatui TUI (classic
text remains the fallback). The first SIGINT drains the in-flight window
before exit and a second SIGINT terminates immediately; there is still no
multi-window recording.

Goal:

Track rolling bottlenecks without becoming a generic TUI monitor.

Deliver:

- rolling windows,
- finding lifecycle (new/persistent/resolved),
- terminal refresh,
- bounded history.

## Milestone 7 — eBPF precision probes

Status: not started. Do not start it merely because eBPF is interesting.

Add probes to resolve concrete uncertainty.

Candidate sequence:

1. scheduler wakeup-to-run latency,
2. off-CPU blocking attribution,
3. block I/O request latency,
4. futex/lock contention,
5. network/socket latency evidence.

Potential Rust ecosystem: Aya, subject to a current technical evaluation and ADR at implementation time.

## Milestone 8 — Evidence graph / multi-resource chains

Status: two conservative chain slices complete. The implemented path relates a
memory mechanism finding to host I/O pressure, and same-cgroup memory plus I/O
pressure, as `consistent_with` (ADR-0009, ADR-0010, ADR-0011). Already-pressured
cgroup findings can also carry reclaim, swap, possible-thrashing, or CPU
quota-throttle mechanism labels from scoped counters; those labels are context,
not additional chains. The implementation does not claim causality, map
processes to devices, link host and cgroup findings, or track chains in watch.
CPU–I/O and host–cgroup chains remain unimplemented.

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

## Milestone 9 — Interface redesign

Status: implementation complete on the `stallhunt-qwen` worktree; the first
feedback pass (EXP-0009) is folded in, real-user feedback is still pending
before release. Not yet tagged or released.

Goal:

> Give sysadmins the same evidence-backed diagnosis in a much clearer package:
> compact by default in one-shot mode, and a modern full-screen presentation in
> watch mode, without becoming a utilization dashboard.

Field feedback on v0.1.x: default `hunt` output read like a wall of text, and
`watch` looked primitive next to `htop`/`btop`. The explanations themselves
were considered valuable, so they move behind `--explain` rather than being
deleted.

Deliver:

- compact verdict-first default text for `hunt`/`replay` (headline, one line
  per resource, leading affected/suspect candidates, scoped pressure,
  related-evidence lines),
- `hunt --explain` / `replay --explain` restoring the full v0.1.x explanatory
  report,
- a ratatui/crossterm watch TUI on terminals: host pressure gauges, finding
  lifecycle table, scoped cgroup pressure, severity history sparkline, details
  pane (`e`), and help overlay (`?`/`h`),
- automatic fallback to the classic refreshing text renderer when stdout is
  not a TTY, `TERM=dumb`, `--no-tui` is passed, or terminal setup fails,
- unchanged JSON, recordings, watch window stream, lifecycle semantics, and
  SIGINT drain contract,
- deterministic fixture tests for both text layouts and ratatui `TestBackend`
  render tests for the TUI.

Decisions: ADR-0013 (terminal stack and TUI scope), ADR-0014 (compact output
policy). ADR-0008's lifecycle contract remains in force; only its presentation
clause is superseded.

Exit condition:

Local users can run the redesigned interface on real hosts and compare it
against `--no-tui`/v0.1.x behavior; feedback is collected before the 0.2.0
release decision. No presentation change may alter findings, evidence, or
lifecycle semantics.

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
