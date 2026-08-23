# ADR-0008: Watch tracks finding lifecycle, not a live dashboard

- Status: Superseded by [ADR-0014](0014-watch-findings-tui.md)
- Date: 2026-08-17

## Context

Milestone 6 needs a continuous mode that follows bottlenecks over time. A
generic TUI monitor would compete with `top`/`htop` and pull the product back
toward utilization dashboards. Repeating independent `hunt` invocations would
double-collect every window and leave gaps between observations.

Watch also needs a machine-readable stream. Hunt JSON is a full diagnostic
report. Recordings are normalized observations for later replay (ADR-0007).
Neither is a rolling lifecycle document.

## Decision

`watch` is a **finding-lifecycle** command.

- Rolling windows reuse the previous endpoint snapshot as the next start so
  intervals are contiguous and collection is not doubled.
- Each window re-runs the current analyzers. Watch does not invent a second
  inference engine.
- Tracked identities are host CPU, host memory, host I/O, and at most 16
  scoped cgroup pressure findings. Healthy and insufficient observations do
  not create tracked findings.
- Lifecycle states are `new`, `persistent`, and `resolved`. Severity changes
  stay `persistent` with the previous severity retained. Missing or
  short-window data leaves a finding persistent and unconfirmed; it does not
  resolve it.
- History is bounded to the last 16 windows of compact events. Full
  observations are not retained.
- Text on a TTY replaces the screen with ANSI clear/home. Piped text and
  `--json` append. There is no TUI crate, alternate screen, or interactive
  navigation.
- `--json` emits one compact `stallhunt.watch_window` object per window.
  That stream is not hunt JSON and not a recording. It has no pre-1.0
  compatibility promise.
- `--interval` uses the same duration limits as `hunt` (100 ms–5 m) and
  defaults to 2 s. `--count` bounds the run for tests and scripts. Without
  `--count`, the process runs until interrupted; the first SIGINT drains the
  in-flight window before exit (superseding this ADR's original default-
  termination behavior), and a second SIGINT terminates immediately.

Later additive mechanism labels refine the lifecycle row's `kind` without
changing identity: host identity remains resource, and cgroup identity remains
path plus resource. The current pressure-kind catalog is maintained in
`docs/cli-ux.md`.

## Consequences

Positive:

- operators see whether contention appeared, continued, or ended
- watch stays cheap enough to reuse hunt collectors
- JSON consumers can follow lifecycle without storing full evidence dumps
- tests can drive the tracker with injected window signals

Costs:

- watch JSON omits victims, suspects, and raw evidence; `hunt`/`record`
  remain the full-evidence paths
- cgroup findings resolve only when the scope is still observed and no longer
  ranked as pressure; a disappeared cgroup stays unconfirmed
- unbounded `--count` can sample indefinitely on a stressed host
- the first interruption can take up to the configured interval to finish;
  operators can interrupt a second time to terminate immediately

## Alternatives considered

### Independent hunts with a sleep between them

Rejected: each hunt takes two full endpoint collections, and the gap between
windows is not covered by PSI totals.

### A TUI resource monitor

Rejected: it would display utilization rather than finding lifecycle and would
require terminal-framework scope the product explicitly deferred.

### Reusing hunt JSON as the watch stream

Rejected: hunt JSON mixes findings with a full evidence payload. A compact
lifecycle object is the watch-specific document; recordings remain the way to
keep analyzer input.
