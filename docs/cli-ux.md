# CLI and UX

## UX goal

The default command should answer a question, not dump a dashboard.

The terminal output should be useful to a human who knows Linux but does not want to manually correlate five tools.

## Command shape

Binary name: `stallhunt`.

### Primary command

```bash
stallhunt
```

Bare `stallhunt` runs a default 10-second hunt. Equivalent explicit form:

```bash
stallhunt hunt
```

Defaults:

- bounded observation,
- sensible duration such as 10 seconds,
- human-readable output,
- all implemented resource analyzers,
- no requirement for elevated privileges.

Options may include:

```text
--duration <DURATION>
--interval <DURATION>
--json
--explain
--no-tui
--resource cpu|memory|io|all
--pid <PID>
--cgroup <PATH>
--verbose
--no-color
```

Do not add flags before a real use case exists. Implemented today:
`--duration`, `--interval`, `--json`, `--explain` (hunt/replay text detail),
and `--no-tui` (watch). `NO_COLOR` is honored for watch TUI colors; hunt text
output stays uncolored.

## Early command set

### `hunt`

Run a bounded diagnosis.

### `capabilities`

Show available telemetry and permission limitations.

### `version`

Standard version information.

### `completions`

Generate shell completions to stdout:

```bash
stallhunt completions bash
stallhunt completions zsh
stallhunt completions fish
```

The CLI uses clap 4 with derive parsing. Delay `explain`, daemon mode, TUI, etc. until the core diagnosis is trustworthy.

Implemented in Milestone 5:

### `record`

Capture a normalized observation to a file.

```bash
stallhunt record --output incident.json [--duration 10s] [--redact] [--force]
```

### `replay`

Re-analyze a recording with the current inference engine.

```bash
stallhunt replay incident.json [--json]
```

### `redact`

Replace identifiers in an existing recording for sharing.

```bash
stallhunt redact incident.json --output incident.redacted.json [--force]
```

Implemented in Milestone 6:

### `watch`

Follow rolling bottlenecks by finding lifecycle.

```bash
stallhunt watch [--interval 2s] [--count N] [--json] [--no-tui]
```

Watch renders a full-screen TUI on a terminal (ADR-0013) and falls back to
classic refreshing text when piped, when `--no-tui` is passed, or when the
terminal cannot host the TUI. It is a finding-lifecycle display, not a generic
resource monitor: no process lists, no utilization dashboards, no interactive
configuration.

## Current CPU diagnosis behavior

Milestone 1 implements:

```text
stallhunt hunt [--duration <DURATION>] [--json]
stallhunt capabilities [--json]
stallhunt version
```

`hunt` takes CPU PSI, host CPU/load, bounded per-process `stat`, and bounded
task scheduler-accounting snapshots around the requested sleep. It reports
`some.total` delta divided by the actual
monotonic elapsed interval, along with host CPU tick deltas, logical CPU count,
load context, and process CPU deltas for stable `(pid, starttime)` identities.
A valid exact-interval CPU PSI `some` value determines the CPU resource verdict;
host utilization, load, and process data provide context rather than
independently creating contention. The effective diagnostic and resource-
confidence window is the shorter of the requested duration and measured PSI
interval. A request below one second remains telemetry smoke mode even if the
measured interval is longer. Otherwise, an effective window of at least one
second reports either no meaningful CPU scheduling contention or a provisional
low, moderate, high, or severe finding.

If host/process CPU context fails but CPU PSI is valid, `hunt` retains the CPU
resource verdict, marks the response incomplete, and emits collection
qualifiers; victims and suspects are empty because attribution is unavailable.
Unavailable or invalid CPU PSI produces no CPU contention assessment. Partial
evidence remains in an `observation` object; it is `null` only when no complete
evidence is available.

When contention is found, scheduler-delay candidates are ranked as affected
workloads and same-window CPU consumers as likely contributors. Both roles are
qualified correlation: summed stable-thread delay is not confirmed harm, and
CPU consumption does not prove causality.
`capabilities` probes CPU PSI and reports `available`, `unsupported`,
`permission_denied`, or `failed`.

The top-level `status: "observed"` in capability JSON means the probe completed;
the nested capability state is authoritative and may still be `unsupported`,
`permission_denied`, or `failed`.

M2 extends the same `hunt` with a separate host-memory assessment and reports
memory PSI, meminfo, and vmstat capabilities. Exact-interval memory PSI `some`
controls the memory verdict; memory `full` is displayed as separately-qualified
all-non-idle-task stall context and is not added to `some`. Text makes the
host-wide/no-process-attribution limit explicit. JSON retains memory
observation, evidence, counter availability, and qualifiers even where the
concise text renders only the relevant finding/context.

M3 adds a separately ranked I/O assessment. Its text explicitly distinguishes
the PSI verdict from disk and process I/O-accounting activity candidates, labels
them same-window/non-causal, and states that affected workloads and
process-to-device mapping are unavailable. JSON adds I/O observation, PSI/full
state, diskstats/process-I/O context, candidates, capabilities, and qualifiers
without changing prior resource objects.

M4 adds a separate scoped-cgroup finding section. It reports exact cgroup PSI
only for that cgroup scope and displays CPU, memory, and I/O controller deltas
as qualified context. When `memory.stat` supports it, a scoped memory pressure
line may say reclaim, swap, or possible thrashing and include mechanism
confidence; page counters never create that pressure line. Possible-thrashing
uses the host conjunction and medium mechanism confidence. A scoped CPU pressure
line may say quota-throttle when `cpu.stat` shows throttled time; throttle
counters never create that pressure line. Cgroup capability is `partial` whenever the bounded
snapshot or controller files are incomplete; this also makes the top-level hunt
status `incomplete`, without discarding valid host findings.

M5 adds `record`, `replay`, and `redact`. Recordings are not hunt JSON: they
store normalized observations under `kind` `stallhunt.recording` schema
version 1. Legacy `bottleneck.recording` files are accepted on replay. Replay
uses the same text/JSON renderers as `hunt`, with the recorded requested
duration. Invalid recordings exit 1. Missing `--output` or an invalid invocation
still exits 2. New recording files are created mode 0600 and are not
overwritten unless `--force` is passed.

M6 adds `watch`. `--interval` uses the same 100 ms–5 m duration parser as
`hunt` and defaults to 2 seconds. `--count` stops after N windows; without it,
watch runs until interrupted. For an unlimited watch, the first SIGINT drains
and writes the in-flight window; a second SIGINT terminates immediately with
status 130. Bounded `--count` runs retain the default signal disposition. Each
window reuses the previous endpoint snapshot. Text reports `new` / `persistent`
/ `resolved` pressure findings plus a compact current-window summary. JSON
is one compact `stallhunt.watch_window` object per window. It is not hunt JSON
and not a recording, and it omits full evidence. Host memory `kind` values
already name reclaim, swap, or possible thrashing. Scoped cgroup `kind` values
name the resource and, when labeled, the mechanism
(`cgroup_memory_reclaim_pressure`, `cgroup_memory_swap_pressure`,
`cgroup_memory_possible_thrashing`, `cgroup_cpu_quota_throttle_pressure`);
identity remains path plus resource, so a mechanism change stays `persistent`. Use
`hunt --json` or `record` when the full evidence payload is required. Invalid
`--count` still exits 2. The classic text renderer (TTY refresh with ANSI
clear/home; piped text appends) remains the fallback and the `--no-tui` mode.

M9 redesigns the interface (ADR-0013, ADR-0014):

- `hunt`/`replay` text becomes compact and verdict-first by default. The full
  v0.1.x explanatory report moves behind `--explain`. JSON is unchanged.
- `watch` renders a ratatui TUI on a terminal: host pressure gauges, the
  finding-lifecycle table, scoped cgroup pressure, a severity history
  sparkline, and a key footer. `e` toggles a details pane with the full
  per-finding summaries; `?`/`h` toggles a help overlay explaining keys,
  panels, and meaning limits; `q` quits. The TUI presents existing watch data
  only — no new collectors, inference, or identities.
- Automatic fallback to classic text when stdout is not a terminal, when
  `TERM=dumb`, when `--no-tui` is passed, or when raw mode/alternate screen
  setup fails.
- Color reinforces severity in the TUI but never carries meaning alone;
  `NO_COLOR` disables it. Hunt text output stays uncolored.
- SIGINT semantics are unchanged: the first SIGINT or Ctrl-C drains the
  in-flight window, the second terminates immediately with status 130. The TUI
  restores the terminal on both paths (best-effort on the immediate path).

Tracked watch pressure kinds are:

- host: `cpu_scheduling_contention`, `memory_pressure`,
  `memory_reclaim_pressure`, `memory_swap_pressure`,
  `memory_possible_thrashing`, and `io_pressure`;
- cgroup: `cgroup_cpu_pressure`, `cgroup_cpu_quota_throttle_pressure`,
  `cgroup_memory_pressure`, `cgroup_memory_reclaim_pressure`,
  `cgroup_memory_swap_pressure`, `cgroup_memory_possible_thrashing`, and
  `cgroup_io_pressure`.

Healthy, unavailable, and insufficient kinds can appear in the compact current
window summary but do not create tracked identities. A mechanism change updates
the lifecycle row's `kind` while preserving host-resource identity or cgroup
path-plus-resource identity.

## Human output structure

Default `hunt`/`replay` text is compact and verdict-first (ADR-0014). It
shows:

- a headline: observation duration plus contention detected / no significant
  contention detected / assessment incomplete;
- one line per host resource with verdict word, severity, and exact-interval
  PSI `some` with cumulative stalled time;
- for contention findings, the leading affected candidates (observed runnable
  delay) and suspect candidates (same-window CPU consumers), each still
  labeled with its caveat and confidence;
- for I/O pressure, the leading same-window device and process activity
  candidates, labeled as non-causal;
- prominent scoped cgroup pressure, one line per scope, labeled as scoped
  verdicts rather than host causality;
- one line per evidence-chain relation, labeled consistent-with and carrying
  its confidence;
- a footer pointing at `--explain` and `--json`.

`--explain` prints the full explanatory report: the v0.1.x layout with the
verdict/evidence lines, complete candidate lists, context and limitations,
capability notes, and requested/measured timings. Nothing was deleted; the
detail moved behind one flag. Suspect output still states that it is
same-window correlation rather than proof of causality. Missing or partial
attribution is rendered as unavailable or incomplete rather than as an
observed empty result.

Process names are terminal-safe and bounded in text output. Neither renderer
dumps raw host counters, rolling PSI averages, or a separate top-ten process
list. `--json` remains the full structured-evidence interface: it retains the
complete observation, typed evidence, ranked roles, capabilities, and
collection qualifiers rather than mirroring either text layout.

Compact example (contention):

```text
stallhunt · observed 10s · contention detected

  CPU     contention           high      PSI some 20.00% · 2s stalled
  Memory  healthy              none      PSI some 0.10% · 0ms stalled
  I/O     healthy              none      PSI some 0.05% · 0ms stalled

Affected (observed delay, not confirmed harm):
  worker [21] — 500ms runnable delay (high)

Suspects (same window only, not proven causal):
  build [20] — 80.0% of one CPU (medium)

Details: --explain · Full evidence: --json
```

The same observation with `--explain` adds the full report:

```text
CPU scheduling contention observed
Verdict: contention · severity high · CPU confidence high
Evidence: CPU PSI some 23.40% over exact 10s interval (2.34s cumulative stalled time)
Victim candidates (observed runnable delay; not confirmed harm):
  1. postgres [4812] — 1.81s delay (high; observed runnable-delay candidate)
Suspect candidates (same window only; not proven causal):
  1. rustc [9231] — 58.0% of one CPU (medium; leading concurrent CPU consumer)
Context and limitations:
  Suspects consumed CPU in the same window; this correlation does not prove causality.
Timing: requested 10s; PSI measured 10s; CPU/process measured 10s
```

## Negative results

A healthy result should still be informative, and compact by default:

```text
stallhunt · observed 10s · no significant contention detected

  CPU     healthy              none      PSI some 0.20% · 0ms stalled
  Memory  healthy              none      PSI some 0.00% · 0ms stalled
  I/O     healthy              none      PSI some 0.40% · 0ms stalled

Details: --explain · Full evidence: --json
```

This distinguishes "busy" from "bottlenecked": a high-PSI-free host can be
busy without being bottlenecked, and the per-resource lines say so directly.

## Terminology

Prefer:

- "affected" or "victim",
- "likely contributor" or "suspect",
- "pressure",
- "runnable delay",
- "observation window",
- "evidence".

Avoid unexplained jargon such as:

- "steal" without context,
- raw kernel field names as the only explanation,
- opaque global scores.

## Color

Color may communicate severity but must never be the only carrier of meaning.

Support:

- automatic TTY detection (the watch TUI only activates on a terminal),
- `NO_COLOR` convention,
- severity words are always rendered alongside color in the TUI.

There is no `--no-color` flag; `NO_COLOR` covers the use case. Hunt/replay
text output remains uncolored in both compact and `--explain` modes.

## Exit codes

Current bootstrap policy:

- `0`: the requested command completed, including an explicitly unavailable
  bootstrap `hunt`, a successful `record`/`replay`/`redact`, and a completed
  `watch --count` run,
- `1`: a parsed command failed at runtime, such as a missing recording file,
  an unreadable or unsupported recording, or a refused overwrite,
- `2`: invalid command-line invocation.

Once collection exists, `0` will continue to mean that diagnosis completed
successfully regardless of whether findings exist. Machine consumers must
inspect the JSON `status` rather than interpret an empty findings array alone.

Do **not** initially use non-zero merely because a bottleneck exists; that surprises shell users.

If threshold-based CI usage is later desired, add an explicit flag such as:

```bash
--fail-on high
```

and document its exit semantics.

## JSON output

JSON is a first-class interface.

Command:

```bash
stallhunt hunt --json
```

Requirements:

- schema version,
- tool version,
- observation window,
- host metadata relevant to interpretation,
- capabilities,
- findings,
- evidence,
- qualifiers.

Representative Milestone 1 finding shape (optional context fields are omitted here):

```json
{
  "schema_version": 1,
  "tool_version": "0.1.2",
  "requested_observation": {
    "duration_ms": 10000
  },
  "capabilities": {},
  "findings": [
    {
      "kind": "cpu_scheduling_contention",
      "resource": "cpu",
      "severity": "severe",
      "resource_confidence": "high",
      "summary": "CPU scheduling contention observed.",
      "evidence": {
        "psi_some_fraction": 0.234,
        "psi_total_delta_us": 2340000,
        "psi_window_us": 10000000,
        "host_utilization_fraction": 0.971,
        "logical_cpu_count": 8,
        "runnable_tasks": 14,
        "loadavg1": 12.3
      },
      "victims": [
        {
          "key": { "pid": 4812, "start_time_ticks": 123456 },
          "name": "postgres",
          "runnable_wait_ns": 1810000000,
          "runnable_delay_fraction": 0.181,
          "stable_task_count": 4,
          "confidence": "high",
          "label": "observed_runnable_delay_victim_candidate"
        }
      ],
      "suspects": [
        {
          "key": { "pid": 9231, "start_time_ticks": 123999 },
          "name": "rustc",
          "cpu_fraction_of_one": 0.58,
          "cpu_ticks": 584,
          "confidence": "medium",
          "label": "concurrent_cpu_consumer"
        }
      ],
      "qualifiers": [
        {
          "kind": "high_utilization_context",
          "message": "Host CPU utilization was at least 90%; this is supporting context, not the contention verdict."
        }
      ]
    }
  ]
}
```

Do not make text strings the only machine-readable meaning.

Use enums/typed fields plus optional explanatory text.

M8 adds `evidence_chains` to hunt/replay JSON. An empty array means no
defensible relation was found. A host chain object uses `kind`
`memory_mechanism_consistent_with_io`; a same-cgroup chain uses
`cgroup_memory_consistent_with_io`. Both use `relation` `consistent_with`, typed
`from`/`to` endpoints, compact linking evidence, and qualifiers. Same-cgroup
endpoints carry the cgroup path and are never mixed with host endpoints. A chain
is not a finding and is omitted from `findings`. Hunt text appends a `Related
evidence` section only when a chain exists.

## Stable output policy

Human output may evolve freely before 1.0.

JSON compatibility needs an explicit versioning policy before external integrations are encouraged.

Until then:

- include `schema_version`,
- document that pre-1.0 schema may change,
- prefer additive changes where convenient.

## Verbose/debug output

`--explain` (hunt/replay) is the implemented detail flag: it switches the
default compact verdict-first text to the full explanatory report. A future
`--verbose` should add collector/diagnostic context, not turn the normal
renderer into a raw `/proc` dump.

A future `--debug-dump` can emit normalized observation data for bug reports.

## Duration UX

Accept ergonomic durations such as:

```text
500ms
2s
30s
1m
```

The current parser accepts integral or decimal durations that resolve exactly
to milliseconds. Supported units are `ms`, `s`, and `m`; the inclusive range is
100 ms through 5 minutes. `hunt` and `record` default to 10 seconds; `watch`
`--interval` defaults to 2 seconds.

These are initial bounded-hunt safety limits, not validated inference
thresholds. Future analyzers must qualify windows that are too short for strong
conclusions, and experiments may justify revising the limits.

Warn or reduce confidence for observation windows too short to support robust inference.

## TUI

M9 adds a watch TUI built on ratatui (ADR-0013). The differentiator remains
diagnosis, so the TUI displays changing findings rather than reproducing
`htop`. It is a presentation of the same `WatchWindow` data the classic text
renderer prints: no new collectors, inference, or identities.

Layout (top to bottom):

- header line: tool, window index, interval, and drain state;
- host pressure gauges for CPU, memory, and I/O (exact-window PSI `some`);
- finding lifecycle table (new / persistent / resolved) with scope, kind,
  severity, PSI, and window count;
- scoped cgroup pressure panel and a severity history sparkline;
- footer with key hints.

Keys:

- `q` quit;
- `e` toggle the details pane (full per-finding summaries and current-window
  signal summaries);
- `?` / `h` toggle a help overlay explaining the panels and meaning limits;
- `Esc` close the help overlay;
- `Ctrl-C` first drains the in-flight window then exits, a second exits now
  with status 130.

The TUI activates only when stdout is a terminal, `TERM` is not `dumb`, a
terminal size is available, and `--no-tui` is not passed. Otherwise watch
falls back to the classic refreshing text renderer. `--json` and piped text
are unchanged. Terminal restore (raw mode off, cursor visible, alternate
screen left) happens on graceful exit and best-effort on the immediate
second-SIGINT path.
