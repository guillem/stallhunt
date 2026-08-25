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

The implicit form also accepts hunt options:

```text
stallhunt [--duration <DURATION>] [--json] [--verbose] [--no-color]
```

Defaults:

- bounded observation,
- sensible duration such as 10 seconds,
- human-readable output,
- all implemented resource analyzers,
- no requirement for elevated privileges.

Bare `stallhunt` is a complete implicit `hunt`: it accepts the same `--duration`,
`--json`, `--verbose`, and `--no-color` options as `stallhunt hunt`. Root hunt
options cannot be combined with an explicit subcommand. `replay` accepts
`--json`, `--verbose`, and `--no-color`; `watch` accepts `--interval`,
`--count`, `--json`, and `--no-color`.

Still reserved, not yet implemented — do not add before a real use case exists:

```text
--resource cpu|memory|io|all
--pid <PID>
--cgroup <PATH>
```

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
stallhunt replay incident.json [--json] [--verbose] [--no-color]
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
stallhunt watch [--interval 2s] [--count N] [--json] [--no-color]
```

This is a finding-lifecycle TUI on a terminal, not a generic resource monitor.

### `mcp`

Serve Model Context Protocol tools over stdio for coding agents.

```bash
stallhunt mcp [--interval 2s] [--no-sampler]
```

stdout carries protocol frames exclusively; stdin EOF ends the session. A
resident sampler (interval bounds match `watch`) keeps a rolling
finding-lifecycle view so agents get instant answers about the recent past;
`--no-sampler` disables it. Tools and transport are documented in
[`mcp-server.md`](mcp-server.md) and ADR-0017.

## Current CPU diagnosis behavior

Milestone 1 implements:

```text
stallhunt hunt [--duration <DURATION>] [--json] [--verbose] [--no-color]
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
all-non-idle-task stall context and is not added to `some`. Text distinguishes
the host-wide resource finding from v0.4's separate PSI-gated scoped process
roles. JSON retains memory observation, evidence, counter availability,
qualifiers, and canonical process scopes even where concise text renders only
the relevant finding/context.

M3 adds a separately ranked I/O assessment. Its text explicitly distinguishes
the PSI verdict from disk and process I/O-accounting activity candidates and
labels them same-window/non-causal. v0.4 separately reports scoped delay-based
victim roles while preserving the caveat that process-to-device mapping and
causality are unavailable. JSON adds I/O observation, PSI/full
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
store normalized observations under `kind` `stallhunt.recording`. New files
use schema version 2; schema-1 and legacy `bottleneck.recording` files are
accepted on replay, with schema-1 process-resource/taskstats evidence treated
as unavailable. Replay
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
/ `resolved` pressure findings plus a compact current-window summary. A TTY
opens the finding-lifecycle TUI; piped text and `--json` append. JSON
is one compact `stallhunt.watch_window` object per window. It is not hunt JSON
and not a recording, and it omits full finding evidence while retaining typed,
bounded process attribution where it is supported. Host memory `kind` values
already name reclaim, swap, or possible thrashing. Scoped cgroup `kind` values
name the resource and, when labeled, the mechanism
(`cgroup_memory_reclaim_pressure`, `cgroup_memory_swap_pressure`,
`cgroup_memory_possible_thrashing`, `cgroup_cpu_quota_throttle_pressure`);
identity remains path plus resource, so a mechanism change stays `persistent`. Use
`hunt --json` or `record` when the full evidence payload is required. Invalid
`--count` still exits 2.

Schema-2 hunt/replay JSON and watch JSON include canonical host and
PSI-pressured cgroup `process_scopes` with all six process roles. Legacy
hunt/replay text and watch text render every host and cgroup scope explicitly.
On a terminal, hunt/replay presents compact per-scope role counts and top
candidates. `watch` renders all five retained candidates in a responsive role
grid at 120×30 or larger; smaller terminals retain six role summaries and
expandable, scrollable detail. Candidate
lists are bounded and may be marked partial; retained lifecycle lists are
explicitly stale rather than presented as current evidence.

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

Every watch surface transports analyzer-owned CPU, memory, and I/O victim and
suspect lists for the host scope, while schema-2 and lifecycle records also
carry cgroup-resource pairs. Each candidate carries a stable process key,
terminal-safe name, confidence, typed evidence, and its analyzer label. Direct
delay evidence and heuristic fallbacks remain distinguishable, and candidates
are correlation-qualified rather than proof of harm or causality. Cgroup
lifecycle findings carry their matching victim/suspect pair; stale retention is
matched by cgroup path plus resource identity.

Lifecycle findings repeat their last observed process candidates and role-list
availability. A confirmed
persistent finding refreshes those candidates from the current window; an
unconfirmed persistent or resolved finding labels them as **last observed** so
they cannot be mistaken for current activity. Empty and unavailable role lists
are rendered explicitly rather than omitted. Watch JSON uses schema version 2
and exposes the canonical `process_scopes` collection while retaining the
earlier flat candidate fields.

## Human output structure

Current `hunt` text output is concise and finding-first. It shows the CPU
verdict, severity, and resource confidence; exact-interval PSI evidence;
bounded ranked victim candidates (at most five) and suspect candidates (at
most three), including role and confidence; relevant context and limitations;
and requested and measured timings. Suspect output explicitly states that it
is same-window correlation rather than proof of causality. Missing or partial
attribution is rendered as unavailable or incomplete rather than as an observed
empty result.

Process names are terminal-safe and bounded in text output. The default text
renderer does not dump raw host counters, rolling PSI averages, or a separate
top-ten process list. `--json` remains the full structured-evidence interface:
it retains the complete observation, typed evidence, ranked roles, capabilities,
and collection qualifiers rather than mirroring the concise text summary.

Example:

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

A healthy result should still be informative:

```text
Observed 10.0s · no significant resource contention detected.

CPU     healthy   PSI 0.2%
Memory  healthy   PSI 0.0%
I/O     healthy   PSI 0.4%

Highest CPU consumer:
  firefox [8121]  122% of one CPU

No evidence indicates that it is materially delaying other work.
```

This distinguishes "busy" from "bottlenecked".

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

Color may communicate severity but must never be the only carrier of meaning:
severity, confidence, and lifecycle words are always present in the text
itself, whether or not color is emitted.

Implemented on `hunt` and `replay` (ADR-0013):

- automatic TTY detection selects the compact report; piped/non-TTY output
  is always the legacy plain text and never carries color, regardless of
  `--no-color`,
- `--no-color` disables color on a TTY without changing the layout,
- the `NO_COLOR` environment variable (any non-empty value) is honored the
  same way.

`watch` implements the same `--no-color`/`NO_COLOR` support (ADR-0013):
automatic TTY detection selects the TUI; piped text and `--json` are always
the legacy output and never carry color. `--no-color`/`NO_COLOR` disable
color in the TUI without changing that dispatch.

Color for `hunt`/`replay`'s compact report is plain SGR escape codes in
`src/style.rs`; the watch TUI reuses the same severity-to-visual-weight
mapping (`SeverityTone`/`severity_tone`) through
`style::severity_ratatui_style`, so the two surfaces cannot drift apart on
what a given severity looks like even though they render through different
backends (ANSI text vs. `ratatui` widgets).

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
  "schema_version": 2,
  "tool_version": "0.4.1",
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

`--verbose` (`hunt`, `replay`) adds diagnostic context; it does not turn the
renderer into a raw `/proc` dump. Concretely: the compact TTY report
collapses each finding's "Context and limitations" qualifiers to a caveat
count and a small set of category tags by default (for example,
`Context: 4 caveats (causality, attribution, collection) — use --verbose for
full text`); `--verbose` restores the full verbatim qualifier messages
under each resource, matching the legacy renderer's text. JSON output is
unaffected by `--verbose` in both cases — qualifier messages are always
complete there.

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

## Compact report

`hunt` and `replay` render two text surfaces, selected by whether stdout is
a terminal (ADR-0013). Neither recomputes a diagnosis independently; both
are driven by the same single analysis pass
(`render::analyze_hunt`/`HuntAnalyses`), so they cannot disagree with each
other or with JSON output.

- **Piped or otherwise non-TTY stdout** (`stallhunt hunt | cat`, `>file`,
  CI): the legacy plain-text renderer, unchanged from pre-ADR-0013 output —
  no color, no compaction, the full stacked per-resource sections. This is
  the stable surface for scripts and existing golden fixtures.
- **A terminal**: the compact report — a header verdict line, one row per
  resource with a colored severity word and PSI evidence, victim/suspect
  candidates for pressured resources, up to three ranked cgroup findings,
  a related-evidence line for evidence chains, a collapsed caveat count
  (see "Verbose/debug output" above), and a timing footer. It is
  substantially shorter than the legacy layout for the same diagnosis —
  the multi-section fixture pair in `tests/fixtures/render/hunt-legacy-full.txt`
  versus `hunt-compact-full.txt` is roughly a 4-5x reduction in both lines
  and bytes.

`--no-color`/`NO_COLOR` affect color only; they do not switch layout back to
the legacy renderer. There is no `--format` flag — piping is the escape
hatch to the legacy layout.

## TUI

`watch` renders a full-screen terminal UI (`ratatui`/`crossterm`, ADR-0013)
when stdout is a terminal. ADR-0008 originally rejected a generic TUI
resource monitor because it "would display utilization rather than finding
lifecycle." This TUI is not that: its panels are the same finding-lifecycle
model `watch` already computed for the plain-text renderer — new,
persistent, and resolved findings, per M6 (ADR-0008) — not a live table of
per-process utilization. Small PSI indicators are supporting visuals
alongside the lifecycle panels, never the centerpiece.

The differentiator is diagnosis.

At 120×30 or larger, a 55% left column keeps the **Lifecycle** list, **Current
window**, **History**, and scrollable **Detail** pane visible. The remaining
right column is a two-column/three-row process-role grid: CPU, memory, and I/O
victim/suspect lists, with all five retained candidates in each cell. It follows
the exact selected host or cgroup path. Compact terminals show six role
summaries and collapse Detail by default; an explicit Detail choice survives a
resize and can replace Current/History. Detail includes every role plus full
qualifiers; it is not behind `--verbose`. A help overlay and persistent footer
restate that watch tracks findings, not utilization.

Keys: `q`/`Esc` quit; `↑`/`k` and `↓`/`j` select a lifecycle row;
`Enter`/`Space` toggle detail visibility; `PageUp`/`PageDown` and `Home`/`End`
scroll the wrapped detail content; `h`/`?` toggle the help
overlay; `Ctrl-C` is the same two-stage interrupt described above for
unlimited `watch` runs — the first drains the in-flight window before
exiting, the second exits immediately — except that in raw mode a local
keyboard Ctrl-C never reaches the process as `SIGINT` (the terminal driver
stops translating it once raw mode disables `ISIG`), so it is read as a key
event instead; an external `kill -INT <pid>` still works via the same
signal handler as the piped path. Redraws only happen on a window tick, a
key press, or a resize — never a busy loop, matching the "stay cheap on a
stressed system" principle.

Piped text and `--json` are completely unaffected by the TUI's existence:
`stallhunt watch | cat` and `stallhunt watch --json` still emit the exact
frames and `stallhunt.watch_window` stream documented above, with no
alternate screen and no raw mode.
