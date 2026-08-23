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
--resource cpu|memory|io|all
--pid <PID>
--cgroup <PATH>
--verbose
--no-color
```

Do not add flags before a real use case exists. Implemented today:
`hunt --duration [--json] [--verbose] [--no-color]`, `replay [--json]
[--verbose] [--no-color]`, and `watch --interval [--count] [--json]
[--no-color]` (ADR-0013, ADR-0014).

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

### `watch`

M6 added `watch` (ADR-0008); ADR-0014 supersedes its TTY presentation:

```bash
stallhunt watch [--interval 2s] [--count N] [--json] [--no-color]
```

On a TTY, text output is a framed dashboard that redraws in place each
window: host PSI pressure meters with numeric percentages and status words,
up to six currently pressured cgroups, finding lifecycle rows
(`NEW`/`PERSISTENT`/`RESOLVED`), severity-history sparklines for the last 16
windows, and a footer with the SIGINT contract. Piped text appends the pre-redesign
window blocks. This is not an interactive utilization monitor and not a
generic resource dashboard.

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
status 130 (restoring the cursor first in dashboard mode). Bounded `--count`
runs retain the default signal disposition. Each window reuses the previous
endpoint snapshot. On a TTY, text renders the ADR-0014 dashboard (meters,
scoped pressure, lifecycle, history sparklines) and redraws in place with
hidden cursor; piped text appends window blocks and `--json` appends one
compact `stallhunt.watch_window` object per window. It is not hunt JSON and
not a recording, and it omits full evidence. Host memory `kind` values
already name reclaim, swap, or possible thrashing. Scoped cgroup `kind`
values name the resource and, when labeled, the mechanism
(`cgroup_memory_reclaim_pressure`, `cgroup_memory_swap_pressure`,
`cgroup_memory_possible_thrashing`, `cgroup_cpu_quota_throttle_pressure`);
identity remains path plus resource, so a mechanism change stays `persistent`.
Use `hunt --json` or `record` when the full evidence payload is required.
Invalid `--count` still exits 2.

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

Human `hunt`/`replay` text is **compact by default** (ADR-0013) and fully
detailed with `--verbose`. Both renderers are deterministic and covered by
checked-in golden fixtures.

### Compact default

The compact renderer answers the primary question first:

```text
stallhunt 0.2.0 · observed 10s
Verdict: CPU scheduling contention — high (confidence high)
  CPU      pressure  high      PSI some 23.40% · 2.3s stalled / 10s
  Memory   ok                   PSI some 0.12% · 37% used
  I/O      pressure  moderate  PSI some 12.20% · 1.2s stalled / 10s

CPU scheduling contention · high · confidence high
  Victims — observed runnable delay, not confirmed harm:
    postgres [4812]  1.81s delayed
  Suspects — same window only, not proven causal:
    rustc [9231]     583.0% of one CPU

Scoped cgroup pressure
  /app.slice/app.service · memory (reclaim) moderate · PSI some 21.0%

Related evidence
  memory reclaim pressure is consistent with block-I/O pressure in the same window (confidence low)

measured: PSI 10s · CPU/process 10s · memory PSI 10s · I/O PSI 10s
Use --verbose for full evidence, qualifiers, and timings · --json for machine-readable output
```

Rules:

- one-line verdict: the highest-severity pressured finding, an explicit
  healthy/inconclusive/no-telemetry result, or `some telemetry unavailable`;
- the resource table always shows all observed resources with the deciding
  exact-interval PSI evidence and cumulative stalled time; unavailability is
  shown as `unavailable (PSI <capability>)`, sub-second windows as
  `short window`;
- candidate lists appear only for pressured resources and are capped at
  three per role; correlation caveats stay inline;
- scoped cgroup pressure is capped at three lines plus an overflow count;
  absence is the one-line `no pressure in the bounded selection` statement,
  and an unavailable cgroup observation stays visible as
  `Scoped cgroups: unavailable (<capability>)` so collection limits are never
  silently omitted;
- chains render as one line each and never claim causality;
- the dim footer advertises `--verbose`/`--json`, and one dim line carries
  measured intervals.

Process names remain terminal-safe and bounded. The compact renderer never
dumps raw host counters, rolling PSI averages, or a top-ten process list, and
never recomputes a diagnosis — it re-formats analyzer findings.

### `--verbose`

The verbose renderer reproduces the complete pre-redesign text: every
verdict/evidence line, ranked role with confidence labels, qualifier and
limitation list, controller context, and per-resource timing:

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

`--json` remains the full structured-evidence interface regardless of detail
level: it retains the complete observation, typed evidence, ranked roles,
capabilities, and collection qualifiers.

## Negative results

A healthy compact result keeps the negative finding explicit:

```text
stallhunt 0.2.0 · observed 10s
Verdict: no meaningful contention detected
  CPU      ok   PSI some 0.20% · 20ms stalled / 10s
  Memory   ok   PSI some 0.00% · 0ms stalled / 10s · 95% used
  I/O      ok   PSI some 0.40% · 40ms stalled / 10s

Scoped cgroups: no pressure in the bounded selection
Use --verbose for full evidence, qualifiers, and timings · --json for machine-readable output
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

Color communicates severity but is never the only carrier of meaning; see
the implemented policy under [Color and TTY presentation](#color-and-tty-presentation).

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

`--verbose` selects the full human renderer (ADR-0013): every qualifier,
limitation, ranked role label, and measured timing. It does not turn the
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

## Color and TTY presentation

Implemented policy (ADR-0013, ADR-0014):

- Color is emitted only when stdout is a terminal, `--no-color` was not
  passed, and the `NO_COLOR` environment variable is unset or empty.
- One shared severity palette is used everywhere: `ok`/none green, low cyan,
  moderate yellow, high bright red, severe bold red; `unconfirmed` magenta,
  `unavailable` dim; dashboard section headers are bold.
- Color is never the only carrier of meaning: every colored element keeps its
  textual label, percentage, or word, and stripping SGR sequences from any
  colored output reproduces the colorless output.
- `--verbose` hunt text and all piped/non-TTY output are unstyled plain text.

## TTY dashboard for `watch`

`watch` text on a TTY renders the ADR-0014 dashboard: PSI pressure meters,
scoped pressure, lifecycle rows, and severity-history sparklines, redrawn in
place each window with a hidden cursor and no alternate screen. Piped text and
`--json` keep the ADR-0008 append contract.

The differentiator remains diagnosis. Watch does not show per-process
utilization tables, and there is no interactive navigation; if a future TUI
adds interaction it should display and expand changing findings rather than
reproduce `htop`.
