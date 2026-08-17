# CLI and UX

## UX goal

The default command should answer a question, not dump a dashboard.

The terminal output should be useful to a human who knows Linux but does not want to manually correlate five tools.

## Command shape

Working binary name below is `bottleneck`.

Names are provisional.

### Primary command

```bash
bottleneck hunt
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

Do not add flags before a real use case exists.

## Early command set

### `hunt`

Run a bounded diagnosis.

### `capabilities`

Show available telemetry and permission limitations.

### `version`

Standard version information.

Delay `watch`, `record`, `replay`, `explain`, daemon mode, TUI, etc. until the core diagnosis is trustworthy.

## Current CPU diagnosis behavior

Milestone 1 implements:

```text
bottleneck hunt [--duration <DURATION>] [--json]
bottleneck capabilities [--json]
bottleneck version
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

Color may communicate severity but must never be the only carrier of meaning.

Support:

- automatic TTY detection,
- `--no-color`,
- `NO_COLOR` convention if practical.

Do not overdesign terminal visuals before core output stabilizes.

## Exit codes

Current bootstrap policy:

- `0`: the requested command completed, including an explicitly unavailable
  bootstrap `hunt`,
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
bottleneck hunt --json
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
  "tool_version": "0.1.0",
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

## Stable output policy

Human output may evolve freely before 1.0.

JSON compatibility needs an explicit versioning policy before external integrations are encouraged.

Until then:

- include `schema_version`,
- document that pre-1.0 schema may change,
- prefer additive changes where convenient.

## Verbose/debug output

`--verbose` should add diagnostic context, not turn the normal renderer into a raw `/proc` dump.

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
100 ms through 5 minutes; the default is 10 seconds.

These are initial bounded-hunt safety limits, not validated inference
thresholds. Future analyzers must qualify windows that are too short for strong
conclusions, and experiments may justify revising the limits.

Warn or reduce confidence for observation windows too short to support robust inference.

## TUI

A TUI is explicitly not an early priority.

The differentiator is diagnosis.

If added later, it should display changing findings rather than simply reproduce `htop`.
