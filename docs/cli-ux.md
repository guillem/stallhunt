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

## Current CPU telemetry behavior

Milestone 1.1 implements:

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
A successful observation uses JSON `status: "observed"`; unavailable or invalid
CPU PSI or CPU/process collection produces `status: "incomplete"`, an
explicit qualifier, and no findings. When either collector succeeds, its
partial evidence remains in an `observation` object; it is `null` only when no
complete evidence is available.

This is evidence collection, not a CPU bottleneck finding: the output must not
claim severity, healthy/no-contention status, victims, suspects, or causality.
Process CPU consumption is explicitly concurrent context, not a causal claim.
Scheduler-delay candidates are summed stable-thread evidence, not confirmed
victims.
`capabilities` probes CPU PSI and reports `available`, `unsupported`,
`permission_denied`, or `failed`.

The top-level `status: "observed"` in capability JSON means the probe completed;
the nested capability state is authoritative and may still be `unsupported`,
`permission_denied`, or `failed`.

## Human output structure

Recommended ordering:

1. one-line health summary,
2. ranked findings,
3. evidence per finding,
4. negative findings / important non-problems,
5. capability limitations if they materially affect confidence.

Example:

```text
Observed 10.0s · 8 CPUs · 214 processes

SYSTEM HEALTH: DEGRADED

1. CPU scheduling contention                         HIGH
   Severity:    severe
   Confidence:  high
   Impact:      CPU pressure during 23.4% of the observation

   Most affected:
     postgres [4812]     1.81s runnable delay
     nginx [5120]        0.62s runnable delay

   Likely contributors:
     rustc [9231]        5.84 CPU-s (58% of host capacity)
     ffmpeg [9401]       1.92 CPU-s (19%)

   Evidence:
     CPU PSI some        23.4%
     CPU utilization     97.1%
     runnable/total      14/623

   Attribution note:
     Contributor ranking is based on CPU consumption during
     the same observation window; exact scheduler interference
     is not traced in this release.

Memory: no meaningful pressure detected.
I/O:    no meaningful pressure detected.
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

Example shape:

```json
{
  "schema_version": 1,
  "tool_version": "0.1.0",
  "observation": {
    "duration_ms": 10000
  },
  "capabilities": {},
  "findings": [
    {
      "kind": "cpu_scheduler_contention",
      "severity": "severe",
      "confidence": "high",
      "victims": [],
      "suspects": [],
      "evidence": [],
      "qualifiers": []
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
