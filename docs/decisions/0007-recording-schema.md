# ADR-0007: Record normalized observations without a compatibility promise

- Status: Accepted
- Date: 2026-08-17

## Context

Milestone 5 needs a user-facing way to capture an incident and analyze it later.
The architecture already separates collection from inference so fixtures and
replays can drive the same analyzer. Hunt JSON is a presentation of findings
plus a subset of evidence; several interval durations are omitted there, and
that document is allowed to evolve as a pre-1.0 diagnostic report.

A recording that stored only findings could not be re-analyzed after inference
changes. A recording that dumped raw procfs would be larger, more sensitive,
and would re-introduce kernel-format and collector-limit coupling at replay
time.

Recordings also contain process names, device names, and cgroup paths. Those
are useful locally and unsafe to treat as ordinary log files.

## Decision

M5 recordings store **normalized interval observations**, not findings and not
raw procfs.

Replay re-runs the **current** analyzer. Identical input plus identical tool
version is deterministic. A later analyzer may produce different findings from
an older recording; that is intended, not a format break.

The on-disk document is a distinct schema from hunt JSON:

- `kind` is `bottleneck.recording`
- `schema_version` is an integer, currently `1`
- durations are integer microseconds
- each resource is `observed` or `unavailable` with a typed error
- wall-clock `recorded_at_unix_ms` is metadata only and is never used for
  interval math

Pre-1.0 recordings have **no compatibility promise**. Unknown `kind` or
`schema_version` values are rejected rather than partially interpreted.
`schema_version` exists so a later ADR can define compatibility once the model
is stable enough to support it.

Default recordings retain identifiers needed for local diagnosis: process
`comm` names, disk names, cgroup paths, and inferred systemd unit candidates.
`--redact` replaces those presentation strings with stable placeholders while
keeping PIDs, start times, major/minor keys, counters, and path hierarchy.
Redaction is not cryptographic anonymization.

New recording files are created with mode `0600`. Existing paths are not
overwritten unless `--force` is passed. Decode is bounded.

A support bundle is the recording file itself. Capture locally without
redaction, then `redact` a copy before sharing.

## Consequences

Positive:

- replay uses the same inference path as `hunt`
- fixtures and user recordings share one observation model
- privacy defaults are explicit before the format is advertised
- hunt JSON can keep evolving as a report without silently becoming a
  recording contract

Costs:

- pre-1.0 recordings may become unreadable after a schema change
- redacted names are still correlated with process keys
- microsecond duration rounding can differ slightly from a live
  `Instant::elapsed` nanosecond interval
- recordings are not a substitute for a raw kernel dump when collector bugs
  are the question

## Alternatives considered

### Reuse hunt JSON as the recording

Rejected: hunt JSON mixes findings with a presentation subset of evidence and
skips some elapsed intervals that analysis requires.

### Record findings instead of observations

Rejected: that prevents deterministic re-analysis when inference improves.

### Record raw procfs snapshots

Rejected for M5: larger, more sensitive, and replay would depend on
re-running collectors against kernel text rather than the normalized model.

### Promise compatibility in v0.1

Rejected: the normalized model is still growing. An explicit version field
plus hard rejection of unknown versions is enough until a later ADR.
