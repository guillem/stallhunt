# Data model

## Design goals

The model must support:

- deterministic analysis,
- partial telemetry,
- evidence-backed findings,
- explicit confidence,
- process lifetime safety,
- recording/replay,
- human and JSON rendering.

## Time model

Use monotonic time for intervals whenever possible.

Represent an observation window as:

```rust
struct ObservationWindow {
    started_at: MonotonicTimestamp,
    ended_at: MonotonicTimestamp,
}
```

Wall-clock timestamps may be recorded for user context, but interval calculations must not depend on system-clock adjustments.

## Raw vs normalized data

### Raw observation

A raw observation is a direct reading at one instant.

Examples:

- cumulative process CPU ticks,
- cumulative process read bytes,
- PSI cumulative stall microseconds,
- `/proc/stat` counters.

### Normalized interval

Derived from at least two raw observations.

Examples:

- process CPU seconds consumed,
- CPU share,
- runnable delay added,
- I/O bytes/sec,
- pressure percentage during the exact observation window.

This distinction is essential for replay and testing.

## Identity

### Process

Do not identify a process solely by PID.

Suggested identity:

```rust
struct ProcessKey {
    pid: u32,
    start_time_ticks: u64,
}
```

Optional metadata:

```rust
struct ProcessIdentity {
    key: ProcessKey,
    comm: String,
    cmdline: Option<Vec<String>>,
    executable: Option<PathBuf>,
    uid: Option<u32>,
    parent: Option<ProcessKey>,
    cgroup: Option<CgroupKey>,
}
```

Metadata may disappear between reads.

### Thread

Later:

```rust
struct ThreadKey {
    process: ProcessKey,
    tid: u32,
}
```

### Cgroup

M4's cgroup key is a normalized cgroup-v2 path plus discovered mount identity.
Preserve scope separately from an optional
path-derived systemd unit candidate; the latter is presentation metadata, not a
stable identity or authoritative manager lookup.

### Block device

Prefer stable major/minor identity internally.

Names such as `nvme0n1` are presentation metadata.

## Capability model

Example:

```rust
struct Capabilities {
    psi_cpu: CapabilityState,
    psi_memory: CapabilityState,
    psi_io: CapabilityState,
    process_schedstat: CapabilityState,
    process_io: CapabilityState,
    cgroup_v2: CapabilityState,
    cgroup_cpu: CapabilityState,
    cgroup_memory: CapabilityState,
    cgroup_io: CapabilityState,
    cgroup_psi: CapabilityState,
    delay_accounting: CapabilityState,
}
```

Where state distinguishes:

- available,
- unavailable,
- permission denied,
- unsupported,
- failed.

Do not reduce everything to bool.

## Evidence

Every finding is supported by typed evidence.

Suggested concept:

```rust
enum Evidence {
    Pressure {
        resource: PressureResource,
        scope: Scope,
        some_fraction: f64,
        full_fraction: Option<f64>,
        window: ObservationWindow,
    },
    CpuConsumption {
        process: ProcessKey,
        cpu_seconds: Duration,
        normalized_cores: f64,
    },
    RunnableDelay {
        process: ProcessKey,
        delay: Duration,
        window: ObservationWindow,
    },
    IoAccounting {
        process: ProcessKey,
        storage_read_bytes: Option<u64>,
        charged_write_bytes: Option<u64>,
        cancelled_write_bytes: Option<u64>,
    },
    MissingCapability {
        capability: Capability,
        effect: String,
    },
}
```

Exact Rust representation can evolve.

Requirements:

- evidence is serializable,
- evidence can render to concise human text,
- evidence references stable entity keys,
- evidence states units unambiguously.

## Findings

Suggested structure:

```rust
struct Finding {
    id: FindingId,
    kind: FindingKind,
    resource: Resource,
    severity: Severity,
    confidence: Confidence,
    window: ObservationWindow,
    summary: String,
    impact: Impact,
    victims: Vec<AttributedEntity>,
    suspects: Vec<AttributedEntity>,
    evidence: Vec<Evidence>,
    qualifiers: Vec<Qualifier>,
}
```

## Severity

Severity represents impact, not certainty.

Use an internal numeric score if helpful, but expose a small stable vocabulary:

- none,
- low,
- moderate,
- high,
- severe.

Avoid magical thresholds spread throughout the code.

M1.5 uses typed `CpuFinding`, `CpuEvidence`, `Victim`, `Suspect`, and
`Qualifier` values. Evidence retains exact PSI fraction, cumulative delta and
window plus optional host/load context. Victims retain stable task count and
summed runnable delay; suspects retain same-window CPU fraction.

Centralize scoring configuration.

M2 adds typed `MemoryFinding` and `MemoryEvidence` values. The evidence retains
the exact memory-PSI `some` interval, optional independently-qualified `full`
interval, end-of-window meminfo gauges, optional vmstat deltas, capability
states, the independent memory-context interval, and qualifiers. `full` is
represented separately because it is a subset of `some`, not a second pressure
amount to add. Pressure confidence and optional VM-counter mechanism confidence
are separate. The host-memory finding has no victims or suspects: the input
evidence is host-wide and the collector does not walk processes.

M3 adds `IoFinding`/`IoEvidence`, device activity candidates keyed by
major/minor with name-change lifecycle validation, and process I/O-accounting
activity candidates keyed by PID plus start
time. Diskstats sectors remain raw 512-byte-sector units, `in_flight` remains an
end-snapshot gauge, and each counter delta may be absent after reset. The two
candidate lists are correlation-only same-window context, not a process-to-device
mapping, causal chain, or victim model.

M4 adds an additive `CgroupObservation` to pre-1.0 JSON: mount identity,
stable process-to-cgroup memberships, bounded snapshots, per-scope PSI
intervals, controller context, inferred unit candidates, and typed collection
issues. Its capability state is derived from those issues and per-file states,
not merely the presence of an observation. Membership retains the process key proven by a
stat-cgroup-stat sequence. A cgroup PSI finding carries cgroup scope and must
not be merged with or substituted for a host finding; no model edge implies a
process-to-device or cross-cgroup causal relation. A scoped memory pressure
finding may carry an optional `mechanism` of `reclaim` or `swap` with separate
low `mechanism_confidence` when `memory.stat` page deltas are present in the
same window, `possible_thrashing` with medium `mechanism_confidence` when the
host thrashing conjunction is met at cgroup scope, or `cpu_quota_throttle` when
a scoped CPU finding has a positive `cpu.stat` `throttled_usec` delta. Those
fields are omitted when unlabeled. `memory.events` high/max remain chain-only
evidence and do not label the finding. `nr_throttled` without throttled time
does not label CPU.

## Confidence

Suggested vocabulary:

- low,
- medium,
- high.

Optionally retain a continuous internal score, but do not imply statistical precision unless the method justifies it.

Confidence should increase when independent evidence converges.

Confidence should decrease when:

- key telemetry is absent,
- attribution is only temporal correlation,
- multiple suspects are indistinguishable,
- observation window is too short,
- data contradicts the hypothesis.

## Victim and suspect attribution

An entity can have independent roles:

```rust
struct Attribution {
    entity: EntityRef,
    role: AttributionRole,
    strength: f64,
    evidence_ids: Vec<EvidenceId>,
}
```

Possible roles:

- victim,
- suspect,
- both,
- context-only.

Do not assume the highest resource consumer is automatically the primary cause.

## Impact model

Prefer measurable lost time.

Examples:

- fraction of wall time with CPU pressure,
- runnable delay,
- I/O wait duration,
- reclaim delay,
- number of affected tasks,
- latency percentiles later.

A finding may include more than one impact measure.

## Qualifiers

Qualifiers explain limitations.

Examples:

- "Per-task scheduler delay unavailable on this kernel."
- "Suspect attribution is based on concurrent CPU consumption."
- "Observation window was only 2 seconds."
- "Some processes were unreadable due to permissions."

These should survive JSON output.

## Snapshot/replay format

M5 recordings are a distinct on-disk document from hunt JSON (ADR-0007).

They store normalized interval observations so replay can re-run current
inference. Findings are not stored. Hunt JSON remains a diagnostic report and
is rejected if passed to `replay`.

Current recording envelope:

```json
{
  "kind": "stallhunt.recording",
  "schema_version": 1,
  "tool_version": "0.1.0",
  "recorded_at_unix_ms": 0,
  "redaction": "none",
  "requested_duration_ms": 10000,
  "observation": {}
}
```

Durations are integer microseconds. Each resource is `observed` or
`unavailable` with a typed error. Wall-clock `recorded_at_unix_ms` is metadata
only.

Pre-1.0 recordings have no compatibility promise. Legacy recordings with
`kind` `bottleneck.recording` are accepted on replay. Unknown `kind` or
`schema_version` values are rejected. A later ADR can define compatibility
once the model is stable.

## Watch window model

M6 adds a compact rolling-window document distinct from hunt JSON and from
recordings (ADR-0008). Each window stores:

- window index and requested interval,
- current host CPU/memory/I/O observation status,
- bounded cgroup pressure identities,
- lifecycle entries (`new`, `persistent`, `resolved`) with consecutive-window
  counts and optional previous severity,
- the last 16 compact history events.

Finding identity is host CPU, host memory, host I/O, or a cgroup path plus
resource. Healthy and insufficient observations do not create identities.
Missing data leaves an active identity persistent and unconfirmed. A cgroup
lifecycle `kind` names the scoped resource and any reclaim, swap, possible-
thrashing, or CPU quota-throttle label; changing that label does not create a
new identity. Host memory lifecycle kinds likewise distinguish generic,
reclaim, swap, and possible-thrashing pressure while preserving the single host
memory identity. The complete pressure-kind catalog is in `cli-ux.md`.

Watch JSON `kind` is `stallhunt.watch_window`. It is not replayable as a
recording and does not carry full evidence.

## Evidence chains

M8 adds an optional relation between already-produced findings (ADR-0009,
ADR-0010, ADR-0011).

A chain is not a resource verdict. Two implemented paths exist:

- host: `from` is a memory finding labeled reclaim, swap, or possible
  thrashing, `to` is an I/O pressure finding, and VM-counter mechanism evidence
  is required
- same-cgroup: `from`/`to` are memory and I/O pressure findings that share one
  cgroup path, and that memory finding has a positive `memory.events` `high` or
  `max` delta, or positive `memory.stat` `pgscan_direct` and `pgsteal_direct`
  deltas, or a positive `pswpin` delta

In both cases:

- `relation` is `consistent_with`,
- confidence is never high,
- coincident PSI without the independent mechanism does not create a chain.

Host and cgroup findings are not linked to each other. Different cgroup paths,
including ancestor and child, are not linked. CPU is not linked to I/O. At most
16 same-cgroup chains are retained. Watch does not track chain identities.

## Missing data

Use `Option` only when "not present" is semantically sufficient.

Where the reason matters, represent it explicitly.

Bad:

```rust
sched_delay: Option<Duration>
```

Potentially better:

```rust
sched_delay: Availability<Duration>
```

with:

```rust
enum Availability<T> {
    Available(T),
    Unsupported,
    PermissionDenied,
    Disappeared,
    Invalid,
}
```

Do not overuse this wrapper on every field; reserve it for diagnostically important absence.
