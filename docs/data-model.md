# Data model

## Design goals

The model must support:

- deterministic analysis,
- partial telemetry,
- evidence-backed findings,
- explicit confidence,
- process lifetime safety,
- future recording/replay,
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

Use normalized cgroup-v2 path plus mount identity if necessary.

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
    IoBytes {
        process: ProcessKey,
        read_bytes: u64,
        write_bytes: u64,
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

Design the normalized model to be serializable from the beginning.

Do not promise a stable public recording format in v0.1.

Recommended early approach:

- internal serde representation,
- fixture files checked into tests,
- explicit schema version field.

Example:

```json
{
  "schema_version": 1,
  "window": {},
  "capabilities": {},
  "host": {},
  "processes": [],
  "devices": []
}
```

When record/replay becomes user-facing, create an ADR defining compatibility expectations.

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
