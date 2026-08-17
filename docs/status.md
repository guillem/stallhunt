# Project status

Last updated: 2026-08-17

## Current milestone

**Milestone 1 — CPU contention vertical slice**

Milestones 1.1 through 1.4 are complete. M1.4 adds bounded scheduler-delay
evidence; Milestone 1.5 (CPU inference) is next.

## Implemented

- A single stable-Rust package builds the `bottleneck` binary.
- The package forbids unsafe Rust.
- Real `hunt`, `capabilities`, help, and version command structure exists.
- `hunt` accepts `--duration` values from 100 ms through 5 minutes, including
  exact-millisecond decimal values, and defaults to 10 seconds.
- `hunt` and `capabilities` support separate text and JSON render paths.
- CPU PSI `some` parsing retains rolling averages and the raw cumulative
  microsecond total. The parser validates required fields and ranges, tolerates
  unknown future fields, rejects duplicates/malformed input, and treats CPU
  `full` as compatibility data rather than evidence.
- `hunt` now performs a bounded CPU PSI two-snapshot observation and derives
  exact-interval pressure from `some.total` delta divided by measured monotonic
  elapsed microseconds. Counter regression, an unmeasurable interval, and a
  delta exceeding elapsed time are rejected rather than clamped.
- `capabilities` probes CPU PSI and distinguishes available, unsupported,
  permission-denied, and failed states. `hunt` reports incomplete observations
  explicitly without producing findings.
- Text and JSON output include typed CPU PSI interval evidence and rolling
  averages while explicitly limiting the result to raw evidence.
- `hunt` also collects `/proc/stat`, `/proc/loadavg`, and bounded two-snapshot
  `/proc/<pid>/stat` process data over the same observation window. It reports
  host CPU counter deltas, logical CPU count, load context, and CPU deltas for
  process identities that match on both PID and start-time ticks.
- PSI and CPU/process pairs each use their own completed-snapshot monotonic
  interval. `loadavg` is best-effort context and is explicitly optional rather
  than invalidating CPU evidence.
- `/proc/stat`, `/proc/loadavg`, and process-stat parsers reject malformed
  required fields. Process-stat parsing handles spaces and `)` in `comm`; text
  output sanitizes control characters and bounds names to 80 characters.
- Host CPU accounting does not double-count guest counters. It preserves
  iowait separately and falls back to non-iowait aggregate deltas when iowait
  decreases, as Linux permits.
- Process enumeration is sorted and capped at 4,096 PIDs per snapshot.
  Disappearing, permission-denied, unreadable, malformed, directory-iteration,
  cap-limited, and inconsistent process-counter observations are retained as
  typed JSON collection context.
  Hitting the cap makes process context incomplete; a failed global process
  enumeration preserves host CPU evidence but marks process context failed.
- `rustix` 1.x with only its `param` feature obtains `USER_HZ` safely for
  process CPU fractions; raw ticks remain in the observation and JSON output.
- `serde` and `serde_json` safely serialize dynamic structured output.
- M1.4 probes per-task scheduler accounting directly; the unrelated
  `kernel.sched_schedstats` switch is not used as a capability gate. It retains
  stable `(tid,starttime)` task counters, sums checked runnable-delay
  deltas to stable process identities, and caps task samples at 16,384 per
  endpoint after the existing PID cap. Direct task schedstat reads determine
  availability; task churn, TID reuse, permissions, malformed data, and caps are
  explicit JSON context. Candidate delay is raw summed-thread evidence.
- Invalid CLI invocations write to stderr and exit with status 2.
- Unit tests cover command parsing, PSI parsing/fixtures, boundary and invalid
  interval normalization, and renderer semantics.
- Executable integration tests cover real host CPU PSI hunt/capability behavior
  and invalid invocation.
- Cargo formatting, Clippy, and test quality gates are documented.

## Known limitations

- CPU PSI remains host-wide evidence only. There is no CPU severity/confidence
  inference, no healthy/no-contention conclusion, and no victim or suspect
  attribution. Process CPU consumption is concurrent context, not causal
  evidence.
- A hunt can be incomplete if CPU PSI becomes unreadable or invalid between
  snapshots; this is reported as an explicit capability/observation limit.
- The JSON shape is bootstrap scaffolding and has no pre-1.0 compatibility
  promise beyond its explicit `schema_version` field.
- Scheduler delay is raw evidence only; there is no severity/confidence
  inference, healthy result, victim conclusion, suspect ranking, or causality.
  Tasks whose entire lifetime falls between snapshots are not observable. No
  general telemetry framework, inference engine, or real finding exists yet.
- Scheduler identity validation can require three procfs file reads for each of
  up to 16,384 selected tasks per endpoint. The collector is bounded, but its
  observer overhead still needs measurement in M1.6.
- No CI workflow or packaging configuration exists; validation is local.

## Current recommended next task

Implement **Milestone 1.5: CPU inference**:

- establish contention from exact-interval CPU PSI and emit an explicit
  no-meaningful-contention result when pressure is negligible,
- centralize provisional severity thresholds and keep confidence independent,
- rank runnable-delay victim candidates separately from same-window CPU
  consumers, with suspect confidence capped by correlation-only evidence,
- cover positive, negative, boundary, missing-data, and contradictory-evidence
  cases with deterministic normalized fixtures.

Do not broaden into memory or I/O collection before M1.6 validates the CPU
slice.

## Current design risks

### R1: False causality

The project can lose credibility if it equates "largest consumer" with "cause".

Mitigation:
- separate resource diagnosis confidence from suspect confidence,
- retain evidence/qualifiers,
- introduce event telemetry only when needed.

### R2: Scope explosion

Linux exposes huge amounts of telemetry.

Mitigation:
- add telemetry only for concrete diagnostic questions,
- work in vertical slices.

### R3: Observer overhead

Naive per-process sampling can become expensive on large hosts.

Mitigation:
- measure early,
- optimize based on evidence,
- consider staged collection later.

### R4: Kernel/configuration variability

Some useful fields depend on kernel configuration, permissions or version.

Mitigation:
- explicit capabilities,
- graceful degradation,
- fixtures from varied environments.

### R5: Premature eBPF complexity

eBPF could dominate the project before the inference model proves useful.

Mitigation:
- eBPF prohibited as MVP dependency by ADR-0003.

### R6: Pre-1.0 JSON evolution

Dynamic output is serialized with `serde_json`, but the shape remains pre-1.0
and can evolve as the normalized model grows.

Mitigation:
- keep `schema_version` explicit,
- do not promise pre-1.0 compatibility yet.

## Known open decisions

Not yet decided:

- final project/binary name,
- license,
- minimum Rust version,
- minimum Linux kernel/support baseline,
- long-term CLI argument parsing strategy,
- serialization crate/versioning policy for dynamic JSON,
- error-handling approach beyond the current small CLI,
- color/terminal crate,
- eventual eBPF framework,
- CI provider/configuration,
- packaging/distribution.

These should be decided when implementation makes the tradeoff concrete, not
all at bootstrap.

## Last meaningful validation

On 2026-08-17 with Rust 1.97.1 / Cargo 1.97.1, M1.4 validation ran:

```bash
cargo fmt --all -- --check
cargo clippy --locked --offline --workspace --all-targets --all-features -- -D warnings
cargo test --locked --offline --workspace --all-features
```

Validation uses the locked dependency graph from the local Cargo cache. The 45
unit and 6 executable integration tests cover strict schedstat parsing, direct
fixture-tree collection, stable task aggregation, TID reuse, thread churn,
counter regression, bounded PID/TID selection, partial rendering, and earlier
CPU/PSI behavior. On the Linux 7.1.5 validation host, the
`kernel.sched_schedstats` sysctl was `0` while direct per-task schedstat remained
available; host hunt JSON retained stable scheduler-delay intervals and
reported no scheduler collection issues.

## Next milestone

**Milestone 1.5 — CPU inference.**

See `roadmap.md`.
