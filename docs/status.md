# Project status

Last updated: 2026-08-17

## Current milestone

**Milestone 4 — Cgroup/systemd awareness**

Milestone 1 — the CPU contention vertical slice, including M1.6 validation and
overhead measurement — and M3 block-I/O pressure are functionally complete.
M3's bounded controlled competing-I/O acceptance established a PSI-backed
resource finding with qualified same-window candidates. It did not establish
victim attribution, process-device mapping, or causality. M2's first
host-memory collector/analyzer/output slice is implemented, but safely
controlled harmful-memory-pressure validation remains open.

M4 design is accepted in ADR-0006; implementation and validation have not yet
landed. The slice is cgroup-v2-only, membership-first, bounded, and
permission-aware: mount discovery comes from mountinfo, membership from `0::`,
and a stat-cgroup-stat identity check prevents a moved/reused PID from being
attributed. It will read selected mapped cgroups and ancestors rather than a
whole tree, limit itself to 1,024 PIDs and 2,048 groups plus depth/path/file
budgets, and add only scoped PSI verdicts with controller context. Systemd unit
names will be optional inferred path metadata; no D-Bus dependency is planned.

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
  permission-denied, and failed states. A valid CPU PSI interval still produces
  a CPU resource verdict if host/process context is incomplete; attribution is
  omitted and qualified. Invalid or unavailable CPU PSI produces no assessment.
- Text and JSON output include typed CPU PSI interval evidence, rolling
  averages, and evidence-backed CPU findings or an explicit insufficient-data
  result.
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
- M1.5 analyzes normalized CPU evidence without reading procfs: exact-interval
  CPU PSI alone establishes the resource verdict. The effective diagnostic and
  resource-confidence window is the shorter of requested and measured PSI
  duration; a requested duration below one second remains smoke mode. Otherwise
  the effective window must be at least one second. Provisional `<1%`,
  `1/5/15/30%` boundaries produce an explicit no-meaningful-contention finding
  or low, moderate, high, and severe contention. Stable scheduler-delay
  candidates and same-window CPU consumers are separately ranked, qualified
  victims and suspects; neither role proves causality.
- Invalid CLI invocations write to stderr and exit with status 2.
- Unit tests cover command parsing, PSI parsing/fixtures, boundary and invalid
  interval normalization, pure CPU analyzer positive/negative/boundary,
  missing-data, and contradictory-evidence cases, plus renderer semantics.
- Normalized JSON fixtures cover healthy, saturated, busy-but-not-pressured,
  and scheduler-accounting-unavailable CPU analysis inputs.
- Executable integration tests cover real host CPU PSI hunt/capability behavior
  and invalid invocation.
- M1.6 makes default text output concise and finding-first. A fixed normalized
  observation drives checked-in golden text coverage, and structural tests cover
  JSON output. JSON intentionally remains the full structured-evidence surface:
  complete observation, evidence, ranked roles, capabilities, and collection
  qualifiers are retained even when text omits raw detail.
- The opt-in `tests/cpu_acceptance.rs` rootless acceptance test creates bounded
  oversubscription only on Linux with readable CPU PSI and at most eight logical
  CPUs. It owns busy workers with RAII cleanup and bounds the hunt with a timeout.
- `tools/measure-overhead.sh` is an opt-in, scenario-specific release-binary
  harness for baseline, process, churn, and CPU-stress measurements. It may use
  an already-installed `stress-ng`, never installs it, and has no CI timing gate.
- M2 reads bounded host `/proc/pressure/memory`, `/proc/meminfo`, and selected
  `/proc/vmstat` snapshots around the existing one requested sleep. Each
  resource pair uses its own completed monotonic interval because collection is
  sequential.
- Memory PSI `some` is the sole memory resource-verdict signal. Valid `full` is
  retained only as a separately-qualified non-additive subset; a missing or
  interval-invalid `full` cannot invalidate valid `some`. Meminfo occupancy/swap allocation and
  vmstat counters only classify or qualify a PSI verdict.
- M2 produces typed host-memory findings for no harmful pressure, generic active
  pressure, reclaim pressure, swap pressure, possible thrashing, and insufficient
  observation. The slice has no process walk or process attribution; all memory
  evidence is explicitly host-wide.
- Deterministic memory parser/normalization/analyzer/renderer fixtures cover
  positive, negative, boundary, missing, and contradictory cases. A live healthy
  memory smoke passed, including graceful capability behavior.
- M3 reads bounded host I/O PSI, `/proc/diskstats`, and `/proc/<pid>/io` around
  the same requested sleep. Each resource pair retains its own monotonic interval
  because collection is sequential. Diskstats is capped at 4,096 devices; process
  I/O is capped at 1,024 PIDs and uses stat-io-stat identity validation, at most
  3,072 reads per endpoint. Diskstats input is capped at 1 MiB.
- Exact I/O PSI `some` is the sole I/O resource-verdict signal. Valid `full` is
  retained as a non-additive subset. Diskstats preserves raw 512-byte sector
  units, end `in_flight` gauge, independent counter resets, and distinct busy /
  weighted-time semantics. Process `read_bytes`, charged `write_bytes`, and
  `cancelled_write_bytes` remain distinct from logical `rchar`/`wchar` context.
  Process-I/O attribution is explicitly unsupported on 32-bit targets because
  the kernel documents possible torn 64-bit counter reads.
- M3 ranks positive disk and process I/O-accounting activity only during PSI
  pressure. Candidates are same-window context, not victims, process-device
  mappings, or causal claims. High activity with low PSI is explicitly healthy.
- Deterministic I/O parser/normalization/analyzer/renderer fixtures and a live
  healthy smoke passed. The ignored rootless M3 acceptance also ran without
  skipping on Linux 7.1.5: two owned `stress-ng` HDD workers (64 MiB each,
  direct/sync/fsync, checkout-local temporary path) remained alive through a
  two-second hunt and cleanup passed. It found `io_pressure` with PSI `some`
  13.6029889%, three device candidates, and two process-I/O candidates.
- Cargo formatting, Clippy, and test quality gates are documented.

## Known limitations

- CPU PSI is host-wide evidence. M1.5 provides provisional severity and
  qualified attribution, but process consumers remain same-window correlation,
  not proven causes.
- A hunt can be incomplete if CPU PSI becomes unreadable or invalid between
  snapshots; this is reported as an explicit capability/observation limit.
- The JSON shape is bootstrap scaffolding and has no pre-1.0 compatibility
  promise beyond its explicit `schema_version` field.
- Scheduler-delay candidates are observed stable-task evidence, not proof of
  user-visible harm. Tasks whose entire lifetime falls between snapshots are
  not observable.
- Scheduler identity validation can require three procfs file reads for each of
  up to 16,384 selected tasks per endpoint. M1.6 exercised a representative
  73 stable tasks / 146 endpoint reads in the clean sleeping-thread acceptance
  case, but high-visible-PID/task overhead remains unvalidated.
- No CI workflow or packaging configuration exists; validation is local.
- M2 has not yet demonstrated safely controlled real-host harmful memory
  pressure. Reclaim and swap labels have separate low mechanism confidence;
  possible thrashing requires material direct-reclaim plus bidirectional-swap
  rates and is capped at medium mechanism confidence. All remain
  implementation/fixture validated rather than experimentally validated.
- M3's controlled PSI/resource and same-window-candidate exit is validated,
  but it has not validated I/O victims, process-device mapping, or causality.
  High-visible-PID observer overhead also remains unvalidated.
- CPU thresholds are provisional and event telemetry is still required for
  stronger causal attribution.

## Current recommended next task

Finish M4 cgroup/service attribution according to ADR-0006:

- implement mountinfo / `0::` discovery and bounded stat-cgroup-stat process
  membership; collect only mapped groups plus ancestors;
- add scoped PSI/controller context, capabilities, text/JSON evidence, and
  deterministic lifecycle/budget/permission fixtures;
- retain host PSI verdicts and qualified M1/M3 candidate semantics rather than
  treating cgroup membership, controller activity, or inferred systemd metadata
  as causal proof;
- preserve the M2 debt: safely demonstrate harmful memory pressure separately,
  with exact memory PSI `some` as verdict and `full`, meminfo, and vmstat as
  non-additive context only.

Do not introduce eBPF as a prerequisite for M4.

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

On 2026-08-17 with Rust 1.97.1 / Cargo 1.97.1, the deterministic gate ran:

```bash
cargo fmt --all -- --check
cargo clippy --locked --offline --workspace --all-targets --all-features -- -D warnings
cargo test --locked --offline --workspace --all-features
```

Validation uses the locked dependency graph from the local Cargo cache. The
default gate has 103 unit tests and six CLI tests; three ignored host-workload
tests remain opt-in. On Linux 7.1.5,
`cargo test --locked --offline --test io_acceptance -- --ignored --nocapture`
ran rather than skipping. Its exactly two owned `stress-ng` HDD workers used
64 MiB each with direct/sync/fsync I/O on a checkout-local temporary path under
an eight-second coordinator bound. The two-second hunt found `io_pressure`:
PSI `some` was 0.13602988901958982 (13.6029889%), with measured PSI,
diskstats, and process-I/O windows of 2,002,876 us, 2,000,947 us, and
2,000,534 us respectively; it reported three device candidates and two process
suspects. The workload remained alive after measurement and owned cleanup
passed. This validates neither a victim, process-device mapping, nor causality.

The separate M3 live healthy smoke had all I/O capabilities available, six
stable disk devices, and four stable process-I/O intervals. A release M3
baseline short measurement reported wall 1.00s, max RSS 2592 KiB, PSI skew
1.231 ms, and displayed user/system time of 0.00s. High-visible-PID overhead
remains unvalidated. Full controlled-load and release-harness ranges are in
`docs/experiments.md`.

The current M2 slice also passed its deterministic memory parser, interval,
analyzer, renderer, and executable healthy-host smoke coverage. That smoke
observed a healthy host and validates capability/degradation behavior; it does
not substitute for a controlled harmful-memory-pressure experiment.
