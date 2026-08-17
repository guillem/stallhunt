# Project status

Last updated: 2026-08-17

## Current milestone

**Milestone 1 — CPU contention vertical slice**

Milestones 1.1 (Rust/CLI bootstrap) and 1.2 (CPU PSI collection and
normalization) are complete. Milestone 1.3 (CPU/process collector) is next.

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
- `serde` and `serde_json` safely serialize dynamic structured output.
- Invalid CLI invocations write to stderr and exit with status 2.
- Unit tests cover command parsing, PSI parsing/fixtures, boundary and invalid
  interval normalization, and renderer semantics.
- Executable integration tests cover real host CPU PSI hunt/capability behavior
  and invalid invocation.
- Cargo formatting, Clippy, and test quality gates are documented.

## Known limitations

- CPU PSI is host-wide evidence only. There is no CPU severity/confidence
  inference, no healthy/no-contention conclusion, and no process, victim, or
  suspect attribution.
- A hunt can be incomplete if CPU PSI becomes unreadable or invalid between
  snapshots; this is reported as an explicit capability/observation limit.
- The JSON shape is bootstrap scaffolding and has no pre-1.0 compatibility
  promise beyond its explicit `schema_version` field.
- CPU PSI is the only collector and normalized interval model. No general
  telemetry framework, inference engine, or real finding exists yet.
- No CI workflow or packaging configuration exists; validation is local.

## Current recommended next task

Implement **Milestone 1.3: CPU/process collector**:

- collect `/proc/stat` CPU counters and CPU capacity context,
- enumerate processes and robustly parse `/proc/<pid>/stat`,
- use PID plus start time for process identity,
- calculate process CPU deltas over the CPU PSI observation window,
- retain explicit partial-permission/process-churn behavior.

Do not add scheduler-delay attribution until M1.4.

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

On 2026-08-17 with Rust 1.97.1 / Cargo 1.97.1, M1.2 validation ran:

```bash
cargo fmt --all -- --check
cargo clippy --locked --offline --workspace --all-targets --all-features -- -D warnings
cargo test --locked --offline --workspace --all-features
```

The sandbox could not reach the crates.io index, so validation used the locked
dependency graph from the local Cargo cache. The emitted `hunt --json` output
is structurally parsed in unit tests and was also smoke-tested against the host.

## Next milestone after CPU PSI

**Milestone 1.3 — CPU/process collector.**

See `roadmap.md`.
