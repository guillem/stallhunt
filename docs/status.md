# Project status

Last updated: 2026-08-17

## Current milestone

**Milestone 1 — CPU contention vertical slice**

Milestone 1.1 (Rust/CLI bootstrap) is complete. Milestone 1.2 (CPU PSI
collection and normalization) is the current recommended work.

## Implemented

- A single stable-Rust package builds the `bottleneck` binary.
- The bootstrap has no third-party dependencies and forbids unsafe Rust.
- Real `hunt`, `capabilities`, help, and version command structure exists.
- `hunt` accepts `--duration` values from 100 ms through 5 minutes, including
  exact-millisecond decimal values, and defaults to 10 seconds.
- `hunt` and `capabilities` support separate text and JSON render paths.
- Bootstrap output explicitly distinguishes unavailable implementation from a
  completed healthy diagnosis: no observation is claimed and no findings are
  fabricated.
- Invalid CLI invocations write to stderr and exit with status 2.
- Unit tests cover command parsing, duration success/boundary/failure cases,
  and renderer semantics.
- Executable integration tests cover help, text/JSON placeholder behavior,
  capability behavior, and invalid invocation.
- Cargo formatting, Clippy, and test quality gates are documented.

## Known limitations

- `hunt` does not yet read telemetry, wait for the requested duration, or
  analyze the host. A valid placeholder invocation exits successfully but
  carries an explicit unavailable status.
- `capabilities` does not probe the host; it reports `not_checked`.
- The JSON shape is bootstrap scaffolding and has no pre-1.0 compatibility
  promise beyond its explicit `schema_version` field.
- No collector, raw observation model, normalization, inference, or real
  finding exists yet.
- No CI workflow or packaging configuration exists; validation is local.

## Current recommended next task

Implement **Milestone 1.2: CPU PSI collection and parsing** as one vertical
slice:

- parse `/proc/pressure/cpu` robustly,
- represent raw cumulative `some` observations and rolling averages,
- calculate pressure over the exact observation interval from the cumulative
  `total` delta,
- handle malformed, missing, unsupported, and unreadable PSI explicitly,
- make `hunt` perform the bounded two-snapshot observation needed for CPU PSI,
- make `capabilities` report actual CPU PSI availability,
- add deterministic parser and normalization fixtures/tests,
- extend text and JSON output without claiming full CPU causality or
  per-process attribution.

Do not introduce a generic metric framework or implement the process collectors
from M1.3 in this slice.

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

### R6: Bootstrap JSON inertia

The hand-written placeholder JSON is safe only while values are fixed and
controlled. Extending it to arbitrary kernel/process text would create escaping
and schema-maintenance risk.

Mitigation:
- reassess serialization dependencies when M1.2 introduces dynamic data,
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

On 2026-08-17 with Rust 1.97.1 / Cargo 1.97.1:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

The emitted `hunt --json` placeholder was also parsed successfully with `jq`.

## Next milestone after CPU PSI

**Milestone 1.3 — CPU/process collector.**

See `roadmap.md`.
