# Development guide

## Current state

The repository contains completed Milestone 1 CPU, M2 host-memory, M3
block-I/O, M4 bounded cgroup/service, M5 recording/replay, M6 watch, and the
first Milestone 8 evidence-chain slice.

Build and run it from the repository root:

```bash
cargo build
cargo run -- hunt --duration 1s
cargo run -- capabilities --json
cargo run -- record --duration 1s --output /tmp/incident.json
cargo run -- replay /tmp/incident.json
cargo run -- watch --interval 1s --count 2
```

`hunt` performs bounded CPU PSI, host CPU/load, process CPU, scheduler-accounting,
memory PSI, meminfo, and vmstat observations around one requested sleep. CPU
and memory collectors each retain their own measured interval because the reads
are sequential. The memory analyzer uses exact memory PSI `some` for its
verdict; `full` is non-additive subset context, while meminfo/vmstat only
classify/contextualize the result. Memory findings are host-wide and make no
process attribution. M2 deterministic fixtures, a healthy live smoke, and a
delegated-cgroup harmful-pressure acceptance are recorded. Reclaim-only and
possible-thrashing remain fixture-validated.

M3 similarly uses exact I/O PSI `some` as its resource verdict and retains
diskstats/process-I/O as independently timed activity context. A disk candidate
and a process I/O-accounting candidate only overlapped the observation; they are
not a device mapping, victim diagnosis, or causal claim. I/O `full` is
non-additive subset context. Deterministic fixtures, a healthy smoke, and a
bounded controlled competing-I/O acceptance pass establish the M3 functional
exit; they do not establish victim, device-mapping, or causal attribution.

The CPU analyzer uses a bounded two-snapshot CPU PSI, host CPU/load, process CPU, and
task scheduler-accounting observation. The pure CPU analyzer uses only a valid
exact-interval CPU PSI `some` value for its resource verdict. The effective
diagnostic and resource-confidence window is the shorter of requested and
measured PSI duration; a request below one second remains telemetry smoke mode.
Otherwise, an effective window of at least one second reports either no
meaningful CPU scheduling contention or a provisional low, moderate, high, or
severe finding. Host/process collection failure does not discard a valid PSI
resource verdict, but leaves attribution empty and qualified. Runnable-delay
victims and same-window CPU consumers are qualified attribution candidates, not
proven causes. M1.6 adds a concise finding-first text renderer; `--json`
retains the complete structured evidence and collection context.

## Toolchain

Initial recommendation:

- stable Rust,
- Cargo,
- rustfmt,
- Clippy.

Do not pin a Rust version until CI/reproducibility needs justify it.

When a minimum supported Rust version is chosen, record it here and potentially in an ADR if compatibility is a deliberate product commitment.

## Default quality gates

Once Rust code exists:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

Add targeted commands as the project evolves.

The executable integration tests are in `tests/cli.rs`; the opt-in rootless
host-workload tests are `tests/cpu_acceptance.rs`, `tests/io_acceptance.rs`, and
`tests/memory_acceptance.rs`; parser and renderer unit tests live beside their
implementations. Acceptance tests serialize their host workloads and should run
only when intentionally creating bounded pressure:

```bash
cargo test --test cpu_acceptance -- --ignored
cargo test --test io_acceptance -- --ignored
BOTTLENECK_MEMORY_ACCEPTANCE_PATH=/absolute/cgroup/path \
  cargo test --locked --offline --test memory_acceptance -- --ignored --nocapture
```

The memory acceptance path must be a caller-owned, writable delegated cgroup-v2
parent with the `memory` controller already enabled for children. The test
creates and cleans up only a generated child cgroup, applies bounded `memory.max`
and `memory.high` settings there, and moves its owned allocator before it starts
allocating. Cleanup now drains remaining tasks in that uniquely named child
before removing it. It never changes the parent cgroup or runs an unconstrained
host-wide allocator.

For manual collector-overhead measurements, build first and measure the release
binary rather than Cargo or a debug build:

```bash
cargo build --release --locked --offline
tools/measure-overhead.sh --binary target/release/bottleneck --duration 1 --repetitions 3
tools/measure-overhead.sh --binary target/release/bottleneck --duration 1 --repetitions 3 --scenario high --sleepers 64 --tasks 512
```

The harness is opt-in and scenario-specific. It may use an already-installed
`stress-ng` for CPU stress but never installs it; timings are evidence ranges,
not a CI gate. `all` does not spawn hundreds of PIDs. EXP-0007 records
workstation-scale PID/task cost.

## Repository hygiene

Recommended root files once implementation starts:

```text
Cargo.toml
Cargo.lock
rust-toolchain.toml        # only if deliberately pinned
.gitignore
LICENSE                    # after license is chosen
AGENTS.md
README.md
docs/
src/ or crates/
tests/
```

Do not add generated build output.

## Initial dependency philosophy

The CLI and PSI parser use the standard library. M1.2 adds `serde` and
`serde_json` because live structured output has dynamic optional fields and
should not rely on hand-built JSON escaping.

Likely useful categories:

- CLI parser,
- serialization,
- error/context handling,
- terminal formatting,
- duration parsing.

However, do not preselect crates in documentation before implementation evaluates current ecosystem choices.

For small parsers under procfs/sysfs, custom parsing may be clearer and safer than a broad abstraction crate.

## Logging

Diagnostic logs and diagnostic *findings* are different.

If logging is added:

- logs go to stderr,
- structured JSON findings remain clean,
- `--json` must not be corrupted by log noise,
- default verbosity should be quiet.

## Configuration

Avoid a configuration-file system in v0.1.

Start with sane built-in defaults plus command-line options.

Configuration becomes justified when users need stable thresholds/policies or scoped targets.

## Architecture evolution

Before introducing major infrastructure, ask:

- Does this solve an observed complexity?
- Can a smaller mechanism solve it?
- Does it make fixture/replay analysis easier or harder?
- Does it increase runtime privilege?
- Does it increase observer overhead?

Examples requiring deliberate decisions:

- Tokio/async runtime,
- daemon mode,
- plugin system,
- eBPF,
- SQLite/storage,
- long-running state,
- remote API.

## Commit discipline

Useful commit progression for a vertical slice:

1. model/parsers,
2. normalization,
3. analyzer,
4. CLI rendering,
5. docs/status.

These can be one commit if small, but each final commit should leave the repository coherent.

## Coding-agent handoff

Before ending a session, an agent should:

1. run validation,
2. update `docs/status.md`,
3. record unresolved issues,
4. make next steps concrete,
5. ensure design decisions are in Git.

A new agent should not need the previous chat transcript.

## Comments

Prefer comments that explain:

- kernel semantics,
- invariants,
- why a calculation is correct,
- why an apparently simpler approach is wrong.

Avoid comments that restate syntax.

When code depends on a kernel field definition, include a concise source/reference note in the code or docs when useful.

## Unsafe code

Unsafe Rust is not prohibited, but requires justification.

Before adding unsafe:

- identify why safe APIs are insufficient,
- localize the unsafe boundary,
- document invariants,
- test boundary conditions.

An ADR is appropriate if unsafe/FFI becomes a significant architectural mechanism.

## Generated code

Avoid build-time code generation unless it removes meaningful maintenance burden.

The current local validation commands are:

```bash
cargo fmt --all -- --check
cargo clippy --locked --offline --workspace --all-targets --all-features -- -D warnings
cargo test --locked --offline --workspace --all-features
```

If future eBPF bindings/BTF tooling generates artifacts, document exactly what is generated, from what source, and whether generated files are committed.
