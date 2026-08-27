# Development guide

## Current state

The repository contains completed Milestone 1 CPU, M2 host-memory, M3
block-I/O, M4 bounded cgroup/service, M5 recording/replay, M6 watch, the v0.4
scoped-attribution/TUI implementation, the first two Milestone 8
evidence-chain slices, and the v0.5 `stallhunt mcp` server (ADR-0017,
ADR-0018). v0.4.1 was a pre-release code-review bugfix pass on top of the
v0.4.0 slice (see `docs/status.md`); v0.5.2 is the current release candidate.
EXP-0010 records the passed taskstats, 512-TGID/member-ceiling,
cleanup, and dependency-review gates.

Build and run it from the repository root:

```bash
cargo build --release --locked
./target/release/stallhunt hunt --duration 1s
./target/release/stallhunt capabilities --json
./target/release/stallhunt record --duration 1s --output /tmp/incident.json
./target/release/stallhunt replay /tmp/incident.json
./target/release/stallhunt watch --interval 1s --count 2
```

For installed use, see [`install.md`](install.md):

```bash
cargo install --path .
stallhunt
```

`hunt` performs bounded CPU PSI, host CPU/load, process CPU, scheduler-accounting,
memory PSI, meminfo, and vmstat observations around one requested sleep. CPU
and memory collectors each retain their own measured interval because the reads
are sequential. The memory analyzer uses exact memory PSI `some` for its
verdict; `full` is non-additive subset context, while meminfo/vmstat only
classify/contextualize the result. Memory findings are host-wide and make no
finding-local process attribution; v0.4's separate `ProcessScope` roles reuse
the bounded CPU/process evidence when matching PSI pressure exists. M2
deterministic fixtures, a healthy live smoke, and a
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

Requirements:

- stable Rust **1.85+** (MSRV, recorded in `Cargo.toml`),
- Cargo,
- rustfmt,
- Clippy.

Linux **4.20+** with procfs and PSI is the supported runtime baseline (ADR-0012).

## Default quality gates

After dependencies are available in the local Cargo cache. Adding or
upgrading a dependency (for example, `ratatui`/`crossterm`, added in
ADR-0013) needs one `cargo build` or `cargo update` with network access to
populate the cache and regenerate `Cargo.lock`; commit the updated lock
file so the gate below stays `--offline`-clean afterward:

```bash
cargo fmt --all -- --check
cargo clippy --locked --offline --workspace --all-targets --all-features -- -D warnings
cargo test --locked --offline --workspace --all-features
```

Add targeted commands as the project evolves.

`cargo-audit` is a separate release review, not an offline Cargo quality gate.
On 2026-08-24, cargo-audit 0.22.2 did not support the planned literal
`--omit=dev` option; its supported full-lockfile `cargo audit` command exited
0 but reported `RUSTSEC-2024-0436` (`paste`, unmaintained) and
`RUSTSEC-2026-0002`/`RUSTSEC-2026-0253` (`lru`, unsound), pulled through
ratatui 0.29. Ratatui 0.30.0 requires Rust 1.86, and 0.30.1 or newer requires
Rust 1.88; every 0.30 release therefore conflicts with the Rust 1.85 MSRV. Do
not suppress or change that dependency without an
explicit reviewed decision. The v0.4.0 review accepted the locked exposure
because ratatui uses neither advised `lru` API and `paste` is a maintenance-only
warning; do not suppress it, and revisit on any call-path, advisory, dependency,
or MSRV change.

The executable integration tests are in `tests/cli.rs`; opt-in Linux acceptance
tests are `tests/cpu_acceptance.rs`, `tests/io_acceptance.rs`,
`tests/memory_acceptance.rs`, and `tests/cgroup_acceptance.rs`; parser and
renderer unit tests live beside their implementations. Host-pressure acceptance
tests serialize their workloads and should run only when intentionally creating
bounded pressure:

```bash
cargo test --test cpu_acceptance -- --ignored
cargo test --test io_acceptance -- --ignored
STALLHUNT_MEMORY_ACCEPTANCE_PATH=/absolute/cgroup/path \
  cargo test --locked --offline --test memory_acceptance -- --ignored --nocapture
STALLHUNT_CGROUP_ACCEPTANCE_PATH=/absolute/cgroup/path \
  cargo test --locked --offline --test cgroup_acceptance -- --ignored --nocapture
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
tools/measure-overhead.sh --binary target/release/stallhunt --duration 1 --repetitions 3
tools/measure-overhead.sh --binary target/release/stallhunt --duration 1 --repetitions 3 --scenario high --sleepers 64 --tasks 512
tools/check-tui-pty.sh --binary target/debug/stallhunt
```

The harness is opt-in and scenario-specific. It may use an already-installed
`stress-ng` for CPU stress but never installs it; timings are evidence ranges,
not a CI gate. `all` does not spawn hundreds of PIDs. The PTY check requires
util-linux `script`; it captures the bounded one-window TUI stream, checks
alternate screen enter/leave sequences, and compares terminal settings.
EXP-0007 records workstation-scale PID/task cost. It predates the v0.4
512-TGID/member taskstats configuration; EXP-0010 records the required capable
controlled-host follow-up.

## Repository hygiene

Recommended root files once implementation starts:

```text
Cargo.toml
Cargo.lock
rust-toolchain.toml        # optional; MSRV is in Cargo.toml
.gitignore
LICENSE-MIT
LICENSE-APACHE
CHANGELOG.md
AGENTS.md
README.md
docs/
src/ or crates/
tests/
```

Do not add generated build output.

## Initial dependency philosophy

The CLI uses clap 4 with derive parsing. M1.2 adds `serde` and
`serde_json` because live structured output has dynamic optional fields and
should not rely on hand-built JSON escaping.

Likely useful categories:

- serialization,
- error/context handling,
- terminal formatting,
- duration parsing.

Clap covers CLI parsing. Do not preselect other crates in documentation before implementation evaluates current ecosystem choices.

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

The current package forbids unsafe Rust through `Cargo.toml`. Introducing any
unsafe or FFI boundary requires an explicit project decision before changing
that lint. The decision must identify why safe APIs are insufficient, localize
and document the invariants, and define boundary tests. A significant unsafe or
FFI mechanism requires an ADR.

## Generated code

Avoid build-time code generation unless it removes meaningful maintenance burden.

If future eBPF bindings/BTF tooling generates artifacts, document exactly what is generated, from what source, and whether generated files are committed.
