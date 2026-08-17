# Development guide

## Current state

The repository contains the Milestone 1.2 CPU PSI slice.

Build and run it from the repository root:

```bash
cargo build
cargo run -- hunt --duration 1s
cargo run -- capabilities --json
```

`hunt` performs a bounded two-snapshot CPU PSI observation. It reports raw
pressure evidence only; CPU inference and process collection are still future
work.

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

The executable integration tests are in `tests/cli.rs`; parser and renderer
unit tests live beside their implementations.

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

If future eBPF bindings/BTF tooling generates artifacts, document exactly what is generated, from what source, and whether generated files are committed.
