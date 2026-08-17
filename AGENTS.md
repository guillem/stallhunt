# AGENTS.md

This repository is the source of truth for the Stallhunt project.

## Mission

Build a Linux-first command-line tool that automatically identifies active system performance bottlenecks and explains:

1. whether meaningful contention exists,
2. which resource is constraining progress,
3. which processes/services are being delayed,
4. which processes/services are likely causing the contention,
5. how much time is being lost,
6. what evidence supports the diagnosis,
7. how confident the tool is in each causal claim.

The project is **not another `top` clone**. Traditional monitors report resource consumption. Stallhunt should report **lost progress and likely causes**.

Product name: **Stallhunt**. Crate, package, and binary: `stallhunt`. See ADR-0012.

## Operating principle

Treat Git as project memory.

A fresh clone on another computer must contain enough information for a competent coding agent or engineer to understand:

- what the project is,
- what has already been implemented,
- what decisions have been made,
- what remains,
- what is currently broken,
- what should be done next,
- why the architecture looks the way it does.

Do not rely on chat history as durable project context.

## Required reading order

Before making non-trivial changes, read:

1. `README.md`
2. `docs/README.md`
3. `docs/product.md`
4. `docs/architecture.md`
5. `docs/status.md`
6. relevant files under `docs/decisions/`
7. any domain-specific document relevant to the requested work

For implementation work, also read:

- `docs/data-model.md`
- `docs/telemetry.md`
- `docs/inference-engine.md`
- `docs/testing.md`

## Project constraints

### Platform

- Linux first.
- Native Linux kernel interfaces are preferred over portability abstractions when they materially improve diagnosis.
- Other operating systems are explicitly out of scope until the Linux implementation is useful and stable.

### Language

- Rust is the implementation language.
- Prefer stable Rust unless an ADR explicitly approves nightly-only functionality.

### Delivery strategy

Build in vertical slices.

A vertical slice should ideally include:

- telemetry collection,
- normalized internal representation,
- analysis/inference,
- CLI output,
- tests,
- documentation.

Avoid building all collectors first and postponing useful diagnosis until later.

### eBPF

Do **not** make eBPF a prerequisite for the first useful release.

The initial implementation should prefer `/proc`, `/sys`, PSI, scheduler/accounting interfaces, cgroups, and other low-complexity kernel interfaces.

Introduce eBPF only when a concrete diagnostic question cannot be answered adequately using simpler interfaces. See `docs/decisions/0003-procfs-first-ebpf-later.md`.

### Causality

Never present correlation as certainty.

Every diagnosis should distinguish:

- observed fact,
- derived metric,
- heuristic inference,
- probable causal relationship,
- unknown/unsupported conclusion.

Prefer language such as:

- "observed",
- "consistent with",
- "likely cause",
- "primary suspect",
- "correlated with",
- "insufficient evidence".

Do not claim that process A caused process B to stall unless the evidence model supports that claim.

### Performance impact

The tool must be safe to run on an already stressed machine.

Design collectors to be:

- bounded,
- sampling-based where possible,
- allocation-conscious,
- low-overhead,
- resilient to disappearing processes,
- resilient to partial permissions,
- resilient to kernel-feature absence.

A monitoring tool that materially worsens the bottleneck is a failed design.

## Documentation discipline

Documentation is part of every feature.

When behavior or architecture changes, update the relevant docs in the same commit.

At minimum, every meaningful development session should consider whether to update:

- `docs/status.md`
- `docs/roadmap.md`
- `docs/architecture.md`
- `docs/decisions/*`
- `README.md`

### `docs/status.md` is mandatory project state

Keep it factual and current.

It should always contain:

- current milestone,
- implemented capabilities,
- known limitations,
- known bugs,
- current design risks,
- next recommended tasks,
- last meaningful validation performed.

Do not let it become a changelog. Git already records history.

### ADRs

Use Architecture Decision Records for decisions that are expensive to reverse or likely to be questioned later.

Create a new ADR under `docs/decisions/` when deciding matters such as:

- dependency strategy,
- async runtime,
- telemetry backend,
- privilege model,
- eBPF framework,
- persistence format,
- plugin architecture,
- output schema compatibility,
- daemon/client split,
- support policy.

Do not edit an accepted ADR to pretend the earlier decision never happened. Supersede it with a new ADR.

## Implementation conventions

Until code exists, these are defaults, not immutable law.

### Crate organization

Prefer a workspace only when multiple crates have a clear ownership boundary.

A likely eventual shape is:

```text
crates/
  stallhunt-core/       # normalized model, scoring, inference
  stallhunt-linux/      # Linux telemetry collectors
  stallhunt-cli/        # command-line application
```

Do not create this split merely for aesthetics. Start simpler if one crate is sufficient.

### Dependencies

Prefer:

- Rust standard library,
- small focused crates,
- well-maintained ecosystem libraries,
- direct kernel interfaces where reasonable.

Avoid introducing:

- large frameworks for tiny conveniences,
- multiple crates serving the same purpose,
- dependencies without clear maintenance health,
- async runtimes before concurrency needs justify them.

Every new dependency should answer: "What complexity does this remove that we would otherwise own?"

### Error handling

- Do not panic on expected runtime conditions.
- Process disappearance between `/proc` reads is normal.
- Permission failures should degrade capability and be reported clearly.
- Unsupported kernel features should become capability flags, not crashes.
- Preserve enough context in errors to diagnose the failed subsystem.

### Time and units

Internally:

- durations: monotonic time where possible,
- sizes: bytes,
- rates: per second,
- CPU: time-based values before percentages,
- percentages: derive at presentation/analysis boundaries,
- identifiers: use typed wrappers where confusion is plausible.

Human output may use sensible IEC/SI formatting.

### Testing

Every inference rule requires tests for:

- positive case,
- negative case,
- boundary case,
- missing-data case,
- contradictory-evidence case when relevant.

Prefer deterministic fixture-based tests over tests that depend on current host load.

See `docs/testing.md`.

## Git workflow

Keep changes reviewable.

### Milestone-boundary resumability

At every milestone boundary, the repository must be resumable by a competent
agent or engineer with no access to previous conversation history.

Milestone completion requires:

- implementation committed,
- formatting, static checks, and tests passing,
- `docs/status.md` updated,
- `docs/roadmap.md` updated when milestone state or sequencing changed,
- important architectural decisions captured in ADRs,
- known bugs, limitations, validation gaps, and the precise next task recorded,
- no essential project knowledge existing only in an agent conversation,
- a clean working tree with no generated or debug artifacts.

Prefer commits that are:

- coherent,
- small enough to reason about,
- independently testable,
- explicit about documentation changes.

Before declaring a task complete:

1. run formatting,
2. run static checks,
3. run tests,
4. run relevant integration/fixture tests,
5. update `docs/status.md`,
6. inspect `git diff`,
7. ensure no generated/debug junk is committed.

When the project has a Rust workspace, the default validation target should become:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

If those commands are not yet appropriate, document the current validation commands in `docs/development.md`.

## Agent behavior

When implementing a request:

1. understand the requested outcome,
2. read relevant project docs,
3. inspect existing code before proposing new abstractions,
4. state assumptions in code/docs when ambiguity matters,
5. choose the smallest coherent vertical slice,
6. implement,
7. test,
8. update project documentation,
9. summarize what changed and what remains.

Do not silently broaden scope.

Do not "future-proof" by adding unused abstraction layers.

Do not refactor unrelated code unless necessary for correctness.

Do not overwrite unresolved design questions with arbitrary choices. If a choice is necessary to proceed, record it as an explicit decision or assumption.

## Definition of done

A feature is not done merely because it compiles.

For a diagnostic feature, done normally means:

- data can be collected or loaded from a fixture,
- data is normalized,
- the inference is explained by evidence,
- confidence/severity behavior is defined,
- human CLI output is understandable,
- machine-readable output remains coherent,
- tests cover success and non-success cases,
- docs describe the capability and its limits,
- `docs/status.md` reflects reality.

## First implementation target

The first useful vertical slice should answer:

> "Is the machine currently experiencing CPU scheduling pressure, and which tasks are most likely contributing to it or suffering from it?"

The implementation should use simple Linux telemetry first, likely including:

- `/proc/pressure/cpu`
- `/proc/stat`
- `/proc/loadavg`
- `/proc/<pid>/stat`
- `/proc/<pid>/schedstat` when available

It should produce evidence-based output without requiring eBPF.

See `docs/roadmap.md`.
