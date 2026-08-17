# Project status

Last updated: 2026-08-17

## Current milestone

**Milestone 0 — Repository bootstrap**

The project is documentation-only. No Rust code has been created yet.

## Implemented

- Product concept defined.
- Linux-first scope defined.
- Architectural layers defined.
- Initial telemetry sources identified.
- Evidence/confidence model defined conceptually.
- CLI direction defined.
- Testing strategy defined.
- Initial ADRs written.
- Git-as-project-memory workflow established.

## Not implemented

Everything executable, including:

- Cargo project,
- CLI,
- collectors,
- parsers,
- observation model,
- inference engine,
- JSON schema,
- tests,
- CI,
- packaging.

## Current recommended next task

Implement **Milestone 1.1: Rust/CLI bootstrap** as the smallest coherent change.

Suggested result:

```text
Cargo.toml
src/
  main.rs
  cli.rs        # or equivalent simple structure
tests/
```

With commands:

```bash
bottleneck hunt --duration 1s
bottleneck capabilities
```

At this stage they may return a clearly marked placeholder result, but:

- CLI structure should be real,
- JSON/text rendering boundaries should be considered,
- quality gates should be established,
- no fake telemetry should be presented as diagnosis.

Then proceed immediately to PSI parsing rather than overbuilding CLI infrastructure.

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

## Known open decisions

Not yet decided:

- final project/binary name,
- license,
- minimum Rust version,
- minimum Linux kernel/support baseline,
- CLI argument parsing crate,
- serialization crate/versioning policy,
- error-handling approach,
- color/terminal crate,
- eventual eBPF framework,
- CI provider/configuration,
- packaging/distribution.

These should be decided when implementation makes the tradeoff concrete, not all at bootstrap.

## Validation status

No executable validation exists yet.

Documentation has been prepared to be internally consistent, but implementation will reveal necessary revisions.

## Next milestone after bootstrap

**Milestone 1 — CPU contention vertical slice.**

See `roadmap.md`.
