# Documentation index

This directory is the durable design and project-memory layer.

Milestone 1's CPU vertical slice is complete; Milestone 2 memory pressure is
next. `status.md` is the authoritative current-state record, while
`experiments.md` retains the controlled validation and overhead evidence behind
the CPU heuristics.

## Read this first

| Document | Purpose |
|---|---|
| [`product.md`](product.md) | Product definition, user problems, scope, non-goals, success criteria |
| [`architecture.md`](architecture.md) | System architecture and component boundaries |
| [`status.md`](status.md) | Current factual project state and next work |
| [`roadmap.md`](roadmap.md) | Milestones and intended sequencing |

## Implementation design

| Document | Purpose |
|---|---|
| [`data-model.md`](data-model.md) | Normalized metrics, observations, evidence, findings and identifiers |
| [`telemetry.md`](telemetry.md) | Linux data sources and collector design |
| [`inference-engine.md`](inference-engine.md) | Rules, severity, confidence and causal reasoning |
| [`cli-ux.md`](cli-ux.md) | CLI commands, output model and JSON expectations |
| [`security-privileges.md`](security-privileges.md) | Permission model, privilege minimization, data sensitivity |
| [`testing.md`](testing.md) | Unit, fixture, integration, load and regression testing |
| [`development.md`](development.md) | Local development and code-quality conventions |
| [`codex-workflow.md`](codex-workflow.md) | Practical instructions/prompts for CLI coding-agent sessions |
| [`experiments.md`](experiments.md) | Durable controlled experiments and validation conclusions |
| [`references.md`](references.md) | Primary technical references and research starting points |
| [`glossary.md`](glossary.md) | Shared terminology |

## Architecture decisions

Architecture Decision Records live under [`decisions/`](decisions/).

Accepted initial decisions:

- ADR-0001: Rust
- ADR-0002: Linux-first
- ADR-0003: procfs/sysfs/PSI first; eBPF later
- ADR-0004: evidence and confidence instead of false certainty
- ADR-0005: Git repository as project memory

## Documentation rules

Documentation describes current truth unless explicitly marked as a proposal.

If implementation diverges from a design document:

1. determine whether implementation or documentation is wrong,
2. fix the mismatch in the same change,
3. record architectural decisions as ADRs when appropriate,
4. update `status.md`.

Do not preserve stale plans as if they were current architecture. Git history preserves old versions.
