# Documentation index

This directory is the durable design and project-memory layer.

Milestones 1–6 are functionally complete. Milestone 8's first two conservative
evidence-chain slices relate memory mechanism pressure to I/O pressure, first
host-wide and then same-cgroup, without claiming causality. Scoped cgroup
findings can also carry reclaim, swap, possible-thrashing, or quota-throttle
context labels without creating pressure. The repository is currently parked;
`status.md` is the authoritative record of implemented behavior, pending work,
and the gate for selecting a future slice. `experiments.md` retains controlled
validation and overhead evidence.

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
- ADR-0006: bounded cgroup-v2 scoped attribution
- ADR-0007: versioned normalized-observation recordings without a compatibility promise
- ADR-0008: watch tracks finding lifecycle rather than providing a TUI monitor
- ADR-0009: evidence chains require independent mechanism evidence and never claim causality
- ADR-0010: same-cgroup memory plus I/O chains stay on one path and never join host findings
- ADR-0011: same-cgroup chains may use memory.stat page deltas in addition to memory.events
- ADR-0012: Stallhunt product identity, clap CLI, MSRV, Linux baseline, and JSON kinds
- ADR-0013: watch finding-lifecycle TUI and styled hunt/replay terminal report
- ADR-0014: implicit hunt options and additive watch process attribution
- ADR-0015: bounded procfs/taskstats process evidence with no privilege elevation
- ADR-0016: scoped six-role process attribution, schema-2 compatibility, and responsive TUI behavior

## Documentation rules

Documentation describes current truth unless explicitly marked as a proposal.

If implementation diverges from a design document:

1. determine whether implementation or documentation is wrong,
2. fix the mismatch in the same change,
3. record architectural decisions as ADRs when appropriate,
4. update `status.md`.

Do not preserve stale plans as if they were current architecture. Git history preserves old versions.
