# Codex workflow

This repository is intentionally prepared so command-line coding agents can continue work without access to the conversation that created the project.

## Starting a new Codex session

From the repository root, a good first instruction is:

```text
Read AGENTS.md and the project documentation it references. Treat the repository
as the source of truth and do not assume context from previous chats.

Inspect docs/status.md and docs/roadmap.md. Implement the current recommended
next task as the smallest coherent vertical slice. Follow existing ADRs.

Before finishing:
- run all applicable formatting/lint/test commands,
- update docs/status.md to match reality,
- update any design documentation affected by the implementation,
- add an ADR if you make a significant architectural decision,
- summarize changes, validation, limitations, and the next recommended task.
```

Once the project has code, add:

```text
Inspect the existing implementation before proposing new abstractions. Reuse the
current data model and conventions unless there is a concrete reason to change
them.
```

## Starting from the current implementation

Milestones 1.1 through 1.3 are complete. The current recommended Codex session is:

```text
Read AGENTS.md and all required project documentation. Inspect the existing
Rust implementation before proposing new abstractions.

Implement Milestone 1.4: scheduler-delay attribution.

Requirements:
- collect `/proc/<pid>/schedstat` when available,
- detect unavailable, unreadable, and malformed scheduler accounting,
- calculate runnable-delay deltas only for stable process identities,
- preserve process disappearance and partial permission behavior,
- add victim evidence without CPU severity or suspect inference.

Integrate only the smallest useful scheduler-delay evidence into the existing
`hunt` observation and output.
Update docs/status.md and any affected design docs.
```

## Session discipline

### Prefer one milestone slice per session

A coding agent can often implement much more, but broad autonomous changes make review harder.

Prefer:

```text
one diagnostic capability
  -> collector
  -> model
  -> analysis
  -> output
  -> tests
  -> docs
```

over:

```text
all telemetry collectors
  -> giant unfinished framework
```

### Ask the repository before asking the human

Before raising a design question, inspect:

- ADRs,
- status,
- roadmap,
- architecture,
- current code/tests.

If the repository already answers it, follow the repository.

If a decision is genuinely open but not necessary for the task, leave it open.

If a decision is necessary, make the smallest defensible choice and document it.

## Useful Codex task templates

### Implement a milestone

```text
Read AGENTS.md and current project docs. Implement <milestone/subtask> only.
Preserve existing architecture unless the task exposes a concrete flaw.

Use a vertical slice. Add deterministic tests. Do not silently expand scope.
Run validation and update docs/status.md before finishing.
```

### Review current implementation

```text
Read AGENTS.md and the relevant project docs. Review the current implementation
against the documented product goals and architecture.

Focus on correctness, Linux/kernel semantic mistakes, race conditions, false
causal claims, parser robustness, observer overhead, privilege assumptions, and
test gaps.

Do not refactor merely for style. Fix clear problems you can verify, add
regression tests, and update docs/status.md if project reality changes.
```

### Investigate a failing fixture

```text
Treat the fixture as evidence, not as the desired answer. Determine whether the
collector/parser, normalization, inference rule, fixture, or expected finding is
wrong.

Do not weaken a diagnostic rule merely to make the test pass. Preserve the
severity/confidence distinction and document any semantic correction.
```

### Add a new telemetry source

```text
Before adding the collector, state which diagnostic ambiguity this telemetry
resolves. If it does not improve a concrete finding, do not add it.

Keep collection separate from inference. Add parser fixtures, missing-capability
behavior, normalization tests, and update docs/telemetry.md.
```

### Introduce eBPF later

```text
Read ADR-0003. Do not introduce eBPF as a generic enhancement. Identify the
specific diagnostic question that current telemetry cannot answer.

Evaluate current implementation options and deployment/privilege consequences.
Create an ADR before committing to the eBPF architecture.
```

## Git handoff checklist

At the end of a substantial session, the repository should answer:

- What works now?
- What was validated?
- What is known not to work?
- What architectural decisions changed?
- What is the next smallest useful task?

The primary place for that answer is `docs/status.md`.

Do not store session transcripts in the repository unless they contain durable technical information that has not been captured elsewhere.

## Branch/worktree strategy

Once multiple agents or parallel efforts are used, prefer one vertical slice per branch/worktree.

Good parallel candidates:

- parser fixture improvements,
- CLI renderer work against an already-defined model,
- documentation/reference work,
- isolated resource analyzers after shared interfaces stabilize.

Bad parallel candidates:

- simultaneous competing data-model redesigns,
- several agents changing the same core inference API,
- eBPF architecture before requirements are settled.

Merge shared model/architecture changes before spawning dependent parallel work.

## Commit messages

No rigid convention is required initially.

Prefer messages that describe project behavior:

```text
add bounded CPU PSI sampling
attribute CPU runnable delay from schedstat
report missing process I/O capability
document CPU severity thresholds
```

rather than implementation trivia.
