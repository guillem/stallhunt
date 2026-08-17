# ADR-0005: Treat the Git repository as complete project memory

- Status: Accepted
- Date: 2026-08-17

## Context

Development may continue:

- on different computers,
- at different times,
- through different coding agents,
- without access to earlier chat sessions.

Important project context must therefore survive independently of any assistant conversation.

## Decision

The Git repository is the source of truth for:

- product intent,
- architecture,
- decisions,
- current status,
- development conventions,
- roadmap,
- known limitations.

`docs/status.md` must be updated as work progresses.

Significant design choices must be captured in ADRs.

Coding agents should read repository docs before significant changes.

## Consequences

Positive:

- reproducible handoff,
- agent-independent continuity,
- auditable decisions,
- reduced dependence on conversational memory.

Costs:

- documentation must be maintained,
- stale docs become a project risk,
- changes take slightly more discipline.

## Operational rule

A coding session is not complete if it materially changes project reality but leaves `docs/status.md` or relevant design docs stale.
