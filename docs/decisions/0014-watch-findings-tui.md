# ADR-0014: Watch TTY is a findings TUI

- Status: Accepted
- Date: 2026-08-23
- Supersedes: [ADR-0008](0008-watch-finding-lifecycle.md)

## Context

ADR-0008 made `watch` a finding-lifecycle command and rejected a TUI resource
monitor so the product would not compete with `top`/`htop`. Diagnosis is now
in place (M1–M6, M8). Operators still need the lifecycle model, but the TTY
presentation (ANSI clear/home) is too primitive.

A later TUI was always supposed to display changing findings rather than
reproduce htop. That is this decision.

## Decision

Keep the ADR-0008 **lifecycle model**:

- contiguous rolling windows that reuse the previous endpoint snapshot,
- identities: host CPU/memory/I/O plus at most 16 cgroup pressure findings,
- states `new` / `persistent` / `resolved`,
- compact `stallhunt.watch_window` JSON stream,
- no full-observation retention in history,
- first SIGINT drains the in-flight window; second SIGINT exits 130.

Change only TTY **presentation**:

- On a TTY, `watch` enters a ratatui findings TUI (alternate screen).
- Home view is the lifecycle table plus PSI bars, not a process list.
- A detail pane shows victims/suspects for the **current** window's selected
  finding from the in-memory `HuntObservation`. History stays compact events.
- `?` opens an explain overlay with qualifier text.
- `--json`, piped stdout, and `watch --plain` stay non-interactive compact
  text/JSON.
- Collectors still run once per window. The TUI redraws on new windows, keys,
  and resize — not at a frame-rate poll of `/proc`.
- Terminal restore is a drop guard. The second SIGINT restores then exits 130
  because `process::exit` skips Drop.

## Consequences

Positive:

- operators get htop-like density without a utilization dashboard,
- JSON consumers and scripts are unchanged,
- `--plain` is an escape hatch on a TTY.

Costs:

- TUI code and restore/SIGINT complexity,
- watch JSON still omits victims/suspects; only the live TUI detail pane sees
  the current window's attribution,
- a leaked alternate screen is an operator-visible failure.

## Alternatives considered

### Keep ADR-0008 TTY text and only densify hunt

Rejected: users called watch primitive and asked for an htop/btop visual
language.

### Interactive hunt TUI after the observation

Rejected: hunt is a bounded UNIX snapshot. Scripts and ssh one-shots should
print and exit.

### 60 fps live bars

Rejected: extra sampling would fight the overhead rule.
