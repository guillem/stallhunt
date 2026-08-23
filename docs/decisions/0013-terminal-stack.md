# ADR-0013: ratatui + crossterm for presentation

- Status: Accepted
- Date: 2026-08-23

## Context

Default hunt text had become a concatenated wall of resource paragraphs, and
watch TTY output was ANSI clear/home rather than a real terminal application.
`docs/status.md` listed the color/terminal crate as an open decision. Color
must never be the only carrier of meaning. The binary forbids `unsafe`, uses
stable Rust 1.85, and must stay cheap on a stressed host.

Hunt is a one-shot snapshot. Watch on a TTY is interactive. Piped output and
`--json` must not enter an interactive UI.

## Decision

Use **crossterm 0.28** and **ratatui 0.29** (MSRV-compatible; ratatui 0.30
requires rustc 1.88).

- Hunt/replay snapshot text is produced as a compact string. Crossterm styles
  severity labels only when stdout is a TTY, `--no-color` is absent, and
  `NO_COLOR` is unset or empty.
- Watch TTY uses ratatui with a crossterm backend, alternate screen, and raw
  mode. See ADR-0014.
- ASCII bars are the non-TTY / golden-test fallback; Unicode block bars are
  used on a TTY.
- Do not add a second color crate (`colored`, `owo-colors`, `termion`).

`--explain` expands qualifier prose and static finding-kind help. `--json`
ignores `--explain` because JSON already carries qualifiers.

## Consequences

Positive:

- one terminal stack for snapshot color and the watch TUI,
- `NO_COLOR` and `--no-color` are explicit,
- tests can force colorless ASCII output via `TextStyle`.

Costs:

- two extra dependencies,
- TTY restore must be guaranteed on panic and SIGINT (ADR-0014),
- ratatui 0.29 is pinned below the latest 0.30 line until MSRV allows it.

## Alternatives considered

### Custom ANSI without a TUI crate

Rejected: we would own alternate screen, UTF-8 width, resize, and key parsing.

### Color crate plus a separate TUI crate

Rejected: two overlapping terminal stacks for one binary.
