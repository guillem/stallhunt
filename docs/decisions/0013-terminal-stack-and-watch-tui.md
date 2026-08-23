# ADR-0013: Terminal stack (ratatui + crossterm) and a watch TUI

- Status: Accepted
- Date: 2026-08-23

## Context

Field feedback on the v0.1.x interface is consistent: default `hunt` output
reads like a wall of text, and `watch` looks primitive next to tools such as
`htop` and `btop`. Modern terminals can render panels, bars, and color, and
sysadmins expect continuous modes to use them. The presentation redesign is
tracked as Milestone 9; ADR-0014 covers the verbosity policy, this ADR covers
the terminal stack and the interactive surface.

ADR-0008 deliberately kept `watch` free of a TUI crate, alternate screen, and
interactive navigation so the product would not drift into a `top` clone. That
constraint succeeded: watch tracks finding lifecycle, not utilization. The
lifecycle model itself is what users want to see better; the presentation
clause is what this ADR revisits. The cli-ux guidance ("if a TUI is added
later, it should display changing findings rather than simply reproduce htop")
still applies.

Constraints:

- MSRV is 1.85 (ADR-0012), and CI runs locked tests on Rust 1.85. `ratatui`
  0.30 and its split `ratatui-core`/`ratatui-widgets` crates declare
  `rust-version = "1.88.0"`, so they cannot be used without raising the MSRV.
  `ratatui` 0.29 declares `rust-version = "1.74.0"` and uses `crossterm` 0.28
  (MSRV 1.63).
- The package forbids unsafe Rust in our own code; dependencies remain subject
  to normal vetting.
- The tool must stay safe on a stressed machine and must not break scripted
  use: piped text, `--json`, `--count`, and the SIGINT drain contract are
  existing behavior that other decisions (ADR-0008) guarantee.

## Decision

Adopt **ratatui 0.29** with the **crossterm 0.28** backend as the terminal
stack. This resolves the long-open "color/terminal crate" decision recorded in
`docs/status.md`.

Scope rules:

- `watch` renders an interactive full-screen TUI **only** when stdout is a
  terminal, `TERM` is not `dumb`, a terminal size is available, and
  `--no-tui` is not passed. Otherwise it falls back automatically to the
  existing refreshing text renderer. `--json` and piped text are unchanged.
- The TUI presents **the same watch data**: host pressure gauges, finding
  lifecycle table, scoped cgroup pressure, bounded history sparkline, and key
  hints. It introduces no new collectors, inference, or identities. It is a
  presentation of `WatchWindow`, not a second monitor.
- Interactive keys are bounded and documented in the footer: `q` quits,
  `?`/`h` toggles a help overlay, `e` toggles a detail pane with the full
  per-finding summaries. There is no configuration editing, scrolling state,
  or process management.
- Color communicates severity but is never the only carrier of meaning:
  severity words are always rendered alongside color. The `NO_COLOR`
  environment variable disables color. Hunt text output stays uncolored.
- Hunt/replay/capabilities remain one-shot non-interactive output. The TUI is
  a watch-only surface.
- SIGINT semantics are unchanged: the first SIGINT drains the in-flight window
  and exits, a second terminates immediately with status 130. The TUI
  restores the terminal (raw mode off, cursor visible, alternate screen left)
  on graceful exit and best-effort before the immediate exit path.
- `--no-tui` exists so operators on a TTY can still get the classic text
  rendering (screen readers, remote relays, redesign A/B feedback).

## Consequences

Positive:

- watch becomes legible at a glance (gauges, color-coded lifecycle, sparkline
  history) while still displaying changing findings rather than utilization;
- ratatui's `TestBackend` allows deterministic buffer-level render tests with
  no host dependency;
- crossterm keeps raw-mode/alternate-screen handling in a maintained crate
  instead of hand-rolled ANSI sequences;
- scripted consumers keep an exact compatibility story (text fallback and
  JSON are untouched).

Costs:

- two new dependencies (plus their transitive set) must be tracked in
  `Cargo.lock` and vendored/cached for offline builds;
- the TUI is a second presentation path that must be kept in sync with watch
  semantics;
- MSRV now indirectly constrains terminal-stack upgrades: moving to ratatui
  0.30+ requires an MSRV decision first;
- terminal restore on the immediate second-SIGINT path is best-effort because
  the handler exits the process directly.

## Alternatives considered

### Keep hand-rolled ANSI text rendering

Rejected: the redesign requires panels, bars, overlays, and resize handling.
Maintaining that by hand duplicates what a terminal framework already solves
and would grow with every added panel.

### termion

Rejected: termion is effectively unmaintained and lacks the widget layer; it
would still require building layout and widgets by hand.

### ratatui 0.30 (split crates)

Rejected for now: it declares `rust-version = "1.88.0"`, above the project
MSRV of 1.85 locked by CI. Revisit together with any MSRV decision.

### A full htop-style process TUI

Rejected: it would reproduce utilization dashboards, contradict the product
mission (lost progress, not consumption), and require telemetry/attribution
the project does not claim. The TUI renders findings, not process lists.
