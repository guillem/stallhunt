# ADR-0014: Watch TTY dashboard rendering with direct ANSI, no TUI framework

- Status: Accepted
- Date: 2026-08-24

Supersedes the presentation clauses of [ADR-0008](0008-watch-finding-lifecycle.md):
watch remains a finding-lifecycle command with the same tracked identities,
lifecycle states, history bounds, JSON stream, drain-then-exit SIGINT
behavior, and no-recording policy. Only the TTY presentation contract
changes. ADR-0008's statement that watch "is not a TUI" meant, and still
means, that watch is not an interactive utilization monitor competing with
`top`/`htop`; it does not and will not show per-process utilization tables,
interactive navigation, or configuration menus.

## Context

Users found v0.1.2 `watch` text mode too primitive: a scrolling list of
lifecycle rows with no visual anchoring, no color, and no sense of magnitude.
The same feedback asked for a presentation "more like htop or btop" — modern
terminals are capable of block bars, color, and flicker-free refresh, and
sysadmins read pressure magnitude far faster from a meter than from
"PSI 23.40%".

ADR-0008 deferred terminal-framework scope. That decision protected the
product from becoming a dashboard before diagnosis was trustworthy. By v0.1.2
the diagnosis surface is stable (M1–M6, two M8 slices), and the lifecycle
data model already carries everything a dashboard needs: current per-resource
PSI fractions, severities, statuses, scoped cgroup pressure, lifecycle
transitions, and severity history.

The status document also listed "color/terminal crate" as an open decision.

## Decision

On an interactive terminal, text `watch` renders a **framed dashboard** that
redraws in place each window:

- a title row with tool version, window index, and interval;
- **HOST PRESSURE** meters: one block bar per host resource scaled by
  exact-interval PSI `some` (the share of the window with stalled work), with
  the numeric percentage and a textual status/severity word — the meter is
  magnitude at a glance, the words remain the meaning;
- **SCOPED PRESSURE**: up to six currently pressured cgroups with kind,
  severity, and PSI;
- **FINDINGS** lifecycle rows (`NEW` / `PERSISTENT` / `RESOLVED`) with consecutive-window
  counts and severity transitions;
- **HISTORY**: the last 16 windows as per-resource severity sparklines
  (`· ▁ ▃ ▅ █` by severity, `·` for resolved);
- a footer with the SIGINT contract and a pointer to `hunt --verbose`.

Rendering rules:

- **No TUI framework and no color crate.** The dashboard is plain string
  formatting emitting ANSI sequences directly: cursor-home plus
  erase-below per frame, hide/show cursor around the run. This closes the
  "color/terminal crate" open decision: direct ANSI for now, revisit only if
  a concrete need (input handling, cells, resize semantics) appears.
- **No alternate screen.** Scrollback is preserved; the frame simply
  overwrites the rows it owns.
- The cursor is hidden for the run and restored on every exit path,
  including the immediate second-SIGINT termination.
- Rows are composed from styled spans so border alignment and truncation are
  computed on visible characters; color never changes the layout, and
  stripping SGR sequences reproduces the colorless dashboard byte for byte.
- Colors follow ADR-0013's shared severity palette, gated on terminal
  detection, `--no-color`, and the `NO_COLOR` convention; color is never the
  only carrier of meaning.
- The layout adapts to the measured terminal width (clamped to 60–160
  columns; 80 when the width is unknown).
- **Piped text and `--json` are unchanged**: appending window blocks and the
  `stallhunt.watch_window` stream keep their ADR-0008 contract for scripts
  and tests.

## Consequences

Positive:

- sysadmins get magnitude, state, and history at a glance without a new
  dependency or an interactive framework to maintain;
- watch stays a diagnosis surface (pressure meters and finding lifecycle),
  not a utilization table, preserving the product differentiator;
- deterministic golden coverage remains possible because the dashboard is a
  pure function of `WatchWindow` plus a display configuration (width, color,
  refresh) that tests inject.

Costs:

- a second text renderer for watch to maintain alongside the piped format
  and JSON;
- terminals shorter than the frame will clip it; the dashboard does not yet
  adapt its height;
- no input handling yet: the dashboard is not interactive (deliberately).

## Alternatives considered

### `ratatui`/`crossterm` TUI framework

Rejected for now: full-cell buffering, widgets, and input handling are more
framework than the lifecycle view needs, and they add dependency weight the
project's conventions ask us to justify by concrete need. Revisit if
interactive navigation (selecting a finding, expanding evidence) is approved.

### Alternate screen (`smcup`/`rmcup`) like htop

Rejected: it hides session scrollback and complicates piped/CI behavior for
no diagnostic gain.

### Keep the scrolling text format on TTYs

Rejected: this was the user complaint.
