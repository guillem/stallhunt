# ADR-0013: Interface redesign — compact hunt output and interactive watch TUI

- Status: Accepted
- Date: 2026-08-23

## Context

Local user feedback on the pre-M9 interface had two recurring complaints:

- the default `hunt` text is a wall of text: full evidence sections for every
  resource, qualifiers, and timing lines, even when the answer is a single
  contention finding;
- `watch` on a TTY is a primitive clear-screen reprint of the same text window,
  neither a modern TUI nor a classic UNIX tool that behaves well when piped.

Operators asked for htop/btop-grade presentation without losing the product's
differentiator: Stallhunt reports lost progress and likely causes, not
utilization. The question was how to make the default output glanceable while
keeping the evidence-backed diagnosis reachable and keeping watch scriptable.

## Decision

### Compact default text with `--explain`

`hunt` and `replay` default to a compact text form: a one-line summary, a
resource status table covering CPU/Memory/I/O (plus pressured cgroup scopes),
a 2–4 line block per finding, one-line `related:` summaries for evidence
chains, and a trailer pointing at the long form. Partial collection stays
visible as `partial` markers. A new `--explain` flag on both commands renders
the previous full long-form output, byte-identical to the pre-M9 renderer.
JSON output is unchanged and remains the full structured-evidence interface.

### Color policy

Color support is hand-rolled ANSI in a new `color` module; no terminal crate
was added for it. Severity maps to color (severe/high red, moderate yellow,
low cyan, healthy green). Color applies only when stdout is a terminal, is
disabled by `--no-color` (on `hunt`, `replay`, `capabilities`, and `watch`)
or by a `NO_COLOR` environment variable with any value, and is never the only
carrier of meaning: status and severity words remain in the text. Only the
compact text form and the TUI are colored; the `--explain` long form and
capabilities text are not.

### Interactive watch TUI

`watch` opens a ratatui + crossterm TUI by default when stdout is a terminal
and `--json` was not given. `--plain` restores the legacy clear/home text
refresh; piped text and `--json` remain byte-compatible with the pre-M9
output. The TUI consumes the same `WatchWindow` data as the text and JSON
paths and extracts per-process detail from the observation before signal
reduction, so neither the tracker nor the `stallhunt.watch_window` JSON
contract changes. The SIGINT contract is preserved: the first SIGINT (or
`q`/Esc/Ctrl-C) drains the in-flight window, and a second SIGINT restores the
terminal and exits 130.

This decision supersedes the ADR-0008 clause that explicitly ruled out a TUI
crate, alternate screen, and interactive navigation ("There is no TUI crate,
alternate screen, or interactive navigation"). The finding-lifecycle model of
ADR-0008 stands; only the output mechanism for terminal `watch` changes.

## Consequences

Positive:

- the default `hunt` answer fits on one screen and is skimmable,
- full evidence remains one flag away (`--explain`) and stays byte-identical,
  so the long-form golden fixtures continue to guard it,
- color is safe for pipes and scripts by default and never changes meaning,
- `watch` on a TTY now has pressure history, finding lifecycle, current-window
  detail, and a help overlay, while piped/`--json` behavior is unchanged.

Costs:

- two new direct dependencies: `ratatui` 0.29 and `crossterm` 0.29.
  `ratatui` 0.30 was rejected because it requires Rust 1.86, above the
  project's MSRV 1.85. Until ratatui can be upgraded, the lockfile contains
  two crossterm copies: 0.28.1 transitively via ratatui and 0.29.0 direct;
- TUI correctness on a real TTY cannot be exercised by CI (no TTY in the CI
  environment); it is validated by headless `ratatui::backend::TestBackend`
  unit tests and by manual/PTY smoke runs;
- the causality-language discipline now applies to widgets: the TUI labels
  delayed tasks as observed and suspects/activity candidates as same-window
  correlations, and the help overlay states the same caveats as the text form;
- the compact form omits qualifier bodies, context, and timing detail; that
  information is reachable only via `--explain` or `--json`.

## Alternatives considered

### Hand-rolled ANSI plus rustix termios instead of ratatui

Rejected: key handling, resize handling, diffed redraw, and layout widgets are
exactly the complexity the project would otherwise own; ratatui removes that
complexity for a well-maintained, pure-Rust dependency.

### `--verbose` instead of `--explain`

Rejected: `--verbose` conventionally implies diagnostic noise, not a fuller
explanation of a diagnosis. `--explain` names the long form's purpose.

### Opt-in `--tui` flag instead of TUI-by-default

Rejected: a hidden-away opt-in flag would be undiscoverable, and the default
TTY experience is precisely what the feedback criticized. `--plain` preserves
the old behavior for minimal terminals, pipes, and scripts without
discoverability problems.

### `ratatui` 0.30

Rejected: 0.30.0 requires Rust 1.86, above the documented MSRV 1.85
(ADR-0012). The lock pins ratatui 0.29 until the MSRV can move.
