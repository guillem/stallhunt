# ADR-0013: Watch becomes a finding-lifecycle TUI; hunt gains a styled report

- Status: Accepted; watch compatibility superseded in part by ADR-0014 and TUI layout superseded in part by ADR-0016
- Date: 2026-08-23

## Context

Users report that the default `hunt` output is a "wall of text" and that
`watch` is "too primitive." Concretely:

- `hunt` stacks four to five severity-ranked sections (CPU, memory, I/O,
  cgroup, evidence chains), each carrying its own verdict, evidence,
  candidate lists, and "Context and limitations" qualifier block. The
  anti-overclaiming qualifiers (ADR-0004) are valuable but numerous—often
  ten or more lines on a multi-resource host—and there is no way to see
  less of them without losing them.
- `watch` (ADR-0008) reprints a full frame on a TTY by clearing the screen
  and writing plain text again. There is no alternate screen, no partial
  redraw, no keyboard interaction, and no visual distinction beyond
  fixed-width text columns—hence the flicker and the "primitive" complaint.

ADR-0008 explicitly rejected a TUI for watch: "A TUI resource monitor...
would display utilization rather than finding lifecycle and would require
terminal-framework scope the product explicitly deferred." That objection
targeted a *utilization dashboard*—an `htop`/`top` clone showing what is
busy. It did not evaluate a TUI whose panels are the finding-lifecycle model
watch already computes (new/persistent/resolved, per docs/cli-ux.md's own
stated opening for a future TUI: "display changing findings rather than
simply reproduce htop"). This ADR proposes exactly that: the tracked
lifecycle, evidence, and history watch already renders as text become the
content of interactive panels, not a replacement domain model.

`docs/status.md` has carried "color/terminal crate" as a deliberately open
decision since ADR-0012, to be resolved "when implementation makes the
tradeoff concrete." That point has arrived.

This is a user-experience change, not a new diagnostic capability: no new
telemetry source, analyzer, or finding kind is introduced. It does not
reopen the M7 (eBPF) or additional M8 (evidence chain) work the project
keeps parked.

## Decision

**`hunt` and `replay` gain a compact, color-coded, width-aware static
report** as their text output when stdout is a terminal. Severity,
confidence, and verdict words remain in the text in every case—color is a
supporting signal, never the only carrier of meaning, per the color
requirement already specified in docs/cli-ux.md. The full per-section
"Context and limitations" qualifier text collapses by default to a count
and a small set of keyed tags (for example: `Context: 4 caveats (causality,
attribution, collection) — use --verbose for full text`); the reserved
`--verbose` flag restores the verbatim messages. When stdout is not a
terminal, `hunt`/`replay` emit exactly the plain text they emit today—same
bytes, same golden fixtures. This is the escape hatch for scripts, CI, and
users who prefer the old format: `stallhunt | cat`.

**`watch` gains a full-screen terminal UI** when stdout is a terminal,
built on `ratatui` (0.29) with the `crossterm` (0.28) backend. The UI's
panels are the finding-lifecycle model already computed by the watch
tracker: a lifecycle list (new/persistent/resolved, with age and prior
severity), the current window's per-resource status, a bounded history
timeline over the existing 16-window window, and a detail pane with full
evidence and qualifiers for the selected finding, reachable without
`--verbose`. Small PSI indicators are supporting visuals alongside the
lifecycle panels, not the centerpiece—this is what distinguishes the
design from the utilization dashboard ADR-0008 rejected. Piped text output
and `--json` are unchanged: same frames, same
`stallhunt.watch_window` stream, no alternate screen, no raw mode. The
watch lifecycle model, tracked identities, 16-window history bound, and
two-stage SIGINT semantics defined in ADR-0008 are unchanged; only the TTY
presentation layer changes.

**Dependencies.** Add `ratatui = { version = "0.29", default-features =
false, features = ["crossterm"] }` and `crossterm = "0.28"`. Verified
against the project's MSRV 1.85 (`rust-version` in `Cargo.toml`):
`ratatui` 0.29.0 declares `rust-version = "1.74.0"` and `crossterm` 0.28.1
declares `rust-version = "1.63.0"`; both are below 1.85. `ratatui` 0.30.x
declares `rust-version = "1.88.0"` and must not be used while MSRV is
1.85. This is the largest dependency addition the project has taken;
it is justified because a correct alternate-screen, raw-mode, resize- and
input-handling terminal layer is exactly the kind of capability
docs/architecture.md's dependency guidance says is worth taking a
dependency for, rather than owning bespoke terminal-control code with no
test coverage for real terminal behavior. `ratatui`/`crossterm` are pulled
in with default features disabled beyond `crossterm`, keeping unrelated
widget/backend surface out of the build.

**Color.** `--no-color` is added to `hunt`, `replay`, and `watch`; the
`NO_COLOR` environment variable (any non-empty value, per
https://no-color.org) is also honored. Both affect color only, never
layout: a non-TTY invocation already renders the legacy plain-text layout
regardless of `--no-color`, and a TTY invocation keeps the compact
layout with color disabled. There is no `--format` flag; TTY-vs-pipe is
the only layout switch, keeping the CLI surface from growing a flag whose
only purpose is to reproduce output pipe redirection already provides.

**Compatibility guarantees.** Hunt JSON, the watch JSON stream, and
recording/replay schemas are unchanged by this ADR. Piped text output for
`hunt`, `replay`, and `watch` is unchanged—existing golden fixtures
(`tests/fixtures/render/cpu-contention.txt`,
`evidence-chain.txt`, `evidence-chain-cgroup.txt`,
`hunt-legacy-full.txt`, `watch-lifecycle.txt`) continue to assert that
path byte-for-byte, including the existing assertion that legacy hunt text
contains no ANSI escape byte. New golden fixtures for the compact report
and TUI draw buffers are added alongside, not in place of, the legacy
ones.

This closes the "color/terminal crate" item in docs/status.md's known open
decisions.

## Consequences

Positive:

- sysadmins see the same evidence in far less vertical space by default,
  with the full anti-overclaiming detail one keystroke or flag away,
- watch stops flickering and gains keyboard navigation without changing
  what it tracks or how often it collects,
- scripts, CI, and `--json` consumers are unaffected—no compatibility
  break,
- the open color/terminal-crate decision is resolved with a documented
  rationale instead of remaining indefinitely deferred.

Costs:

- roughly twenty new transitive crates and a larger binary,
- raw-mode/alternate-screen terminal state must be restored on every exit
  path (normal, `q`, `--count` completion, both SIGINT stages, panics)—new
  code surface that owns that responsibility,
- two presentation surfaces now exist for hunt/replay (legacy text,
  compact report) and two for watch (legacy frames, TUI); both must stay
  driven by the same single analysis pass (`render::analyze_hunt`,
  `HuntAnalyses`) so they cannot diverge in diagnosis,
- the `--locked --offline` CI validation gate requires the updated
  `Cargo.lock` to be committed; the full dependency closure was confirmed
  to resolve and build offline against the locally cached registry before
  this change landed.

## Alternatives considered

### Reproduce ADR-0008's rejected utilization dashboard

Rejected for the same reason ADR-0008 rejected it: a dashboard of gauges
and per-process tables competes with `top`/`htop` and would pull the
product back toward utilization rather than the finding-lifecycle model
that is Stallhunt's actual contribution.

### Hand-rolled terminal control (crossterm only, or raw ANSI/anstyle)

Rejected as the default approach: alternate screen, raw mode, resize
handling, and layout would all be bespoke and under-tested. `crossterm`
alone remains a smaller option in principle, but `ratatui`'s layout and
widget primitives remove enough owned complexity (buffered diffing,
constraint-based layout, testable `TestBackend` snapshots) to justify the
larger dependency, especially for a UI meant to match `htop`/`btop`
quality.

### A `--format classic|compact` flag

Rejected: it adds a flag whose only purpose is to reproduce what piping
already provides, and docs/cli-ux.md's flag-discipline guidance
("do not add flags before a real use case exists") argues against it
while `stallhunt | cat` remains available.

### Collapse qualifiers only in the TUI, keep hunt's text verbose by default

Rejected: it does not address the "wall of text" complaint, which is about
default `hunt` output specifically, not just watch.

### Widen `OutputFormat` with a third TUI/Rich variant

Rejected: the TTY-vs-pipe upgrade is a dispatch decision made once per
invocation from `stdout().is_terminal()`, not a distinct output format a
user selects; keeping `OutputFormat` as `Text | Json` avoids a third value
that would need to interact with `--json` in confusing ways.
