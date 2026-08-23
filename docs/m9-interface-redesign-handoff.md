# Milestone 9 interface redesign — session handoff

Last updated: 2026-08-23. Worktree branch: `stallhunt-qwen`.

This note exists so a future session can resume the Milestone 9 work without
chat history. Fold it into `status.md` / delete it once the redesign ships.

## Task

Users found v0.1.x output a "wall of text" in default mode and too primitive
in watch mode. Request: same information, clearer; modern TUI like htop/btop
for watch; valuable explanations compact by default, full on request. Document
everything, follow project rules, stay in this worktree, and do **not** open a
pull request yet (local users will test different redesigns first).

## What is done (all committed on `stallhunt-qwen`)

### Code
- `src/cli.rs`: `hunt --explain`, `replay --explain`, `watch --no-tui`.
  `HuntOptions.explain`, `ReplayOptions.explain`, `WatchOptions.no_tui`.
- `src/render.rs`: default text is now compact/verdict-first
  (`hunt_text_compact`); `--explain` keeps the exact v0.1.x report
  (`hunt_text_detailed`). JSON unchanged. Compact layout is a pure projection
  of analyzer output (no new claims).
- `src/tui.rs` (new): ratatui/crossterm watch TUI — header, host PSI gauges,
  lifecycle table, scoped cgroup pressure, severity history sparkline, footer;
  `e` details pane, `?`/`h` help overlay, `Esc` closes help, `q` quits,
  Ctrl-C drains then exits (second exits 130). Presentation-only: no
  collectors/inference. Respects `NO_COLOR`.
- `src/watch.rs`: `run()` dispatches to TUI when eligible; classic text
  fallback for non-TTY, `--no-tui`, `TERM=dumb`, or failed terminal setup.
  `InterruptFlag` now takes an `on_immediate_exit` hook so the TUI restores
  the terminal before the second-SIGINT exit. Helpers made `pub(crate)`.
- `src/main.rs`: registers `mod tui`.
- Version bumped to `0.2.0` in `Cargo.toml` + `Cargo.lock` (untagged).

### Dependencies
- Added `ratatui 0.29.0` + `crossterm 0.28.1` (NOT ratatui 0.30: it requires
  Rust 1.88, above the 1.85 MSRV). Resolves offline via local cargo cache.

### Tests
- Golden fixture `tests/fixtures/render/cpu-contention-compact.txt`;
  compact-vs-explained structural tests in `src/render.rs`.
- Deterministic ratatui `TestBackend` TUI tests in `src/tui.rs` (panels,
  overlays, empty/first-window, too-small terminal).
- Updated `tests/cli.rs` and `tests/replay_fixtures.rs` for the new contract.

### Docs / decisions
- ADR-0013 (terminal stack + watch TUI scope), ADR-0014 (compact-by-default
  output). ADR-0008 presentation clause marked superseded; lifecycle contract
  unchanged. `docs/decisions/README.md` index updated.
- Updated: `docs/status.md`, `docs/roadmap.md` (new M9), `docs/architecture.md`
  (layout + M9 paragraph), `docs/cli-ux.md`, `README.md`, `CHANGELOG.md`
  (0.2.0 unreleased), `docs/stallhunt.1` (man page, re-rendered with groff).

## Validation (last run, all passing)

```bash
cargo fmt --all -- --check
cargo clippy --locked --offline --workspace --all-targets --all-features -- -D warnings
cargo test --locked --offline --workspace --all-features
groff -man -Tutf8 docs/stallhunt.1 >/dev/null
```

Result: 166 unit tests, 15 CLI tests, 3 replay-fixture tests passed; ignored
opt-in Linux acceptance tests unchanged. Man page renders.

## What remains

1. Commit is staged on `stallhunt-qwen` — do NOT push or open a PR yet.
2. The first feedback pass (EXP-0009) is done and folded in: bare
   `stallhunt` accepts `--duration`/`--json`/`--explain`; the TUI footer says
   `Ctrl-C: 1st drains, 2nd exits now`; watch reports scoped cgroup
   collection as unavailable instead of claiming no pressure. Real local-user
   feedback on density, colors, and key bindings is still required (compare
   TUI vs `--no-tui` vs v0.1.x), ideally on a host where cgroup collection
   succeeds so the scoped panels can be seen live.
3. After feedback: finalize wording/layout, then decide the 0.2.0 tag/release.
4. Remove this handoff file (or fold into `status.md`) when M9 ships.

## Gotchas

- Do not upgrade ratatui past 0.29 without an MSRV decision (ADR-0013).
- The compact header deliberately omits the tool version so the golden
  fixture survives version bumps.
- `--explain` is ignored with `--json` (JSON always carries full evidence).
- TUI terminal-restore on second SIGINT is best-effort (handler exits directly).
