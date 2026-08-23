# Changelog

All notable user-facing changes to Stallhunt are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once public releases begin.

## [0.2.0] - unreleased (Milestone 9 interface redesign, pending local user feedback)

### Added

- `hunt --explain` and `replay --explain` restore the full evidence, qualifiers, and timing report (ADR-0014).
- `watch` renders a full-screen TUI on terminals (ratatui + crossterm): host pressure gauges, finding-lifecycle table, scoped cgroup pressure, severity history sparkline, a details pane (`e`), and a help overlay (`?`/`h`) (ADR-0013).
- `watch --no-tui` forces the classic refreshing text renderer on a terminal.
- The watch TUI honors `NO_COLOR`; severity words are always rendered so color never carries meaning alone.
- Deterministic ratatui `TestBackend` render tests for the TUI and golden fixtures for both compact and explained text layouts.

### Changed

- Default `hunt`/`replay` text output is now compact and verdict-first: one headline, one line per host resource with verdict/severity/PSI, leading affected/suspect candidates, prominent scoped pressure, related-evidence lines, and a footer pointing at `--explain`/`--json` (ADR-0014). Scripts parsing the old default text should switch to `--explain` or `--json`.
- `watch` automatically falls back to classic text when stdout is not a terminal, `TERM=dumb`, `--no-tui` is passed, or terminal setup fails.
- ADR-0008's presentation clause is superseded by ADR-0013; its lifecycle, history, JSON-stream, and SIGINT contracts are unchanged.

## [0.1.2] - 2026-08-23

### Fixed

- A second SIGINT now terminates an unlimited `watch` immediately with status 130 while the first SIGINT still drains the in-flight window.
- The 16-chain truncation regression now constructs 18 eligible chains, so the test fails if rank-then-truncate behavior is removed or broken.

## [0.1.1] - 2026-08-22

### Changed

- Acceptance-test environment variables renamed from `BOTTLENECK_MEMORY_ACCEPTANCE_PATH` / `BOTTLENECK_CGROUP_ACCEPTANCE_PATH` to `STALLHUNT_MEMORY_ACCEPTANCE_PATH` / `STALLHUNT_CGROUP_ACCEPTANCE_PATH`.
- Unlimited `watch` now drains gracefully: the first SIGINT lets the in-flight window complete and be written before exit. Immediate second-SIGINT termination was completed in v0.1.2. Bounded `--count` runs keep default SIGINT termination.

### Added

- Regression tests for the 16-evidence-chain truncation order, schema-1 recording decode without `memory_stat`, host-memory watch kind transitions staying persistent on one identity, and invalid host memory PSI `full` blocking possible-thrashing. The truncation fixture was corrected in v0.1.2 so it actually reaches the truncation step.
- Workflow actions bumped past Node.js 20 deprecation (`actions/upload-artifact@v7`, `softprops/action-gh-release@v3`).

## [0.1.0] - 2026-08-18

### Added

- Product identity as **Stallhunt**: crate and binary name `stallhunt`.
- Dual license: MIT OR Apache-2.0.
- Minimum supported Rust version (MSRV): 1.85.
- Minimum supported Linux baseline: kernel 4.20+ with procfs and PSI.
- Clap-based CLI with subcommands `hunt`, `watch`, `record`, `replay`, `redact`, `capabilities`, `completions`, and `version`.
- Bare `stallhunt` defaults to a 10-second hunt.
- `stallhunt completions <shell>` for bash, zsh, fish, and other supported shells.
- JSON document kinds `stallhunt.recording` and `stallhunt.watch_window`.
- Legacy replay support for recordings with `kind` `bottleneck.recording`.
- [`docs/install.md`](docs/install.md) with install paths and support matrix.
- ADR [`docs/decisions/0012-stallhunt-identity.md`](docs/decisions/0012-stallhunt-identity.md).

### Fixed

- Watch no longer reports an active cgroup finding as `resolved` when that scope remains pressured but falls below the current window's top-16 cgroup ranking. Ranking omission now leaves the finding persistent and unconfirmed.

### Changed

- Documentation rewritten for installed-binary use rather than `cargo run` workflows.
