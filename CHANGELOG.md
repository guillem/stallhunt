# Changelog

All notable user-facing changes to Stallhunt are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once public releases begin.

## [Unreleased]

### Added

- Compact, color-coded, width-aware `hunt`/`replay` report on a TTY (ADR-0013), alongside — never instead of — the unchanged plain-text output on a pipe.
- `--verbose` on `hunt`/`replay` restores the full per-finding qualifier text the compact report collapses to a tag summary by default.
- `--no-color` on `hunt`, `replay`, and `watch`, and support for the `NO_COLOR` environment variable; both affect color only, never layout.
- Interactive full-screen `watch` TUI on a TTY (ADR-0013), built on `ratatui`/`crossterm`: a lifecycle list, current-window status, a bounded history timeline, and a per-finding detail pane showing full qualifier text without a flag. Keys: `q`/`Esc` quit, `↑`/`↓`/`j`/`k` select, `Enter`/`Space` expand detail, `h`/`?` help. Terminal state is restored on every exit path, including both SIGINT stages.

### Changed

- `watch` no longer clears and reprints the screen on a TTY; that presentation is replaced by the TUI above. Piped text and `--json` are unchanged.

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
