# Changelog

All notable user-facing changes to Stallhunt are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once public releases begin.

## [Unreleased]

### Changed

- `hunt` and `replay` default to a compact text form (status table, bounded per-finding blocks, one-line evidence-chain summaries); `--explain` renders the previous full long-form output byte-identically. JSON output is unchanged. See ADR-0013.
- `watch` on a terminal opens an interactive TUI by default; `--plain` restores the classic clear/home text refresh. Piped text and `--json` are byte-compatible with before.
- Color is automatic on terminals and disabled by `--no-color` or a `NO_COLOR` environment variable with any value; severity words remain in the text, so color is never the only carrier of meaning.

### Added

- `--explain` flag on `hunt` and `replay` for the full long-form output.
- `--no-color` flag on `hunt`, `replay`, `capabilities`, and `watch`.
- `--plain` flag on `watch` for the classic refreshing text display.
- Interactive `watch` TUI (ratatui 0.29 + crossterm 0.29): PSI bars with bounded sparklines, finding lifecycle, current-window detail, scoped cgroup panel, help overlay (`?`), pause (`p`/Space), quit-with-drain (`q`/Esc/Ctrl-C). The SIGINT contract is unchanged: first SIGINT drains the in-flight window, second SIGINT restores the terminal and exits 130.
- ADR [`docs/decisions/0013-interface-redesign.md`](docs/decisions/0013-interface-redesign.md), which supersedes the ADR-0008 no-TUI clause.

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
