# Changelog

All notable user-facing changes to Stallhunt are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once public releases begin.

## [Unreleased]

## [0.4.1] - 2026-08-25

### Fixed

- A taskstats interval with no overlapping process identities between the
  start and end snapshots (normal churn) reported `Available` capability
  whenever both endpoint queries individually succeeded, instead of
  `Partial`. Downstream, this made a window with zero collected taskstats
  evidence read as a complete, confirmed clean negative for CPU, memory, and
  I/O completeness, undermining the completeness signal ADR-0015 is built
  around.
- The taskstats-only CPU-delay victim candidate (no schedstat corroboration)
  was scored at full resource confidence instead of the discounted fallback
  tier ADR-0015 specifies for CPU, unlike the analogous I/O taskstats/procfs
  fallback, which already discounted correctly.
- `watch`'s piped-text output rendered a full six-role "unavailable" block for
  every stale lifecycle finding, even ones that never had process candidates.
- CPU thread-churn counting (appeared/exited/identity-changed) missed churn on
  a thread whose kernel stat record omitted `delayacct_blkio_ticks`, letting
  `task_stat_capability` claim full completeness despite real churn.
- `terminal_scope_identifier` could return the 16-character
  `<unnamed-scope>` fallback even under a zero-width budget, breaking the
  width invariant on very narrow terminals.

## [0.4.0] - 2026-08-24

### Added

- Scoped, analyzer-owned process attribution for CPU, memory, and I/O victims
  and suspects. Host and PSI-pressured cgroup scopes each retain up to five
  deterministic candidates per role, with evidence, confidence, and
  completeness kept separate from the resource verdict.
- Bounded procfs leader RSS/RSS-growth, fault, and stable-task block-I/O-delay
  evidence, plus optional, permission-gated TASKSTATS GET collection. TASKSTATS
  is strictly bounded and never enables delay accounting or elevates privilege.
- Canonical schema-2 `process_scopes` in hunt/replay and watch JSON. Schema-1
  recordings remain readable and redactable, but replay their absent v0.4
  process evidence as unavailable.
- Responsive watch presentation: at 120x30 and larger, a selected-scope
  six-role grid appears beside lifecycle, current, history, and scrollable
  detail. Compact terminals retain navigable summaries.

### Changed

- New recordings use schema 2. Derived candidates remain out of recordings so
  replay always re-runs the current analyzer.
- Watch lifecycle retention preserves scoped role lists as explicitly stale
  evidence rather than presenting previous candidates as current.

## [0.3.0] - 2026-08-24

### Added

- Typed, bounded CPU-victim, CPU-suspect, and I/O-suspect attribution across watch's piped text, JSON, lifecycle findings, and terminal UI. Retained candidates on unconfirmed or resolved findings are explicitly labeled last observed.
- An always-visible three-column Processes panel in the watch TUI, with complete candidate evidence in expanded finding detail and explicit empty/unavailable states.
- Parser-level regression coverage for executable documentation examples and ADR-0014 for the implicit-hunt and watch-attribution contracts.

### Fixed

- Bare `stallhunt` now accepts `--duration`, `--json`, `--verbose`, and `--no-color` with explicit-`hunt` parity; mixing root hunt flags with a subcommand is rejected with usage status 2.

### Changed

- Watch JSON additively exposes process candidates and candidate availability while retaining `schema_version: 1`.
- The README now points to the authoritative status and roadmap documents instead of duplicating milestone state.

## [0.2.0] - 2026-08-23

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
