# Cross-pollination from sibling implementations

Stallhunt (`codex/`) is the production line. `grok/`, `kimi/`, and `zcode/` remain
reference implementations only. This document records what was adopted, deferred, or
rejected for v0.1 and why.

## Adopt now

| Donor | Item | Value | Compatibility | Disposition |
|-------|------|-------|---------------|-------------|
| Grok | CI, Cargo metadata, dual license, man page discipline | Repeatable quality gates and installable artifact baseline | Same Rust/stable toolchain; no inference coupling | **Adopted** in `.github/workflows/`, `LICENSE-*`, `docs/stallhunt.1` |
| Kimi | `clap` CLI + shell completions | Better `--help`, fewer hand-rolled parse bugs, packaged completions | Exit codes and command semantics preserved | **Adopted** in `src/cli.rs`, `completions` subcommand |
| zcode | Deterministic full-binary replay testing | Golden recordings exercise real `stallhunt replay` without live `/proc` | Concept only; zcode source is unlicensed and not copied | **Adopted** as committed redacted fixtures under `tests/fixtures/recordings/` |

## Defer

| Donor | Item | Why deferred |
|-------|------|--------------|
| Kimi | Compact per-hunt `degraded[]` footer | Stallhunt already exposes richer `capabilities`; revisit after JSON contract settles |
| zcode | D-state / wchan clustering | New collector + finding vertical slice; valuable victim evidence but not a quick win |
| Grok / zcode | Command-line labels on findings | Extra reads, privacy/redaction, and recording-schema impact |

## Reject for v0.1

| Donor | Item | Why rejected |
|-------|------|--------------|
| Grok | Scoring / threshold semantics, cgroup score roll-ups | Conflicts with evidence-first PSI contract |
| Kimi | Config/TUI, taskstats, eBPF | Different product surface and privilege model |
| zcode | Full `--proc-root` retrofit | Large compatibility and maintenance cost |

## Fixture replay path

Committed recordings are redacted (`redaction: identifiers`) and replayed through the
real CLI:

```bash
stallhunt replay --json tests/fixtures/recordings/cpu-contention.redacted.json
stallhunt replay tests/fixtures/recordings/cpu-healthy.redacted.json
```

Integration coverage lives in `tests/replay_fixtures.rs`.

## License note

Do not copy zcode source while it remains unlicensed. The replay-fixture approach
implements only the **testing concept** using Stallhunt-native recordings.
