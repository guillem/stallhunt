# Stallhunt

Stallhunt is a Linux-first command-line performance triage tool.

Repository: https://github.com/guillem/stallhunt

Traditional tools such as `top`, `htop`, `iotop`, `vmstat`, and `iostat` expose measurements. They are excellent tools, but the human operator still has to answer the harder question:

> **What is actually constraining useful work right now, who is suffering, and who is probably responsible?**

Stallhunt aims to automate that reasoning.

## Install

Requirements:

- Linux 4.20 or newer with procfs mounted; readable PSI files under `/proc/pressure` are required for pressure verdicts,
- Rust 1.85 or newer for source builds.

See [`docs/install.md`](docs/install.md) for `cargo install`, release tarballs, and the support matrix.

From a clone:

```bash
cargo install --path .
stallhunt
```

Bare `stallhunt` runs a default 10-second hunt. On a terminal it renders a
compact, color-coded report; piped or redirected output (`stallhunt | cat`,
`>file`, CI) is unchanged plain text. Use `--json` for the full structured
evidence, `--verbose` to expand the compact report's collapsed caveats back
to full text, or `--no-color` (also `NO_COLOR=1`) to disable color without
changing the layout:

```bash
stallhunt --json
stallhunt hunt --duration 30s
stallhunt hunt --verbose
```

Capture and replay a normalized observation:

```bash
stallhunt record --duration 10s --output incident.json
stallhunt replay incident.json
stallhunt redact incident.json --output incident.redacted.json
```

Follow finding lifecycle for a bounded number of rolling windows. On a
terminal this opens a full-screen TUI (`q` quit, arrows/`jk` select,
`Enter`/`Space` show or hide detail, `PageUp`/`PageDown`/`Home`/`End` scroll,
`h`/`?` help). At 120×30 or larger it also shows the selected host/cgroup's
six process-role lists beside the lifecycle panels; piped output or
`--json` are unchanged append-only text/JSON:

```bash
stallhunt watch --interval 2s --count 3
```

Generate shell completions:

```bash
stallhunt completions bash > ~/.local/share/bash-completion/completions/stallhunt
stallhunt completions zsh > ~/.local/share/zsh/site-functions/_stallhunt
```

Recording output paths are not overwritten unless `--force` is supplied. Ten-second hunts are the normal diagnostic path; sub-second observations are telemetry smoke tests and do not receive healthy or pressure verdicts. See [`docs/development.md`](docs/development.md) for validation and opt-in acceptance commands.

## Core idea

The primary abstraction is **lost time**, not utilization.

High utilization is not automatically a problem. A machine using 95% of its RAM may be perfectly healthy. A CPU at 70% utilization may still have latency-sensitive work suffering from scheduler contention. The project therefore focuses on evidence of stalled progress:

- CPU scheduler pressure,
- I/O stalls,
- memory pressure/reclaim,
- lock contention,
- network-related waits,
- eventually deeper blocking chains.

Example output shape:

```text
$ stallhunt

SYSTEM HEALTH: DEGRADED

1. CPU scheduling contention                         SEVERE
   Impact:    23.4% pressure during observation
   Victims:   postgres [4812], nginx [5120]
   Suspects:  rustc [9231], ffmpeg [9401]
   Confidence: high

   Evidence:
     CPU PSI some avg10:          23.4%
     run queue latency estimate:  elevated
     rustc CPU consumption:       735%
     postgres runnable delay:     3.8s / 10s

2. Block I/O contention                              MODERATE
   Device:    nvme0n1
   Victim:    postgres [4812]
   Suspect:   restic [7712]
   Confidence: medium

Memory: no significant pressure detected.
High memory occupancy alone is not treated as a bottleneck.
```

This output is aspirational; the project will reach it incrementally.

## Product principles

1. **Diagnose, do not merely display.**
2. **Measure stalled progress whenever possible.**
3. **Separate observation from inference.**
4. **Show evidence for every diagnosis.**
5. **Express uncertainty explicitly.**
6. **Remain useful without eBPF.**
7. **Stay cheap enough to run on a stressed system.**
8. **Treat Git as the complete project memory.**

## Initial scope

The first useful release targets Linux and focuses on:

- CPU scheduling contention,
- memory pressure,
- block I/O pressure,
- per-process attribution where Linux exposes enough evidence,
- cgroup/systemd-aware grouping when practical,
- human-readable terminal output,
- versioned machine-readable JSON (the pre-1.0 shape may evolve),
- bounded observation windows,
- deterministic offline fixture/replay analysis.

Later releases may add:

- eBPF-based off-CPU analysis,
- futex/lock contention,
- syscall/blocking attribution,
- network queue/socket diagnosis,
- dependency/wait graphs,
- richer cgroup/container analysis.

## Repository map

```text
.
├── AGENTS.md
├── CHANGELOG.md
├── Cargo.toml
├── LICENSE-APACHE
├── LICENSE-MIT
├── README.md
├── src/
│   ├── analysis.rs
│   ├── cgroup.rs
│   ├── cli.rs
│   ├── cpu.rs
│   ├── duration_us.rs
│   ├── io.rs
│   ├── main.rs
│   ├── memory.rs
│   ├── observe.rs
│   ├── psi.rs
│   ├── record.rs
│   ├── render.rs
│   ├── report.rs
│   ├── style.rs
│   ├── tui/
│   └── watch.rs
├── tests/
│   ├── cgroup_acceptance.rs
│   ├── cli.rs
│   ├── cpu_acceptance.rs
│   ├── io_acceptance.rs
│   ├── memory_acceptance.rs
│   └── fixtures/
│       ├── cpu/
│       └── proc-*
└── docs/
    ├── README.md
    ├── install.md
    ├── product.md
    ├── architecture.md
    ├── data-model.md
    ├── telemetry.md
    ├── inference-engine.md
    ├── cli-ux.md
    ├── security-privileges.md
    ├── testing.md
    ├── development.md
    ├── codex-workflow.md
    ├── experiments.md
    ├── references.md
    ├── roadmap.md
    ├── status.md
    ├── glossary.md
    └── decisions/
```

Start with [`AGENTS.md`](AGENTS.md), then [`docs/README.md`](docs/README.md).

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.

## Current state

For the current milestone, implemented capabilities, validation, known limits,
and the next recommended task, see [`docs/status.md`](docs/status.md). Planned
sequencing remains in [`docs/roadmap.md`](docs/roadmap.md).
