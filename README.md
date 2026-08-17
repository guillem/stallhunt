# Bottleneck Finder

**Working title. Final project/binary name TBD.**

Bottleneck Finder is a Linux-first command-line performance triage tool.

Traditional tools such as `top`, `htop`, `iotop`, `vmstat`, and `iostat` expose measurements. They are excellent tools, but the human operator still has to answer the harder question:

> **What is actually constraining useful work right now, who is suffering, and who is probably responsible?**

Bottleneck Finder aims to automate that reasoning.

## Core idea

The primary abstraction is **lost time**, not utilization.

High utilization is not automatically a problem. A machine using 95% of its RAM may be perfectly healthy. A CPU at 70% utilization may still have latency-sensitive work suffering from scheduler contention. The project therefore focuses on evidence of stalled progress:

- CPU scheduler pressure,
- I/O stalls,
- memory pressure/reclaim,
- lock contention,
- network-related waits,
- eventually deeper blocking chains.

A future invocation might look like:

```text
$ bottleneck hunt --duration 10s

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
- stable machine-readable JSON,
- bounded observation windows,
- deterministic offline fixture/replay analysis.

Later releases may add:

- eBPF-based off-CPU analysis,
- futex/lock contention,
- syscall/blocking attribution,
- network queue/socket diagnosis,
- dependency/wait graphs,
- continuous watch mode,
- recording and replay,
- richer cgroup/container analysis.

## Repository map

```text
.
├── AGENTS.md
├── Cargo.toml
├── README.md
├── src/
│   ├── cli.rs
│   ├── main.rs
│   └── render.rs
├── tests/
│   └── cli.rs
└── docs/
    ├── README.md
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

## Current state

Milestones 1.1 through 1.4 are complete. The repository contains a Rust binary
with real `hunt`, `capabilities`, help, version, duration parsing, and
text/JSON output boundaries.

`hunt` reads CPU PSI, `/proc/stat`, `/proc/loadavg`, bounded process, and
bounded task scheduler-accounting snapshots before and after the requested
interval. It reports PSI, host CPU
counter deltas, capacity/load context, and CPU deltas for processes that
persisted with the same PID and start time across both snapshots. It does not
yet infer contention severity, identify victims or suspects, or claim causal
attribution. Scheduler-delay candidates are raw summed stable-thread evidence,
not confirmed victims. `capabilities` also reports scheduler accounting state.

Run the current binary with:

```bash
cargo run -- hunt --duration 1s
cargo run -- capabilities
```

The next task is CPU inference (M1.5).

See [`docs/status.md`](docs/status.md) and [`docs/roadmap.md`](docs/roadmap.md).
