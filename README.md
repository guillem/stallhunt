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

Bare `stallhunt` runs a default 10-second hunt and prints the compact text
form. Use `--explain` for the full long-form evidence and `--json` for the
full structured evidence:

```bash
stallhunt
stallhunt hunt --duration 30s
stallhunt hunt --explain
stallhunt --json
```

Capture and replay a normalized observation:

```bash
stallhunt record --duration 10s --output incident.json
stallhunt replay incident.json
stallhunt redact incident.json --output incident.redacted.json
```

Follow finding lifecycle for a bounded number of rolling windows. On a
terminal, `watch` opens an interactive TUI (press `?` for help; `q` quits);
`--plain` restores the classic clear-screen text refresh:

```bash
stallhunt watch --interval 2s --count 3
stallhunt watch --plain --interval 2s --count 3
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

Example output shape (real compact form; `--explain` renders the full
evidence version):

```text
$ stallhunt hunt --no-color
Observed 10.0s · 2 findings · worst: Memory moderate

RESOURCE  STATUS       PSI some  SEVERITY  CONFIDENCE
CPU       healthy      0.50%     none      medium
Memory    pressure     8.00%     moderate  high
I/O       pressure     8.00%     moderate  high

Memory pressure observed with correlated direct reclaim activity (8.00% memory PSI some) — severity moderate · confidence high
  800ms stalled over 10s (PSI some 8.00%)
  mechanism: direct reclaim (confidence low; same-window counters)

Block-I/O pressure observed (8.00% I/O PSI some) — severity moderate · confidence high
  800ms stalled over 10s (PSI some 8.00%)
  activity: sda (8:0), writer [42] (same window, not proven causal)

related: Memory reclaim pressure is consistent with block-I/O pressure in the same window · confidence low

Details: stallhunt hunt --explain · full evidence: --json
```

The default output answers the triage question in one screen; full evidence,
context, limitations, and timings are one `--explain` away.

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
│   ├── color.rs
│   ├── cpu.rs
│   ├── duration_us.rs
│   ├── io.rs
│   ├── main.rs
│   ├── memory.rs
│   ├── observe.rs
│   ├── psi.rs
│   ├── record.rs
│   ├── render.rs
│   ├── tui.rs
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

Milestones 1–6 are functionally complete. Milestone 8's first two evidence-chain
slices are implemented. Milestone 9's interface redesign (compact default
output, color, interactive watch TUI) is implemented and pending local user
feedback. Milestone 2's host-memory slice is
implemented and has a recorded delegated-cgroup harmful-pressure acceptance.
The repository contains a Rust binary named `stallhunt` with real `hunt`, `watch`, `record`,
`replay`, `redact`, `capabilities`, help, version, duration parsing, and
text/JSON output boundaries.

`hunt` reads CPU PSI, `/proc/stat`, `/proc/loadavg`, bounded process, and
bounded task scheduler-accounting snapshots before and after the requested
interval. It reports PSI, host CPU
counter deltas, capacity/load context, and CPU deltas for processes that
persisted with the same PID and start time across both snapshots. The CPU slice derives
an evidence-backed CPU resource verdict from valid exact-interval CPU PSI,
including provisional severity and explicit no-meaningful-contention results.
It ranks scheduler-delay victim candidates and same-window CPU-consumer suspect
candidates with qualifiers; neither role is a causal claim. `capabilities` also
reports scheduler accounting state.

CPU inference remains conservative: only exact-interval CPU PSI `some`
determines whether contention exists. A valid interval below 1% reports no
meaningful CPU scheduling contention; 1/5/15/30% are the provisional low,
moderate, high, and severe boundaries. Intervals below one second are telemetry
smoke observations and explicitly do not receive a healthy or contention verdict.

See [`docs/status.md`](docs/status.md) and [`docs/roadmap.md`](docs/roadmap.md).

M1.6 adds a concise finding-first text renderer with deterministic golden
coverage, serialized rootless ignored CPU acceptance tests (including an
eight-logical-CPU safety gate before oversubscription and RAII cleanup), and an
opt-in scenario-based overhead harness. JSON remains the full
structured-evidence interface. The
controlled results exercise the provisional none/low/moderate/high/severe bands,
but do not prove portable exact boundaries. EXP-0007 records workstation-scale
PID/task collector overhead; the 4,096-PID and 16,384-task caps were not
reached.

`hunt` also takes bounded host-memory PSI, `/proc/meminfo`, and selected
`/proc/vmstat` snapshots around the same requested sleep. Exact-interval memory
PSI `some` alone controls the memory verdict; `full` is retained as a
non-additive subset for possible-thrashing context. That heuristic also
requires material direct-reclaim and bidirectional-swap rates and carries a
separate confidence ceiling. Meminfo and vmstat only
classify/contextualize a PSI verdict, and this host-wide slice makes no process
attribution. Deterministic fixtures, a live healthy smoke, and a delegated-
cgroup harmful-pressure acceptance (21–24% host PSI `some`,
`memory_swap_pressure`) are recorded. Reclaim-only and possible-thrashing
labels remain fixture-validated.

M3 block-I/O pressure is functionally complete after a bounded rootless
competing-I/O acceptance run. It uses exact-interval I/O PSI `some` for the
verdict, retains non-additive `full` context, and only ranks disk/process
activity in the same window after PSI pressure is found. Disk and process
candidates are not victims, are not mapped to one another, and do not establish
causality. High I/O activity with low PSI remains a healthy/no-contention result.
M4 adds bounded cgroup-v2/service context: it discovers the actual unified
mount, validates stable `stat` → `0::` cgroup → `stat` memberships, and reads
only selected mapped groups plus ancestors under explicit limits. Per-cgroup
exact PSI is a verdict about that scope only. CPU, memory, and I/O controller
deltas plus path-derived systemd candidates are qualified scoped context, never
cross-cgroup causal proof. When a scoped memory finding is already pressure,
selected `memory.stat` page deltas may label it reclaim, swap, or possible
thrashing; they do not create that verdict. Possible-thrashing uses the host
conjunction at cgroup scope with medium mechanism confidence. A positive
`cpu.stat` `throttled_usec` delta may likewise label already-pressured scoped
CPU as quota-throttle. Capabilities consistently report partial cgroup
collection when limits, permissions, lifecycle changes, or controller files
make that context incomplete.

M5 adds `record`, `replay`, and `redact`. Recordings store normalized
observations under `kind` `stallhunt.recording` schema version 1 so replay can
re-run current inference. Legacy `bottleneck.recording` files are accepted on
replay. They are not hunt JSON and have no pre-1.0
compatibility promise. New files are created mode 0600. `--redact` replaces
process names, disk names, and cgroup path components while keeping counters
and process keys.

M6 adds `watch`. Rolling windows reuse the previous endpoint snapshot. The
command tracks host CPU/memory/I/O and a bounded set of cgroup pressure
findings as new, persistent, or resolved. Scoped cgroup `kind` values name the
resource and any reclaim, swap, possible-thrashing, or quota-throttle label.
On a terminal, watch opens an interactive TUI by default (M9); `--plain`
restores the classic clear-screen refresh. Piped text and JSON emit one
compact `stallhunt.watch_window` object per window and are byte-compatible
with the pre-TUI behavior. Watch is not a recording. On an unlimited watch,
the first SIGINT drains and writes the in-flight window; a second SIGINT
terminates immediately. Full evidence remains on `hunt --json` and `record`.

M8 adds a conservative evidence chain: when memory reclaim, swap, or possible
thrashing coexists with I/O pressure, hunt text and JSON may report that the
memory finding is consistent with the I/O finding. The same relation may also
join same-cgroup memory and I/O pressure when that cgroup's `memory.events`
show a high or max delta or `memory.stat` shows direct reclaim or swap-in.
Coincident PSI without that independent mechanism is not a chain. The relation
is not a causal claim, does not join host findings to cgroup findings, and is
not tracked by watch.

M9 is the interface redesign (ADR-0013): `hunt`/`replay` default to the
compact form above with `--explain` for the full long form (JSON unchanged);
color is automatic on terminals and disabled by `--no-color` or `NO_COLOR`;
`watch` opens the interactive TUI on a terminal, with `--plain` as the escape
hatch. The redesign is implemented and pending local user feedback; no pull
request has been opened yet.
