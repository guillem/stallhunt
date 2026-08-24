# Testing strategy

## Principle

Performance diagnosis logic must be testable without manufacturing real host contention during every test run.

The project therefore needs a strong fixture/replay model from the beginning.

## Test layers

### 1. Parser unit tests

Every kernel text parser requires fixtures.

Examples:

- PSI,
- `/proc/stat`,
- `/proc/loadavg`,
- `/proc/<pid>/stat`,
- `/proc/<pid>/schedstat`,
- `/proc/<pid>/io`,
- `/proc/meminfo`,
- `/proc/vmstat`,
- `/proc/diskstats`.

Include:

- normal examples,
- edge values,
- missing optional fields,
- malformed input,
- unusual process names,
- large counters.

For `/proc/<pid>/stat`, explicitly test process names containing spaces and parentheses.

### 2. Delta/normalization tests

Test:

- normal counter increase,
- zero-length/invalid interval rejection,
- process appears mid-window,
- process exits mid-window,
- PID reuse,
- missing second observation,
- counter reset/wrap policy,
- CPU count changes if supported,
- integer-to-duration conversions.

### 3. Analyzer unit tests

Every rule should have:

- positive case,
- negative case,
- boundary case,
- missing-data case,
- contradictory-evidence case.

Example CPU tests:

#### CPU saturated and tasks delayed

Expected:
- CPU contention finding,
- high severity,
- victims identified,
- consumers ranked.

#### CPU utilization high but PSI near zero

Expected:
- no material CPU contention finding.

#### CPU PSI high but per-process scheduler data unavailable

Expected:
- resource finding remains,
- victim attribution omitted or weakened,
- qualifier added,
- confidence adjusted.

#### CPU PSI high with several equal consumers

Expected:
- contention high confidence,
- suspect attribution lower confidence.

### 4. Golden CLI tests

Given a fixed normalized fixture, assert stable semantic output.

Avoid brittle tests for every whitespace character unless formatting is intentionally contractual.

JSON output can be validated structurally.

M1.6 adds a checked-in concise CPU renderer text fixture driven by a fixed
in-memory observation. It verifies the finding-first layout, bounded ranked
roles, same-window/non-causal language, context/limitation wording, timing,
and terminal-safe process names. Renderer tests also assert JSON finding shape structurally, without
comparing host-collected or wall-clock-dependent output.

ADR-0013 adds a compact-report golden layer alongside the legacy one, all
still driven by fixed in-memory observations and asserted with
`include_str!` against fixtures under `tests/fixtures/render/`:

- `hunt-compact-plain.txt` — the compact TTY layout at width 80 with color
  disabled (`ColorMode::Never`),
- `hunt-compact-color.txt` — the same render with `ColorMode::Always`,
  compared against an escaped representation (raw `\x1b` bytes replaced
  with the literal text `<ESC>`) rather than checked in as raw escape
  bytes, which are invisible in diffs and easily mangled by editors,
- `hunt-compact-verbose.txt` — the compact layout with `verbose: true`,
  restoring full qualifier text,
- `hunt-compact-full.txt` — the compact rendering of the same fixed
  multi-section (CPU + memory + I/O + cgroup) observation used by
  `hunt-legacy-full.txt`, so the two are a direct byte-count comparison of
  the same diagnosis; a test asserts the compact rendering is shorter.

Renderers take an explicit `style::ReportLayout { width, color, verbose }`
rather than probing the terminal, so these tests pin deterministic values
and never depend on the process's actual TTY state — consistent with the
existing rule that tests must not depend on wall-clock time, host CPU
count, or current load.

A separate test (`report::tests::every_real_qualifier_kind_maps_to_a_known_tag`)
re-derives the complete set of `Qualifier.kind` strings straight from
`src/analysis.rs`'s source at test time and asserts every one maps to a
known caveat category in `report::qualifier_tag`, so a newly added
qualifier kind that falls through to the `"other"` bucket fails the test
instead of silently losing its caveat category.

### 4a. Watch TUI tests

ADR-0013's watch terminal UI (`src/tui/{mod,app,draw}.rs`) is tested at two
levels, neither of which opens a real terminal or depends on TTY state:

- **App interaction tests** (`tui::app::tests`) call `App::handle_key`
  directly with hand-built `crossterm::event::KeyEvent`s and assert on the
  resulting state — selection clamping (including on an empty lifecycle,
  and re-clamping when a window shrinks the lifecycle), the
  expanded/help toggles, quit, and that `Ctrl-C` only increments the
  shared interrupt counter rather than exiting directly (the event loop in
  `tui::run`, not `App`, decides what an interrupt count means).
- **Draw tests** (`tui::draw::tests`) render `draw::draw` into a
  `ratatui::backend::TestBackend` and assert on the resulting buffer's
  text content: the lifecycle/current-window/history panels render
  without panicking on an empty lifecycle, the detail pane stays
  collapsed by default and shows full qualifier text once expanded, and
  the help overlay lists its keys. `App` fixtures come from
  `watch::test_support` (`sample_window`,
  `window_with_lifecycle_len`) — the same fixture-builder module
  `watch`'s own tests use, promoted out of its inner `#[cfg(test)] mod
  tests` so other test modules can reuse it instead of re-deriving
  fixture construction. Because `TestBackend` renders into a fixed-width
  buffer, assertions on wrapped qualifier text check for substrings from
  each end of a sentence rather than one contiguous string that could
  straddle a word-wrap line boundary.

The terminal lifecycle itself (raw mode, alternate screen, two-stage
Ctrl-C/SIGINT handling, and that the terminal is restored on every exit
path) was verified manually against the real binary under a pty — driving
actual keypresses and inspecting the raw escape sequences and process exit
codes — rather than in the automated suite, since it requires a real
terminal device the test harness does not provide.

### 5. Host integration tests

Run against real procfs/sysfs where safe.

These tests should primarily verify:

- files can be discovered,
- parsers work on current host,
- races do not crash the tool.

Do not assert that the host is currently bottlenecked.

M2 adds deterministic parser, interval, analyzer, renderer, and executable
healthy-host coverage for memory PSI, meminfo, and vmstat. The analyzer matrix
covers no pressure despite high occupancy/allocated swap, each provisional PSI
boundary, generic pressure with missing context, direct-reclaim and swap-in
conjunctions, full-as-subset validation, possible thrashing, short windows, and
contradictory background-reclaim/swap-out context. The possible-thrashing tests
also reject immaterial churn and verify that page rates use the independent
vmstat interval rather than the PSI interval. A live healthy smoke only
checks structural capability/degradation behavior. The ignored delegated-cgroup
acceptance then produced a PSI-backed `memory_swap_pressure` finding from
21–24% exact host PSI `some` without unconstrained host-wide allocation.

M3 adds deterministic diskstats/process-I/O/PSI parser and interval coverage,
normalized I/O fixtures for healthy high activity, pressure ranking, low
boundary, missing context, and short windows, plus renderer/executable healthy
smoke coverage. Its ignored rootless acceptance test also ran a bounded
competing-I/O scenario: exactly two owned `stress-ng` HDD workers on a
checkout-local temporary path, with direct/sync/fsync behavior and an
eight-second coordinator bound. The test asserts a PSI-backed I/O-pressure
finding while preserving the lack of victim, process-device, and causal claims.

M4 has deterministic cgroup-v2 coverage for mountinfo and `0::` membership
parsing, normalized-path validation, ancestor selection, controller/missing-file
degradation, process movement and PID reuse across interval membership, scoped
PSI rules, path-derived systemd candidates, capability completeness, endpoint
budget-cost merging, controller rendering, and host-versus-cgroup scope
separation. Limits, permission-denial issues, and partial snapshots must remain
explicit regression cases. No test may encode cgroup membership or controller
activity as causal proof.

Any live cgroup test must be ignored by default, use only a uniquely owned
delegated/readable subtree, enforce cleanup and timeouts, and skip rather than
mutate an arbitrary host hierarchy when delegation is absent.

`tests/cgroup_acceptance.rs` follows this policy: it is opt-in and requires a
caller-provided `STALLHUNT_CGROUP_ACCEPTANCE_PATH` already containing the test
process. It observes that scope without mutating the hierarchy.

M5 recording tests cover encode/decode round-trip of a multi-resource
observation, identifier redaction that preserves resource verdicts, rejection
of unknown schema versions, and rejection of hunt JSON. Executable CLI tests
cover `record`/`replay`/`redact` on a live 100 ms observation, 0600 file mode,
overwrite refusal, and invalid invocations.

M6 watch tests cover finding lifecycle (new, persistent, resolved, severity
change, unconfirmed missing data), independent host/cgroup identities, bounded
history, cgroup tracking caps, and a checked-in lifecycle text fixture plus
structural JSON assertions. Candidate tests cover CPU victim/suspect and I/O
suspect conversion, confirmed-window refresh, stale retention for unconfirmed
and resolved findings, and empty supported/unsupported roles. Renderer tests
cover piped text, JSON, and the TUI's normal and expanded candidate evidence,
including empty states and terminal-safe truncation. Executable CLI tests cover `watch --count 1` text
and JSON on a 100 ms window, plus prompt second-SIGINT termination during an
unlimited five-minute window. Live watch does not assert host contention.

The v0.4 scoped-role matrix also covers direct and descendant membership,
component-boundary rejection, independent host/cgroup ranking, five-candidate
limits and stable keys, and membership-cap partial completeness. Cgroup watch
signals obtain their exact two matching role lists from the selected
path-plus-resource scope so stale lifecycle retention cannot cross resources.
Presentation tests cover host/cgroup role rendering, exact scoped lifecycle
matching, responsive 120×30 and 160×45 grids, compact 119×29/80×24 fallback,
detail preference across resize, layout-derived Unicode-aware scrolling, and
terminal-safe identifiers. Unit tests exercise the one-shot terminal
restoration guard on explicit cleanup and panic unwinding. A real PTY
raw-mode/alternate-screen restoration check remains a controlled-host release
gate because it is not deterministic in the ordinary test runner.

M8 evidence-chain tests cover a host memory mechanism plus I/O pressure
positive path (reclaim, swap, possible thrashing), a same-cgroup memory plus
I/O pressure path gated by `memory.events` high/max or `memory.stat`
direct-reclaim/swap-in, coincident PSI without a mechanism, scan-without-steal,
cross-scope and CPU–I/O negatives, 16-chain rank-then-truncate behavior from 18
eligible candidates, checked-in related-evidence text fixtures, and structural
hunt JSON. Chains are not causal claims and are not watch identities.

Scoped cgroup memory findings may be labeled reclaim, swap, or possible
thrashing from `memory.stat` page deltas. Tests cover reclaim, swap-wins,
possible-thrashing (including short window, missing/invalid `full`, slower
observation-interval rates, and moderate `some`), unlabeled pressure (including
`memory.events` high without page deltas), scan-without-steal, and page
counters that must not create a pressure verdict. Scoped CPU findings may be
labeled quota-throttle from `cpu.stat` `throttled_usec`. Tests cover a positive
throttle label, `nr_throttled` without time, and throttle counters that must not
create a pressure verdict. Watch still keys off `Pressure` and does not gain a
new identity. Watch lifecycle `kind` strings name the scoped resource and any
reclaim, swap, possible-thrashing, or quota-throttle label; a mechanism change
stays `persistent`.

Mark environment-dependent tests clearly.

`tests/documentation.rs` scans every Git-tracked Markdown file and the manual
page for concrete `stallhunt`, Cargo, and repository-tool invocations. It
normalizes prompts, release-binary paths, roff escaping, and output redirection,
then validates Stallhunt argv through the CLI's safe `--help` parse path and
checks documented Cargo/repository subcommands through their help paths;
failures include source path and line. Synopsis and placeholder forms are
maintained in a separate explicit inventory. Historical schema prose such as
`bottleneck.recording` is not executable syntax, but a concrete `bottleneck
...` command is rejected.

The current normal deterministic gate contains 196 unit tests, 15 CLI tests,
three documentation-command tests, and three replay-fixture tests. Five Linux
acceptance tests are ignored by default and run only when intentionally
requested.

### 6. Synthetic load scenarios

Create opt-in tests/scripts that deliberately create known contention.

Examples:

#### CPU

- start N+M busy loops on N CPUs,
- run a victim workload,
- verify CPU pressure finding appears.

#### Memory

`tests/memory_acceptance.rs` is deliberately ignored and requires
`STALLHUNT_MEMORY_ACCEPTANCE_PATH` to name an absolute filesystem path to a
uniquely owned, writable delegated cgroup-v2 parent. The test requires its
`memory` controller to already be enabled for children. It creates one
generated child only, applies bounded `memory.max` and `memory.high` limits,
moves an owned allocator into that child before it allocates, and removes the
child after RAII cleanup, which now drains remaining tasks in that uniquely
named child before `rmdir`. It never changes the caller-provided parent's limits
or membership, and skips when the delegation, memory PSI, or `stress-ng` VM
options are unavailable. EXP-0006 recorded a passing delegated-cgroup run.

```bash
STALLHUNT_MEMORY_ACCEPTANCE_PATH=/absolute/cgroup/path \
  cargo test --locked --offline --test memory_acceptance -- --ignored --nocapture
```

The test requires an exact host-memory-PSI `some` interval of at least 1% and
a PSI-backed harmful-memory finding. The finding may be generic, reclaim,
swap, or possible-thrashing according to independently collected context.
`full`, meminfo, and vmstat remain context-only; the acceptance does not
require or infer a process or cgroup-causality conclusion.

#### I/O

Completed M3 acceptance coverage uses a checkout-local temporary path and owned,
bounded workers. Follow-up I/O tests must preserve that non-destructive model and
must not turn same-window candidates into causal/device-mapping assertions.

Synthetic tests must be safe and bounded.

Never assume destructive access to production disks.

The CPU-pressure acceptance test is deliberately ignored and opt-in:

```bash
cargo test --test cpu_acceptance -- --ignored
```

Both cases run only on Linux with readable CPU PSI. The clean sleeping-thread
and oversubscribed busy-worker scenarios each use a timeout around the one-second
JSON hunt; the latter additionally skips hosts with more than eight available
logical CPUs before starting one more owned busy-loop worker than available
CPUs. Host-mutating workloads are
serialized, and owned children have RAII cleanup even on assertion failure.
Skipping due to unsupported conditions or resource-launch limits is expected;
this is rootless acceptance coverage, not a default CI workload.

### 7. Overhead benchmarks

Measure observer effect.

Scenarios:

- idle host,
- moderate process count,
- high process count,
- process churn,
- stressed CPU.

Track:

- tool CPU consumption,
- allocations/memory,
- bytes read from procfs,
- observation latency/skew.

Use `tools/measure-overhead.sh` only with a pre-built binary, preferably a
release binary. It measures baseline, one bounded sleeper/process scenario,
process churn, and CPU stress separately; `stress-ng` is used only when already
installed and is never installed by the harness. Opt-in `many_pids` and
`many_tasks` (or `high`) add bounded extra PIDs/threads; they are not part of
`all`, so constrained sandboxes do not fork hundreds of helpers. `many_pids`
spawns from Python so a failed fork stops the batch. Results are recorded as
ranges, not CI pass/fail timing gates. In constrained sandboxes, helper-heavy
runs may hit fork limits; use the smallest safe process/churn setup and isolate
the optional CPU or high-PID scenarios instead of treating that limit as a
product result.

## Fixture architecture

Recommended directory:

```text
tests/
  cpu_acceptance.rs       # ignored rootless synthetic CPU-pressure coverage
  fixtures/
    cpu/
      healthy.json
      saturated.json
      saturated_no_schedstat.json
      busy_but_not_pressured.json
    render/
      cpu-contention.txt
      watch-lifecycle.txt
    proc-loadavg-valid
    proc-pid-stat-unusual-name
    proc-pressure-cpu-valid
    proc-schedstat-valid
    proc-stat-valid
```

A normalized observation fixture should include a schema version.

Do not only store final findings; store input observations so inference remains testable.

## Reproducibility

Tests must not depend on:

- wall-clock time,
- host CPU count unless integration-tagged,
- local process names,
- current load,
- root privileges.

Inject time/capabilities where necessary.

## Property tests

Property-based tests are valuable for parsers and arithmetic once basic fixtures exist.

Candidates:

- parsers never panic on arbitrary bytes/text,
- delta calculations never produce negative durations from valid monotonic counters,
- severity ordering is monotonic with increasing pressure under fixed context,
- missing evidence never increases confidence accidentally.

Add a property-testing dependency only when there are enough meaningful properties to justify it.

## Fuzzing

Future fuzz targets:

- procfs parsers,
- recording decoder,
- terminal sanitization.

Parser robustness is security-relevant.

## Performance regression policy

Once stable benchmarks exist, record baseline ranges rather than exact timings.

Avoid flaky CI gates based on microbenchmark noise.

## Definition of validated diagnosis

A new finding type should not be considered trustworthy until:

1. parser fixtures exist,
2. normalized fixtures exist,
3. positive/negative analyzer tests exist,
4. at least one synthetic real-host experiment behaves as expected,
5. documented limitations match observed behavior.

M2 has satisfied deterministic, healthy-host smoke, and controlled
harmful-pressure layers. The live run validated a swap-pressure label from
same-window `pswpin`; reclaim-only and possible-thrashing remain
fixture-covered.

# CPU analyzer fixtures

Normalized CPU analyzer tests must be host-independent. The four JSON fixtures
under `tests/fixtures/cpu/` cover a healthy negative case, saturated contention,
saturated contention without schedstat attribution, and busy-but-not-pressured
contradictory context. They describe normalized PSI, window, CPU context,
process CPU, stable scheduler delay, and scheduler capability where relevant.

Missing-data, partial-context, threshold-boundary, and top-N ranking cases are
also required, but are currently expressed as programmatic analyzer tests rather
than serialized fixtures. Do not imply that every rule condition has a JSON
fixture merely because fixture-driven tests exist.
