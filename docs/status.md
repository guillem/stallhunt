# Project status

Last updated: 2026-08-23

## Current milestone

**Post-Milestone 8 — interface redesign release v0.2.0**

Milestones 1–6 remain functionally complete. Since the v0.1.0 productization,
v0.1.1 landed the `BOTTLENECK_*` → `STALLHUNT_*` acceptance-variable rename
(closing that ADR-0012 open decision), regression tests intended to cover four
documented gaps (16-chain truncation order, schema-1 decode without
`memory_stat`, host-memory watch kind transitions, invalid host `full` blocking
possible-thrashing), and a graceful first-SIGINT drain for unlimited watch. The
release workflow's Node-20-deprecated actions were bumped to
`actions/upload-artifact@v7` and `softprops/action-gh-release@v3`. The
v0.1.2 corrective release makes the advertised second-SIGINT termination real
and ensures the 16-chain regression actually reaches truncation with 18
eligible candidates. Release v0.2.0 ships the ADR-0013 interface redesign in
response to user feedback that default `hunt` output was a wall of text and
`watch` was too primitive: `hunt`/`replay` gain a compact styled report and
`--verbose`, and `watch` gains an interactive TUI, both TTY-only and both
leaving piped text/JSON unchanged. This is presentation only; no analyzer,
finding kind, or telemetry source changed, and the repository remains parked
otherwise: no additional M8 chain or M7 probe is approved.
Do not start M7 merely because eBPF is interesting; add a probe only for
a concrete diagnostic gap. M5 recording and replay remain available for offline
re-analysis. M4 remains implemented with opt-in live observational validation;
that test still requires a caller-owned delegated subtree that already contains
the test process and does not mutate the hierarchy.

## Verified milestone assessment

- **M0 complete:** repository bootstrap, durable documentation, ADRs, and status
  tracking exist in Git.
- **M1 complete:** the CPU collector, scheduler-delay attribution, conservative
  inference, renderers, deterministic tests, bounded rootless acceptance tests,
  and overhead experiments satisfy the documented exit condition.
- **M2 complete within its exit condition:** host-wide collection, inference,
  rendering, deterministic fixtures, a healthy-host smoke, and a delegated-
  cgroup harmful-pressure acceptance are recorded. The live run produced
  high-severity `memory_swap_pressure` from exact host PSI `some`. Reclaim-only
  and possible-thrashing labels remain fixture-validated; there is still no
  process attribution.
- **M3 complete within its deliberately limited exit condition:** PSI-backed
  block-I/O pressure and same-window activity candidates were validated by the
  recorded controlled run. Victim attribution, process-device mapping, and
  causality remain explicitly unsupported.
- **M4 implemented:** bounded cgroup-v2 collection, scoped analysis,
  completeness semantics, controller context, and deterministic coverage are
  complete. Live delegated-scope validation is available opt-in and cannot be
  assumed on an arbitrary host.
- **M5 complete within its exit condition:** versioned normalized-observation
  recordings, `record`/`replay`/`redact`, identifier redaction, 0600 file
  creation, and deterministic re-analysis are implemented. Pre-1.0 recordings
  have no compatibility promise (ADR-0007). There is still no multi-window
  recording.
- **M6 complete within its exit condition:** `watch` classifies host and
  bounded cgroup pressure findings as new, persistent, or resolved across
  contiguous rolling windows, appends piped text/JSON unchanged, keeps 16
  history windows, and does not store full evidence in its JSON stream. Per
  ADR-0013, a TTY renders an interactive TUI over that same lifecycle model
  (not a utilization dashboard) instead of the earlier screen-clearing text.
  A second SIGINT while draining terminates immediately with the conventional
  exit status on both the piped and TUI paths; `--count` bounds scripted runs.
- **M8 host and same-cgroup slices complete:** hunt/replay can relate a memory
  reclaim, swap, or possible-thrashing finding to host I/O pressure, and can
  relate same-cgroup memory plus I/O pressure when `memory.events` high/max or
  `memory.stat` direct-reclaim/swap-in increased, as `consistent_with`.
  Coincident PSI without that independent mechanism does not create a chain.
  Confidence is never high. Host findings are not linked to cgroup findings.
  Watch does not track chain identities.
- **M7 not started; remaining M8 chains not started:** no eBPF probe exists,
  and no CPU–I/O, host–cgroup, or process-device chain exists.

## Implemented

- A single stable-Rust package builds the `stallhunt` binary (MSRV 1.85).
- The package forbids unsafe Rust.
- Real `hunt`, `watch`, `record`, `replay`, `redact`, `capabilities`, help, and
  version command structure exists.
- `hunt` accepts `--duration` values from 100 ms through 5 minutes, including
  exact-millisecond decimal values, and defaults to 10 seconds.
- `hunt` and `capabilities` support separate text and JSON render paths.
- CPU PSI `some` parsing retains rolling averages and the raw cumulative
  microsecond total. The parser validates required fields and ranges, tolerates
  unknown future fields, rejects duplicates/malformed input, and treats CPU
  `full` as compatibility data rather than evidence.
- `hunt` now performs a bounded CPU PSI two-snapshot observation and derives
  exact-interval pressure from `some.total` delta divided by measured monotonic
  elapsed microseconds. Counter regression, an unmeasurable interval, and a
  delta exceeding elapsed time are rejected rather than clamped.
- `capabilities` probes CPU PSI and distinguishes available, unsupported,
  permission-denied, and failed states. A valid CPU PSI interval still produces
  a CPU resource verdict if host/process context is incomplete; attribution is
  omitted and qualified. Invalid or unavailable CPU PSI produces no assessment.
- Text and JSON output include typed CPU PSI interval evidence, rolling
  averages, and evidence-backed CPU findings or an explicit insufficient-data
  result.
- `hunt` also collects `/proc/stat`, `/proc/loadavg`, and bounded two-snapshot
  `/proc/<pid>/stat` process data over the same observation window. It reports
  host CPU counter deltas, logical CPU count, load context, and CPU deltas for
  process identities that match on both PID and start-time ticks.
- PSI and CPU/process pairs each use their own completed-snapshot monotonic
  interval. `loadavg` is best-effort context and is explicitly optional rather
  than invalidating CPU evidence.
- `/proc/stat`, `/proc/loadavg`, and process-stat parsers reject malformed
  required fields. Process-stat parsing handles spaces and `)` in `comm`; text
  output sanitizes control characters and bounds names to 80 characters.
- Host CPU accounting does not double-count guest counters. It preserves
  iowait separately and falls back to non-iowait aggregate deltas when iowait
  decreases, as Linux permits.
- Process enumeration is sorted and capped at 4,096 PIDs per snapshot.
  Disappearing, permission-denied, unreadable, malformed, directory-iteration,
  cap-limited, and inconsistent process-counter observations are retained as
  typed JSON collection context.
  Hitting the cap makes process context incomplete; a failed global process
  enumeration preserves host CPU evidence but marks process context failed.
- `rustix` 1.x with only its `param` feature obtains `USER_HZ` safely for
  process CPU fractions; raw ticks remain in the observation and JSON output.
- `serde` and `serde_json` safely serialize dynamic structured output.
- M1.4 probes per-task scheduler accounting directly; the unrelated
  `kernel.sched_schedstats` switch is not used as a capability gate. It retains
  stable `(tid,starttime)` task counters, sums checked runnable-delay
  deltas to stable process identities, and caps task samples at 16,384 per
  endpoint after the existing PID cap. Direct task schedstat reads determine
  availability; task churn, TID reuse, permissions, malformed data, and caps are
  explicit JSON context. Candidate delay is raw summed-thread evidence.
- M1.5 analyzes normalized CPU evidence without reading procfs: exact-interval
  CPU PSI alone establishes the resource verdict. The effective diagnostic and
  resource-confidence window is the shorter of requested and measured PSI
  duration; a requested duration below one second remains smoke mode. Otherwise
  the effective window must be at least one second. Provisional `<1%`,
  `1/5/15/30%` boundaries produce an explicit no-meaningful-contention finding
  or low, moderate, high, and severe contention. Stable scheduler-delay
  candidates and same-window CPU consumers are separately ranked, qualified
  victims and suspects; neither role proves causality.
- Invalid CLI invocations write to stderr and exit with status 2.
- Unit tests cover command parsing, PSI parsing/fixtures, boundary and invalid
  interval normalization, pure CPU analyzer positive/negative/boundary,
  missing-data, and contradictory-evidence cases, plus renderer semantics.
- Normalized JSON fixtures cover healthy, saturated, busy-but-not-pressured,
  and scheduler-accounting-unavailable CPU analysis inputs.
- Executable integration tests cover real host CPU PSI hunt/capability behavior
  and invalid invocation.
- M1.6 makes default text output concise and finding-first. A fixed normalized
  observation drives checked-in golden text coverage, and structural tests cover
  JSON output. JSON intentionally remains the full structured-evidence surface:
  complete observation, evidence, ranked roles, capabilities, and collection
  qualifiers are retained even when text omits raw detail.
- The opt-in `tests/cpu_acceptance.rs` rootless acceptance test creates bounded
  oversubscription only on Linux with readable CPU PSI and at most eight logical
  CPUs. It owns busy workers with RAII cleanup and bounds the hunt with a timeout.
- `tools/measure-overhead.sh` is an opt-in, scenario-specific release-binary
  harness for baseline, process, churn, CPU-stress, many_pids, and many_tasks
  measurements. `all` keeps the small helper set. `many_pids` uses a Python
  sleeper helper. It may use an already-installed `stress-ng`, never installs
  it, and has no CI timing gate. EXP-0007 records workstation-scale results.
- M2 reads bounded host `/proc/pressure/memory`, `/proc/meminfo`, and selected
  `/proc/vmstat` snapshots around the existing one requested sleep. Each
  resource pair uses its own completed monotonic interval because collection is
  sequential.
- Memory PSI `some` is the sole memory resource-verdict signal. Valid `full` is
  retained only as a separately-qualified non-additive subset; a missing or
  interval-invalid `full` cannot invalidate valid `some`. Meminfo occupancy/swap allocation and
  vmstat counters only classify or qualify a PSI verdict.
- M2 produces typed host-memory findings for no harmful pressure, generic active
  pressure, reclaim pressure, swap pressure, possible thrashing, and insufficient
  observation. The slice has no process walk or process attribution; all memory
  evidence is explicitly host-wide.
- Deterministic memory parser/normalization/analyzer/renderer fixtures cover
  positive, negative, boundary, missing, and contradictory cases. A live healthy
  memory smoke passed, including graceful capability behavior. The ignored
  delegated-cgroup acceptance then produced `memory_swap_pressure` from 21–24%
  exact host PSI `some` (EXP-0006); RAII now drains the uniquely named child
  before removing it.
- M3 reads bounded host I/O PSI, `/proc/diskstats`, and `/proc/<pid>/io` around
  the same requested sleep. Each resource pair retains its own monotonic interval
  because collection is sequential. Diskstats is capped at 4,096 devices; process
  I/O is capped at 1,024 PIDs and uses stat-io-stat identity validation, at most
  3,072 reads per endpoint. Diskstats input is capped at 1 MiB.
- Exact I/O PSI `some` is the sole I/O resource-verdict signal. Valid `full` is
  retained as a non-additive subset. Diskstats preserves raw 512-byte sector
  units, end `in_flight` gauge, independent counter resets, and distinct busy /
  weighted-time semantics. Process `read_bytes`, charged `write_bytes`, and
  `cancelled_write_bytes` remain distinct from logical `rchar`/`wchar` context.
  Process-I/O attribution is explicitly unsupported on 32-bit targets because
  the kernel documents possible torn 64-bit counter reads.
- M3 ranks positive disk and process I/O-accounting activity only during PSI
  pressure. Candidates are same-window context, not victims, process-device
  mappings, or causal claims. High activity with low PSI is explicitly healthy.
- Deterministic I/O parser/normalization/analyzer/renderer fixtures and a live
  healthy smoke passed. The ignored rootless M3 acceptance also ran without
  skipping on Linux 7.1.5: two owned `stress-ng` HDD workers (64 MiB each,
  direct/sync/fsync, checkout-local temporary path) remained alive through a
  two-second hunt and cleanup passed. It found `io_pressure` with PSI `some`
  13.6029889%, three device candidates, and two process-I/O candidates.
- M4 discovers a cgroup2 mount from `/proc/self/mountinfo`, parses unified
  `0::` membership, and uses stat-cgroup-stat identity validation. It selects
  the lowest 256 visible PIDs per endpoint and reads only mapped cgroups plus
  ancestors, capped at 512 groups, depth 64, 4,096 path bytes, 64 KiB per file,
  8 MiB per snapshot, and 4,096 attempted reads. These implementation limits
  are more conservative than the 1,024-PID/2,048-group ADR ceilings.
- M4 collects cgroup CPU, memory, I/O, PSI, and selected `memory.stat` files
  best-effort; normalizes
  stable paths and stable memberships; treats exact per-cgroup PSI `some` as a
  verdict about that scope only; retains `full` as non-additive context; and
  emits inferred final-component `.service`, `.scope`, or `.slice` labels.
- M4 findings explicitly qualify overlapping ancestor/child scopes, unstable
  cgroup path lifetime, membership churn, partial collection, and the absence
  of cross-cgroup or host causality. Cgroup observations and findings are
  included in text and JSON output.
- M5 records normalized hunt observations, not findings. `record --output PATH`
  captures the same bounded observation as `hunt`, writes schema `kind`
  `stallhunt.recording` version 1, and creates new files with mode 0600.
  Legacy `bottleneck.recording` files are accepted on replay. `replay`
  reconstructs the observation and re-runs current inference into the
  existing text/JSON renderers. `redact` and `record --redact` replace process
  names, disk names, cgroup path components, and inferred unit candidates while
  keeping counters, process keys, and path hierarchy. Hunt JSON is not a
  recording. Unknown kind or schema versions are rejected. Decode is bounded at
  32 MiB. Existing paths are not overwritten unless `--force` is passed.
- M6 `watch` reuses hunt collectors on contiguous rolling windows. `--interval`
  defaults to 2 s and uses the hunt duration range; `--count` stops after N
  windows. Host CPU, memory, and I/O pressure plus at most 16 cgroup pressure
  identities are classified as new, persistent, or resolved. Healthy results do
  not create findings; missing or short-window data does not resolve an active
  finding. History is capped at 16 compact windows. A TTY renders an
  interactive TUI (ADR-0013); piped text appends `--- window N ---` frames
  and JSON emits one `stallhunt.watch_window` object per window, both
  unchanged by the TUI's existence. Watch JSON is not hunt JSON and not a
  recording. Scoped cgroup lifecycle `kind` values name the resource and any
  reclaim, swap, possible-thrashing, or quota-throttle label; identity
  remains path plus resource.
- Per ADR-0013, `hunt`/`replay` render a compact, color-coded, width-aware
  report (`src/report.rs`) on a TTY instead of the stacked plain-text
  sections; piped output is byte-for-byte unchanged. The 61 per-finding
  qualifier messages collapse by default to a tag summary; `--verbose`
  restores the full text on hunt/replay, and the watch TUI's detail pane
  shows it per finding with no flag. `--no-color` and `NO_COLOR` disable
  color without changing layout on hunt, replay, and watch. `ratatui` 0.29
  and `crossterm` 0.28 are new dependencies, justified in ADR-0013.
- M8 relates a memory reclaim, swap, or possible-thrashing finding to host I/O
  pressure as `consistent_with` when both exist. It also relates same-cgroup
  memory and I/O pressure when that path has a positive `memory.events` high or
  max delta, or positive `memory.stat` direct-reclaim (`pgscan_direct` and
  `pgsteal_direct`) or swap-in (`pswpin`) deltas. Hunt text appends a related-
  evidence section; hunt JSON adds `evidence_chains`. Coincidence without the
  independent mechanism is not a chain, host findings are not linked to cgroup
  findings, and the relation is never a causal claim.
- Scoped memory pressure findings may be labeled reclaim, swap, or possible
  thrashing from already collected `memory.stat` page deltas (`pswpin`,
  `pswpout`, or `pgscan_direct` plus `pgsteal_direct`). PSI still creates the
  verdict; `CgroupAssessmentKind` remains `Pressure`. Reclaim and swap
  mechanism confidence is low. Possible-thrashing uses the host conjunction
  (high or severe `some`, at least 1% valid `full`, a 5s PSI window, and
  material bidirectional swap plus direct-reclaim rates over the cgroup
  observation interval) and has medium mechanism confidence. `memory.events`
  high/max do not label the finding. Scan without steal does not produce a
  reclaim label. Page counters without PSI do not create pressure. Watch still
  keys off `Pressure`.
- Scoped CPU pressure findings may be labeled quota-throttle from an already
  collected `cpu.stat` `throttled_usec` delta. PSI still creates the verdict;
  `CgroupAssessmentKind` remains `Pressure`. Mechanism confidence is low.
  `nr_throttled` without throttled time does not label. Throttle counters
  without PSI do not create pressure. Watch still keys off `Pressure`.
- Cargo formatting, Clippy, and test quality gates are documented.

## Known limitations

- CPU PSI is host-wide evidence. M1.5 provides provisional severity and
  qualified attribution, but process consumers remain same-window correlation,
  not proven causes.
- A hunt can be incomplete if CPU PSI becomes unreadable or invalid between
  snapshots; this is reported as an explicit capability/observation limit.
- The JSON shape is bootstrap scaffolding and has no pre-1.0 compatibility
  promise beyond its explicit `schema_version` field.
- Scheduler-delay candidates are observed stable-task evidence, not proof of
  user-visible harm. Tasks whose entire lifetime falls between snapshots are
  not observable.
- Scheduler identity validation can require three procfs file reads for each of
  up to 16,384 selected tasks per endpoint. EXP-0007 measured a workstation
  with 370 visible PIDs and ~1,587--2,099 stable tasks: about 6 MiB RSS and
  110--210 ms PSI-window skew on a one-second hunt. The 4,096-PID and 16,384-task
  caps were not reached.
- GitHub Actions runs locked tests on Rust 1.85 and formatting, Clippy, and
  locked tests on stable Rust. The five environment-dependent Linux acceptance
  tests remain opt-in rather than CI workloads.
- Tagged releases publish one `x86_64-unknown-linux-gnu` tarball and a SHA-256
  sidecar. The binary is built on GitHub's current Ubuntu runner; compatibility
  with older glibc userspaces is not yet defined by the Linux 4.20 kernel
  baseline.
- Product identity, license (MIT OR Apache-2.0), MSRV (1.85), Linux baseline
  (4.20+), and clap-based CLI are decided (ADR-0012, [`install.md`](install.md)).
- M2's live harmful-pressure run used a delegated 128/256 MiB child and an
  owned 192 MiB `stress-ng --vm` allocator. It produced 21–24% host memory PSI
  `some` and `memory_swap_pressure` over a ~2.15 s window. That swap label is
  same-window `pswpin` correlation with low mechanism confidence; host swap
  occupancy stayed unused afterward. Reclaim-only and possible-thrashing
  remain fixture-validated. `tests/memory_acceptance.rs` still requires
  `STALLHUNT_MEMORY_ACCEPTANCE_PATH` and skips when that delegated parent is
  absent.
- M3's controlled PSI/resource and same-window-candidate exit is validated,
  but it has not validated I/O victims, process-device mapping, or causality.
  EXP-0007 measured process-I/O collection at 129--194 intervals on that
  workstation, still below the 1,024-PID cap.
- The ignored cgroup acceptance test requires a caller-provided, uniquely owned
  delegated subtree. It safely skips when that prerequisite is absent, so an
  arbitrary host does not yet provide controlled per-cgroup pressure evidence.
- The cgroup collector adds a second independent procfs PID walk rather than
  reusing the existing CPU or process-I/O selection. EXP-0007 found that walk
  already at its 256-PID cap on a 370-PID host (94 groups, partial completeness).
  Extra high-numbered helper PIDs did not increase the selected cgroup set.
- M5 recordings are pre-1.0 and may become unreadable after a schema change.
  Identifier redaction is not cryptographic anonymization: PIDs, start times,
  major/minor keys, and path shape remain. Duration replay uses integer
  microseconds, which can differ slightly from a live nanosecond `Instant`
  interval. Recordings do not include extra host identity such as hostname or
  kernel version.
- Watch JSON omits victims, suspects, and raw evidence. A disappeared cgroup
  finding stays unconfirmed until that scope is observed without ranked
  pressure. Unlimited `watch` without `--count` samples until interrupted and
  drains the current window after the first SIGINT; a second SIGINT exits
  immediately. Consecutive 100 ms windows remain smoke observations, same as
  hunt.
- M8's chains are same-window correlation of independent PSI plus either host
  VM counters or same-cgroup `memory.events` high/max or `memory.stat`
  direct-reclaim/swap-in deltas. They do not prove reclaim or swap caused I/O
  stalls, do not map processes to devices, do not link host and cgroup
  findings, and are not a watch identity. Generic memory pressure coincident
  with I/O pressure remains two findings with no chain. Direct scan without
  steal is not a cgroup reclaim mechanism. Scoped possible-thrashing is the
  same provisional heuristic as the host label, using cgroup PSI `full` and
  `memory.stat` rates over the cgroup observation interval; default 2s watch
  windows are too short to receive it. `memory.events` high/max do not label a
  finding. Scoped CPU quota-throttle is same-window `cpu.stat` correlation, not
  proof that a quota caused scoped or host CPU stalls.
- M1's controlled positive-pressure and clean sleeping-thread scenarios passed,
  and busy-but-not-pressured behavior is deterministic fixture coverage. A
  controlled real-host workload that is busy while remaining below the
  contention threshold remains an open experiment in `docs/experiments.md`.
- CPU thresholds are provisional and event telemetry is still required for
  stronger causal attribution.

## Pending work

The repository is intentionally parked after the scoped possible-thrashing
slice. No additional M8 chain or M7 probe is approved.

Diagnostic and attribution gaps:

- host memory findings still have no process attribution;
- I/O findings still have no affected-workload attribution or process-to-device
  mapping;
- event-level scheduler, off-CPU, block-request, lock, and network evidence is
  absent because M7 has not started;
- CPU–I/O, host–cgroup, cross-cgroup, and process-device chains remain
  unsupported; coincident PSI is not evidence for any of them;
- watch does not track evidence chains, retain full evidence, or produce a
  multi-window recording.

Validation gaps:

- scoped reclaim, swap, possible-thrashing, and quota-throttle labels are
  deterministic-test validated but do not have a controlled live scoped-
  pressure acceptance result;
- the cgroup acceptance test is opt-in observational coverage and requires a
  caller-owned delegated subtree;
- host reclaim-only and possible-thrashing remain fixture-validated, while the
  live memory acceptance exercised swap pressure;
- a controlled live busy-but-not-pressured CPU workload remains unrecorded;
- severity thresholds are provisional rather than portable guarantees.

Operational and delivery gaps:

- cgroup collection reaches its 256-PID selection cap on the measured
  workstation, so scoped context is partial and can omit higher-PID groups;
- unlimited watch drains gracefully: the first SIGINT installs a flag so the
  in-flight window completes and is written before exit;
- `MANIFEST.txt` (tracked-file byte sizes) predates several source files,
  including ones added by the ADR-0013 redesign; it has no generator script
  and is not read by CI or the release workflow, so it was left as-is rather
  than hand-regenerated — decide whether to keep it, automate it, or remove
  it before it is trusted for anything;
- recordings are single-window, pre-1.0, and have no compatibility promise;
- the five Linux acceptance scenarios remain intentionally opt-in rather than
  automated CI jobs;
- release automation publishes only one dynamically linked x86_64 GNU/Linux
  artifact with a checksum; additional targets, an explicit glibc baseline,
  signatures, and provenance remain open.

## Known bugs

None recorded at this milestone boundary.

The watch top-16 false-resolution bug (a pressured cgroup below the ranking cap
was reported as `resolved`) was fixed in v0.1.0. Ranking omission now leaves
the finding persistent and unconfirmed; see
[`CHANGELOG.md`](../CHANGELOG.md).

## Current recommended next task
Write down one concrete diagnostic question and the independent evidence needed
to answer it before selecting another feature. No such question is currently
selected. Do not start Milestone 7 unless the question cannot be answered with
current `/proc`, PSI, and cgroup collectors. Do not add another M8 chain unless
independent linking evidence already exists; do not treat coincident PSI as a
path, and do not link host findings to cgroup findings.

## Current design risks

### R1: False causality

The project can lose credibility if it equates "largest consumer" with "cause".

Mitigation:
- separate resource diagnosis confidence from suspect confidence,
- retain evidence/qualifiers,
- relate findings only when independent mechanism evidence exists,
- introduce event telemetry only when needed.

### R2: Scope explosion

Linux exposes huge amounts of telemetry.

Mitigation:
- add telemetry only for concrete diagnostic questions,
- work in vertical slices.

### R3: Observer overhead

Naive per-process sampling can become expensive on large hosts.

Mitigation:
- measure early (EXP-0002 small-process, EXP-0007 workstation-scale),
- treat 1-second hunts as smoke when collection skew is tens to hundreds of milliseconds,
- optimize based on evidence,
- consider staged collection later if a host approaches the PID/task caps.

### R4: Kernel/configuration variability

Some useful fields depend on kernel configuration, permissions or version.

Mitigation:
- explicit capabilities,
- graceful degradation,
- fixtures from varied environments.

### R5: Premature eBPF complexity

eBPF could dominate the project before the inference model proves useful.

Mitigation:
- eBPF prohibited as MVP dependency by ADR-0003.

### R6: Pre-1.0 JSON evolution

Dynamic output is serialized with `serde_json`, but the shape remains pre-1.0
and can evolve as the normalized model grows.

Mitigation:
- keep `schema_version` explicit,
- do not promise pre-1.0 compatibility yet.

### R7: Cgroup bounded-selection blind spots

The deterministic lowest-256-PID cgroup selection is already capped on the
measured workstation. Relevant higher-PID cgroups can be omitted even though
the retained scoped findings are valid.

Mitigation:
- report the cgroup capability and hunt status as partial whenever a cap or
  collection issue is present;
- never interpret missing scoped findings as evidence that no omitted cgroup is
  pressured;
- consider staged or target-aware selection only after a quota-aware
  measurement demonstrates the need.

Workstation-scale collector cost is recorded in EXP-0007. Do not chase the
4,096-PID or 16,384-task caps without a quota-aware setup.

## Known open decisions

Not yet decided:

- serialization crate/versioning policy for dynamic JSON beyond pre-1.0 hunt output,
- eventual eBPF framework,
- compatibility policy, additional targets, and signing/provenance for
  pre-built release artifacts.

Decided in ADR-0012:

- product/binary name: `stallhunt`,
- license: MIT OR Apache-2.0,
- MSRV: Rust 1.85,
- minimum Linux baseline: 4.20+,
- CLI: clap 4 with derive; bare `stallhunt` defaults to 10s hunt; `stallhunt completions <shell>`.

Decided in ADR-0013:

- color/terminal crate: `ratatui` 0.29 (`crossterm` 0.28 backend) for the
  watch TUI; `--no-color`/`NO_COLOR` for color, TTY-vs-pipe for layout.

These remaining items should be decided when implementation makes the tradeoff
concrete, not all at once.

## Last meaningful validation

On 2026-08-23, the v0.2.0 release preparation updated the package, lockfile,
manual, current JSON examples, installation guide, changelog, and project
status after PR #6 merged the ADR-0013 interface redesign. Formatting,
locked-offline Clippy, the full default test suite, a locked-offline release
build, the release binary version check, and the man-page render all passed:

```bash
cargo fmt --all -- --check
cargo clippy --locked --offline --workspace --all-targets --all-features -- -D warnings
cargo test --locked --offline --workspace --all-features
cargo build --release --locked --offline
./target/release/stallhunt version
groff -man -Tascii docs/stallhunt.1
```

The binary reported `stallhunt 0.2.0`. The gate ran 183 unit tests (one fixture
writer ignored), 13 CLI tests, three replay-fixture tests, and five ignored
Linux acceptance tests. Before the version update, PR #6 passed the GitHub
Actions Rust 1.85 and stable jobs. The pressure-generating acceptance tests
remain opt-in because they require explicit host or delegated-cgroup setup.

Later still on 2026-08-23, the ADR-0013 interface redesign (compact
hunt/replay report, watch TUI, `--verbose`/`--no-color`/`NO_COLOR`) landed in
four gate-passing commits, each confirming the pre-existing golden fixtures
stayed byte-identical before adding new ones. Formatting, locked-offline
Clippy, and the full default test suite passed:

```bash
cargo fmt --all -- --check
cargo clippy --locked --offline --workspace --all-targets --all-features -- -D warnings
cargo test --locked --offline --workspace --all-features
```

The gate ran 183 unit tests (one fixture writer ignored), 13 CLI tests, three
replay-fixture tests, and five ignored Linux acceptance tests. The full
`ratatui`/`crossterm` dependency closure (~70 packages) was confirmed to
resolve and build offline against the local registry cache before the
updated `Cargo.lock` was committed. The man page still rendered successfully
with `groff -man -Tascii`. Beyond the automated gate: an external `kill -INT`
to a `--count`-bounded TUI session was manually verified (via a pty) to
restore the terminal before exit — a gap in the initial implementation,
fixed before commit; single and double SIGINT to both bounded and unbounded
TUI sessions were each confirmed to leave the terminal in a clean state; the
watch JSON stream was confirmed structurally to carry no new keys; and the
compact report was confirmed to render roughly 4.7x shorter than the
equivalent legacy output on the same fixed multi-section fixture.

Later on 2026-08-23, a documentation consistency audit reconciled the v0.1.1
and v0.1.2 SIGINT/truncation history, current JSON examples, watch semantics,
published tarball contents, and the implemented CI/release workflows. It also
recorded that the published GNU/Linux binary has no defined old-glibc
compatibility baseline. The formatting, locked-offline Clippy, and full default
test gates below passed again; the man page rendered successfully with `groff`.

On 2026-08-23, the v0.1.2 corrective release restored prompt second-SIGINT
termination for unlimited watch and made the evidence-chain truncation fixture
exercise 18 eligible candidates before retaining 16. Formatting, locked-offline
Clippy, and the full default test suite passed:

```bash
cargo fmt --all -- --check
cargo clippy --locked --offline --workspace --all-targets --all-features -- -D warnings
cargo test --locked --offline --workspace --all-features
```

The gate ran 157 unit tests (156 passed, one fixture writer ignored), 13 CLI
tests, three replay-fixture tests, and five ignored Linux acceptance tests.
PR #4 also passed the GitHub Actions Rust 1.85 and stable jobs. Tag `v0.1.2`
then completed the release workflow, which published the GNU/Linux tarball and
SHA-256 sidecar; the downloaded tarball matched that checksum.

On 2026-08-18, Stallhunt v0.1.0 productization landed: binary/package name
`stallhunt`, clap CLI with default hunt and completions, JSON kinds
`stallhunt.recording` and `stallhunt.watch_window`, dual license, MSRV 1.85,
Linux 4.20+ baseline, watch top-16 false-resolution fix, and documentation
rewritten for installed use. Formatting, locked-offline Clippy, and all default
tests passed:

```bash
cargo fmt --all -- --check
cargo clippy --locked --offline --workspace --all-targets --all-features -- -D warnings
cargo test --locked --offline --workspace --all-features
```

On 2026-08-17, a project-wide implementation/documentation consistency audit
verified current milestone, causality, recording, scoped-mechanism, and watch-
identity claims. The audit refreshed the README quickstart, pending-work
handoff, cgroup budgets, watch-kind catalog, acceptance instructions, ADR
cross-references, and experiment state. The documented quickstart CLI syntax
was checked against the current binary. Formatting, locked-offline Clippy, and
all default tests passed.

Default-gate coverage is 157 unit tests, 13 CLI tests, three replay-fixture
tests, and five ignored Linux acceptance tests.

Earlier the same day, scoped cgroup possible-thrashing labels were validated with
deterministic analyzer coverage (positive conjunction, slower observation-
interval rates, short PSI window, moderate `some`, missing `full`, invalid
`full`, scan-without-steal, page counters without PSI) plus hunt text/JSON
rendering of the label and watch `kind` `cgroup_memory_possible_thrashing`.

Earlier the same day, watch cgroup lifecycle `kind` strings were validated for reclaim,
swap, quota-throttle, unlabeled CPU/I/O, and a mechanism change that stays
`persistent` on the same path-plus-resource identity. Formatting and
locked-offline Clippy passed; default-gate coverage was then 146 unit tests.

Earlier the same day, scoped cgroup CPU quota-throttle labels were validated
with deterministic analyzer coverage (positive `throttled_usec`,
count-without-time, throttle counters without PSI) plus hunt text/JSON
rendering of the label; default-gate coverage was then 145 unit tests.

Earlier the same day, scoped cgroup memory reclaim/swap labels were validated
with deterministic analyzer coverage (reclaim, swap-wins, unlabeled high
events, scan-without-steal, page counters without PSI) plus hunt text/JSON
rendering of the reclaim label; default-gate coverage was then 144 unit tests.

Earlier the same day, M8's cgroup `memory.stat` mechanism slice was validated
with deterministic parser, interval, analyzer, and renderer coverage (direct
reclaim, swap-in, scan-without-steal, events still sufficient, coincident PSI
still insufficient); default-gate coverage was then 143 unit tests.

Earlier the same day, M8's same-cgroup evidence-chain slice was validated with
deterministic analyzer coverage (same-path positive, coincident PSI, missing
events, parent/child split, CPU–I/O, and host-not-linked-to-cgroup) plus a
checked-in related-evidence text fixture and structural hunt JSON.

Earlier the same day, EXP-0007 measured a current release binary on Linux
7.1.5 with about 370 visible PIDs and ~1,587 stable tasks. Three one-second
hunts used about 6 MiB RSS and 110--210 ms PSI-window skew; cgroup collection
was already at its 256-PID cap. Adding 64 sleepers or 512 sleeping threads
stayed under the CPU and process-I/O caps. `many_pids` now uses a Python helper
so failed forks cannot retry into a sleeper leak.

Earlier the same day, M8's first host evidence-chain slice was validated with
deterministic analyzer coverage plus a checked-in related-evidence text
fixture and structural hunt JSON.

Earlier the same day, M6 watch was validated with deterministic lifecycle tests
(new/persistent/resolved, unconfirmed missing data, cgroup cap/history bounds,
golden text, structural JSON) plus a live `watch --interval 100ms --count 1`
text and JSON CLI path.

Earlier the same day, M5 recording/replay was validated with deterministic
round-trip and redaction tests plus a live 100 ms `record` → `replay --json` →
`redact` CLI path. Recordings reject hunt JSON and unknown schema versions.

Earlier the same day, `tests/memory_acceptance.rs` ran twice on Linux 7.1.5 with
`STALLHUNT_MEMORY_ACCEPTANCE_PATH` set to the user-delegated `app.slice`.
Both runs passed: exact host memory PSI `some` was 24.4198% then 21.2702% over
~2.15 s, and both reported `memory_swap_pressure`. The second run, after
child-cgroup drain-before-rmdir, left no leftover directory. Details are in
EXP-0006.

Earlier 2026-08-17 CPU, I/O, overhead, and M4 serialization evidence remains in
`docs/experiments.md` (EXP-0001 through EXP-0005).
