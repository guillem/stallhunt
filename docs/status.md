# Project status

Last updated: 2026-08-27

## Current milestone

**v0.5.2 published; Anthropic desktop installation and submission pending**

The published patch release prepares the existing local stdio MCP server for
discovery and installation without adding a remote transport (ADR-0019): an
OpenAI repository plugin, an x86-64 Linux MCPB, checksum-bound official MCP
Registry metadata, public privacy/terms documents, directory artwork, and tool
review annotations are implemented. PR #12 merged into `main`; tag `v0.5.1`
and its GitHub Release publish the tarball, MCPB, both SHA-256 sidecars, and
rendered `server.json`. On 2026-08-27, the owner published
`io.github.guillem/stallhunt` v0.5.1 to the official MCP Registry; the Registry
API reports it active and latest with the same MCPB SHA-256 digest as the
GitHub release. Anthropic directory submission remains pending and must use
v0.5.2 or later because v0.5.1 predates the required bundled README privacy
section. PR #13 merged the patch release; tag v0.5.2 and its successful release
workflow publish and validate the corrected bundle.

**Currently published release: v0.5.2 — Anthropic-ready local MCPB.**

PR #11 merged into `main` (ADR-0017, ADR-0018): `stallhunt mcp` serves
Model Context Protocol tools over stdio, with a resident sampler for
instant recent-pressure answers and a `detail` argument that keeps tool
payloads small by default. The `v0.5.0` tag was pushed and `release.yml`
published the GitHub Release with the `x86_64-unknown-linux-gnu` tarball
and checksum. `v0.5.0` was superseded by v0.5.1.

Milestones 1–6 remain functionally complete. Release v0.3.0 corrects bare
invocation so root `--duration`, `--json`, `--verbose`, and `--no-color` have
explicit-`hunt` parity, and rejects root hunt flags mixed with a subcommand.
The existing bounded walk now retains leader RSS/RSS growth in bytes, fault
deltas, and stable-task block-I/O delay ticks. The optional bounded TASKSTATS
GET collector normalizes version-gated delays behind separate transport and
delay-accounting states. Host- and cgroup-scoped analyzer-owned six-role attribution emits
canonical schema-2 `process_scopes` in hunt and watch JSON, with PSI gating,
deterministic top-five ranking, typed completeness, and explicit stale lifecycle
retention. Cgroup roles rank full stable direct/descendant membership independently
of host rankings and make only their scope partial on membership gaps. Schema-2 recordings persist normalized procfs/taskstats evidence while
schema-1 replay deliberately strips it. Cgroup roles are exposed in schema-2,
legacy/compact text, lifecycle detail, and the responsive watch TUI. At 120×30
or larger, watch keeps Lifecycle, Current, History, and a layout-derived,
Unicode-aware scrollable Detail on the left while rendering all six selected
host/cgroup roles on the right; compact terminals show six role summaries and
can explicitly expand Detail. EXP-0010 records successful controlled-host
rootless degradation, permitted CPU/block-I/O/memory taskstats evidence in host
and cgroup scopes, and capable 512-TGID/member-ceiling overhead. The temporary
binary capability was removed and the operator restored the sysctl. Do not
start
M7 merely because eBPF is interesting; add a probe only for
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
  and possible-thrashing labels remain fixture-validated. The original M2
  finding has no finding-local process fields; v0.4 adds separate PSI-gated
  scoped memory roles, whose taskstats path passed controlled host-and-cgroup
  validation in EXP-0010.
- **M3 complete within its deliberately limited exit condition:** PSI-backed
  block-I/O pressure and same-window activity candidates were validated by the
  recorded controlled run. v0.4 adds scoped delay-based I/O victim roles, but
  process-device mapping and causality remain explicitly unsupported and the
  taskstats path passed controlled host-and-cgroup validation in EXP-0010.
- **M4 implemented:** bounded cgroup-v2 collection, scoped analysis,
  completeness semantics, controller context, and deterministic coverage are
  complete. Live delegated-scope validation is available opt-in and cannot be
  assumed on an arbitrary host.
- **M5 complete within its exit condition:** versioned normalized-observation
  recordings, `record`/`replay`/`redact`, identifier redaction, 0600 file
  creation, and deterministic re-analysis are implemented. New recordings use
  schema 2; schema 1 remains readable and redactable (ADR-0016). There is still
  no multi-window recording.
- **M6 complete within its exit condition:** `watch` classifies host and
  bounded cgroup pressure findings as new, persistent, or resolved across
  contiguous rolling windows, keeps 16 history windows, and does not store full
  finding evidence in its JSON stream. Piped text and schema-2 JSON expose six
  bounded analyzer-owned role lists for host and cgroup scopes. Per
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
- Real `hunt`, `watch`, `record`, `replay`, `redact`, `capabilities`, `mcp`,
  help, and version command structure exists.
- `mcp` serves Model Context Protocol tools over stdio for coding agents
  (ADR-0017): a hand-rolled synchronous JSON-RPC loop pinned to protocol
  revision 2025-06-18 with no new dependencies. A resident sampler thread
  (default 2 s interval, `--no-sampler` to disable, self-healing via
  `catch_unwind` around each tick) reuses the watch observation seams and
  finding-lifecycle tracker so `get_current_pressure` and
  `get_recent_history` answer instantly about the last up-to-16 windows;
  `run_hunt` and `get_capabilities` mirror the one-shot commands. A
  malformed or non-UTF-8 line gets a JSON-RPC parse error and the session
  continues; a broken output pipe (client gone) ends the session cleanly
  rather than crashing the process. Tool results are projections of the
  schema-version-2 documents serialized from the same structs as the CLI
  JSON output, verified by string-vs-document equality tests and an
  end-to-end pipe-driven session test (`tests/mcp.rs`). By default
  (`detail: "lean"`, ADR-0018) `get_current_pressure` and `run_hunt` remove
  process-candidate fields that are genuinely restated in `process_scopes`
  this window (a stale/resolved lifecycle entry keeps its candidates,
  since those are its only copy), and `run_hunt` also omits raw
  per-process/per-cgroup `observation` telemetry that findings already
  summarize while keeping every ADR-0015 completeness signal, including
  `cgroup.issues` and `process_io`'s completeness fields — measured 70.6%
  and 79.9% smaller respectively against a real `fake_workload.sh`
  reproduction. `get_recent_history` has no lean mode: its response has no
  `process_scopes` for a stripped entry to restate, so it always returns
  full detail. `detail: "full"` returns every field with the same content
  as the CLI's JSON output (key order may differ, since the MCP path
  serializes through a JSON value).
- Every MCP tool has a human-readable title and accurate read-only,
  non-destructive, idempotent, closed-world annotations. Repository plugin and
  MCPB manifests, public privacy/terms material, shared directory artwork,
  checksum-bound Registry metadata generation, packaging scripts, and release
  workflow assets implement ADR-0019 without changing collection or inference.
- `hunt` accepts `--duration` values from 100 ms through 5 minutes, including
  exact-millisecond decimal values, and defaults to 10 seconds.
- Bare `stallhunt` accepts the same `--duration`, `--json`, `--verbose`, and
  `--no-color` options as explicit `stallhunt hunt`; root hunt options conflict
  with explicit subcommands and appear in root help and shell completions.
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
- The v0.4 procfs-normalization slice reuses that bounded PID/task walk: it
  retains leader RSS and RSS growth in checked bytes, minor/major-fault deltas,
  and checked stable-task block-I/O delay-tick sums. Per-thread RSS is never
  summed. RSS is a gauge, so a valid decrease produces zero growth; missing
  trailing `stat` fields, negative RSS, identity churn, monotonic-counter
  regression, and aggregate overflow remain explicit unavailable or partial
  evidence rather than fabricated zeroes. Task-stat completeness is tracked
  independently of schedstat, so block-I/O evidence can remain usable when
  schedstat is unavailable. Schema-1 recordings omit this new evidence. It
  adds no taskstats access,
  process role inference, cgroup attribution, or presentation behavior.
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
  the lowest 512 visible PIDs per endpoint and reads only mapped cgroups plus
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
  and JSON emits one `stallhunt.watch_window` object per window. Every surface
  exposes bounded CPU, memory, and I/O victim/suspect roles when supported.
  Confirmed lifecycle findings refresh candidates; unconfirmed or resolved
  findings retain them with a stale/last-observed label. Schema-2 JSON
  distinguishes available, partial, unavailable, and not-assessed roles. Watch
  JSON is not hunt JSON and not a recording. Scoped
  cgroup lifecycle `kind` values name the resource and any
  reclaim, swap, possible-thrashing, or quota-throttle label; identity
  remains path plus resource.
- Per ADR-0013, `hunt`/`replay` render a compact, color-coded, width-aware
  report (`src/report.rs`) on a TTY instead of the stacked plain-text
  sections; piped output is byte-for-byte unchanged. The 61 per-finding
  qualifier messages collapse by default to a tag summary; `--verbose`
  restores the full text on hunt/replay, and the watch TUI's detail pane
  shows it per finding with no flag. `--no-color` and `NO_COLOR` disable
  color without changing layout on hunt, replay, and watch. `ratatui` 0.29
  and `crossterm` 0.28 are new dependencies, justified in ADR-0013;
  `unicode-width` 0.2 is direct for terminal-column-safe process names, as
  recorded in ADR-0014.
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

- `stallhunt mcp` serves one client on a single thread: `run_hunt` blocks
  that thread for its full requested duration (up to 5 minutes), so a
  concurrent `ping` or sampler-backed request sent while a long hunt is in
  flight gets no response until the hunt finishes. This is disclosed in
  `run_hunt`'s tool description (keep your client timeout above the
  requested duration) rather than fixed, per ADR-0017's decision to
  hand-roll a synchronous single-threaded server; a worker-thread or
  request-multiplexing design would need its own ADR if this becomes a
  real constraint in practice.
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
- The new procfs resource evidence is raw normalized context only. Delayacct
  block-I/O ticks can be absent or disabled, and zero or unavailable values do
  not establish that a process suffered no I/O delay. EXP-0010 supplies
  controlled-host TASKSTATS acceptance; roles still consume positive counters
  conservatively and expose collection gaps explicitly.
- TASKSTATS TGID selection is host-wide, lowest-PID-first, and applied before
  any cgroup scoping. On a host with more than 512 total processes this
  correctly reports `Partial` taskstats capability (the 512-TGID cap is
  reached), so completeness is never falsely claimed; but a scoped hunt
  targeting a higher-PID cgroup can still lose taskstats coverage for exactly
  the scope being investigated, silently falling back to weaker procfs
  evidence within an honestly-labeled partial window. Fixing this requires
  reading cgroup membership before the TGID selection and threading a
  priority set through the collection pipeline, which is a collection-path
  restructure, not a v0.4.1 patch; see "Current recommended next task".
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
  but the original run did not validate I/O victims, process-device mapping,
  or causality. EXP-0010 later observed two procfs block-I/O-delay victims;
  taskstats victims remain unvalidated and the existing acceptance degraded on
  partial process-I/O. EXP-0007 measured process-I/O collection at 129--194
  intervals on that workstation, still below the 1,024-PID cap.
- The ignored cgroup acceptance test requires a caller-provided, uniquely owned
  delegated subtree. It safely skips when that prerequisite is absent, so an
  arbitrary host does not yet provide controlled per-cgroup pressure evidence.
- The cgroup collector adds a second independent procfs PID walk rather than
  reusing the existing CPU or process-I/O selection. EXP-0007 found that walk
  already at its pre-v0.4 PID cap on a 370-PID host (94 groups, partial completeness);
  the current collector cap is 512.
  Extra high-numbered helper PIDs did not increase the selected cgroup set.
- M5 recordings are pre-1.0 and may become unreadable after a schema change.
  Identifier redaction is not cryptographic anonymization: PIDs, start times,
  major/minor keys, and path shape remain. Duration replay uses integer
  microseconds, which can differ slightly from a live nanosecond `Instant`
  interval. Recordings do not include extra host identity such as hostname or
  kernel version.
- Watch JSON carries bounded process-candidate evidence but still omits full
  observations, raw resource evidence, and qualifiers. Schema-2 also carries
  canonical host and cgroup six-role lists. CPU suspects and I/O suspects are
  same-window correlation, while CPU victims are observed summed runnable delay rather
  than proof of user-visible harm. A disappeared cgroup finding stays
  unconfirmed until that scope is observed without ranked pressure.
  Unlimited `watch` without `--count` samples until interrupted and drains the
  current window after the first SIGINT; a second SIGINT exits immediately.
  Consecutive 100 ms windows remain smoke observations, same as hunt.
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

The approved v0.4.0 vertical slice now has bounded procfs/taskstats evidence,
host and cgroup six-role attribution, and schema-2 outputs/recording migration.
v0.4.1 was a pre-release code-review bugfix pass on top of that slice (see
"Last meaningful validation") and is now published. No additional M8 chain or
M7 probe is part of this slice.

Diagnostic and attribution gaps:

- host memory and I/O roles remain conservative candidates rather than causal
  proof; process-to-device mapping remains unsupported;
- event-level scheduler, off-CPU, block-request, lock, and network evidence is
  absent because M7 has not started;
- CPU–I/O, host–cgroup, cross-cgroup, and process-device chains remain
  unsupported; coincident PSI is not evidence for any of them;
- watch does not track evidence chains, retain full evidence, or produce a
  multi-window recording.

Validation gaps:

- scoped swap now has a controlled live result; scoped reclaim-only,
  possible-thrashing, and quota-throttle labels remain deterministic-test
  validated without a controlled live scoped-pressure result;
- the cgroup acceptance test is opt-in observational coverage and requires a
  caller-owned delegated subtree;
- host reclaim-only and possible-thrashing remain fixture-validated, while the
  live memory acceptance exercised swap pressure;
- a controlled live busy-but-not-pressured CPU workload remains unrecorded;
- severity thresholds are provisional rather than portable guarantees.

Operational and delivery gaps:

- historical cgroup collection reached its pre-v0.4 PID selection cap;
  EXP-0010 now records capable 512-TGID and 512-PID cgroup-membership-ceiling
  overhead after safely disambiguating equivalent cgroupfs aliases;
- deterministic codec, attribution, migration, renderer, TUI, stable/MSRV,
  package, and local PTY gates pass;
- v0.4.1 released 2026-08-25 via the normal PR merge/tag workflow (PR #9);
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
- release automation still targets one dynamically linked x86_64 GNU/Linux
  binary, now in both tarball and MCPB containers with checksums; additional
  targets, an explicit glibc baseline, signatures, and provenance remain open;
- OpenAI documents public MCP-backed plugin submission, but the review endpoint
  must be hosted on a publicly accessible domain; local/testing endpoints and
  development tunnels do not satisfy submission. The repository/workspace
  plugin remains Stallhunt's prepared OpenAI path because a hosted server would
  diagnose the wrong Linux machine.
- The official MCP Registry entry for v0.5.1 is active. Anthropic submission
  has not been made and must use v0.5.2 or later because its current policy
  requires the newly added README `Privacy Policy` section inside the immutable
  bundle.

## Known bugs

None recorded at this milestone boundary.

The watch top-16 false-resolution bug (a pressured cgroup below the ranking cap
was reported as `resolved`) was fixed in v0.1.0. Ranking omission now leaves
the finding persistent and unconfirmed; see
[`CHANGELOG.md`](../CHANGELOG.md).

A pre-release code review of the unpublished v0.4.0 tree found and fixed six
issues, most notably a vacuous-truth completeness bug: an empty-overlap
taskstats interval (normal process churn between window endpoints) reported
`Available` capability instead of `Partial`, so a window with zero collected
taskstats evidence could read as a complete, confirmed clean negative. See
`## [0.4.1]` in [`CHANGELOG.md`](../CHANGELOG.md) and "Last meaningful
validation" below for the full list and how each was verified.

## Current recommended next task

Complete the remaining Anthropic directory work recorded in
[`directory-distribution.md`](directory-distribution.md):

1. install and exercise the exact released v0.5.2 MCPB in a compatible Claude
   Desktop environment;
2. submit the exact released MCPB through Anthropic's desktop-extension form
   and retain the reviewer correspondence in this status document;
3. keep the OpenAI plugin on the repository/workspace path. Do not add a remote
   server that would diagnose the wrong host solely for directory eligibility.

After that delivery work, do not start Milestone 7 or add another M8 chain
without a concrete diagnostic gap. The next diagnostic task remains making
TASKSTATS TGID selection cgroup-aware (read cgroup membership before the
bounded procfs walk and prioritize scope members within the 512-TGID cap) so a
scoped hunt on a busy, high-PID host does not lose taskstats coverage for
exactly the scope being investigated; see the bullet under "Known limitations".

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

The deterministic lowest-512-PID cgroup selection can be capped on the
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

### R8: Transitive dependency audit warnings

`cargo audit` 0.22.2 exits successfully for the current lockfile but warns that
`paste` is unmaintained (RUSTSEC-2024-0436) and that `lru` has two unsoundness
advisories (RUSTSEC-2026-0002 and RUSTSEC-2026-0253). They arrive through the
pinned ratatui 0.29 dependency graph. Ratatui 0.30.0 requires Rust 1.86, while
0.30.1 or newer requires Rust 1.88; both are above the 1.85 MSRV, so an upgrade
is not an automatic fix.

Mitigation:

- do not claim a clean audit or use an unsupported `--omit=dev` flag;
- retain the lockfile and do not suppress the warnings;
- ratatui's production `lru` call path uses `get_or_insert`, not the advised
  `IterMut` or `pop` APIs, while `paste` is a build-time maintenance warning;
- accept this narrow exposure for v0.4.0 after technical review, and revisit it
  if the call path, advisories, MSRV, or dependency versions change;
- keep the full-lockfile audit result and disposition in EXP-0009.

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

Decided in ADR-0014:

- root hunt options have explicit-`hunt` parity and conflict with subcommands;
- the earlier schema-1 watch attribution contract is historical and is
  superseded by ADR-0016's schema-2 scoped role model.

These remaining items should be decided when implementation makes the tradeoff
concrete, not all at once.

## Last meaningful validation

On 2026-08-27, PR #13 passed duplicate push/PR CI runs (Rust 1.85 MSRV and
stable formatting/Clippy/tests) and merged as commit `550ccfd`; tag v0.5.2
points to that exact merge. Release workflow run 33069976034 passed in 1m7s:
it rebuilt the release binary, packaged the tarball and MCPB, passed Anthropic
MCPB validator 2.1.2, rendered Registry metadata, uploaded all five assets, and
published <https://github.com/guillem/stallhunt/releases/tag/v0.5.2>. The exact
public MCPB was downloaded afresh; its sidecar verified SHA-256
`f157469d399261d8373b43753e2b6c71284ce2637c0027814c7dd2e28407871f`,
the released `server.json` carried that digest, and the extracted README
contained the required `Privacy Policy` section. The extracted release binary
reported 0.5.2; the pinned validator passed again; and a real protocol session
initialized, listed four tools, and called all four successfully, including a
bounded 100ms lean `run_hunt`. Claude Desktop installation and in-client tool
exercise remain separate pending validation.

The first v0.5.2 desktop-install attempt used Bazzite Linux with KDE. Generic
`xdg-open` dispatched the `.mcpb` to Ark because the desktop classifies MCPB as
a ZIP archive; no file association was changed. Launching the installed Claude
Desktop AppImage directly with the released MCPB path did reach Claude's bundle
handler: `main.log` recorded `Handling DXT/MCPB file` for the exact artifact.
At the last check Claude still reported zero installed local extensions and no
stdio servers, so this is not yet an installation pass; it remains pending the
interactive install confirmation and subsequent in-client tool exercise.

On 2026-08-27, the v0.5.2 release candidate passed
`cargo fmt --all -- --check`, locked/offline warning-denied Clippy for the
workspace/all targets/all features, and the full locked/offline all-features
test suite: 311 of 312 unit tests passed with the fixture writer ignored; 15
CLI, three directory-distribution, three documentation-command, three
replay-fixture, and two real-process MCP session tests passed. The five bounded
Linux load or delegated-cgroup acceptance tests remained intentionally ignored.
A locked/offline release build reported 0.5.2; `cargo package --locked
--offline --allow-dirty` packaged and verified 146 tracked files; the man page
rendered; both packaging scripts passed shell syntax checks; and the OpenAI
plugin passed the installed plugin-creator validator. The generated x86-64
Linux MCPB checksum verified, its rendered `server.json` carried the same
SHA-256 digest, and Anthropic MCPB validator 2.1.2 accepted its manifest. The
extracted bundle contained the README `Privacy Policy` section plus byte-equal
README and public privacy policy files, a 512x512 icon, manifest version 0.5.2,
and a binary reporting 0.5.2. A real newline-delimited MCP session against that
extracted binary initialized protocol revision 2025-06-18, listed four tools,
and successfully called all four, including a bounded 100ms lean `run_hunt`.
This candidate validation is not a substitute for installing the exact
released MCPB in Claude Desktop after publication.

On 2026-08-27, the official MCP Registry API returned one active, latest entry
for `io.github.guillem/stallhunt` v0.5.1. Its published package URL points to
the v0.5.1 GitHub Release MCPB and its `fileSha256` value,
`e843121e5c64f0fc19476bb073b764cd7280ce14ff786ba0ba5fb3c82c52872b`,
matches the public release asset digest. This verifies the first directory
publication action; it does not verify Anthropic installation or review.

On 2026-08-26, PR #12 merged the directory-distribution implementation as
commit `6d6e67a`; tag `v0.5.1` points to that exact merge. The PR push did not
schedule the repository CI workflow before merge, so the merge relied on the
complete local gates recorded below. The tag-triggered release workflow later
scheduled and passed as run 32989114522: it rebuilt the release binary,
created the tarball and MCPB, passed the pinned Anthropic MCPB validator,
rendered checksum-bound Registry metadata, uploaded all five assets, and
published <https://github.com/guillem/stallhunt/releases/tag/v0.5.1>. Freshly
downloaded public tarball and MCPB sidecars both verified, and the released
`server.json` digest exactly matched the public MCPB. A current-directory-rule
review then found that Anthropic additionally requires a `Privacy Policy`
heading in a local connector's bundled README. Main now includes it; v0.5.1
remains immutable and must not be submitted to Anthropic. The Registry entry
was subsequently published and verified on 2026-08-27; no vendor listing has
been published.

On 2026-08-26, the unpublished v0.5.1 directory-distribution preparation
passed `cargo fmt --all -- --check`, Clippy for the workspace/all targets/all
features with warnings denied, and the full all-features test suite: 311 of
312 unit tests passed with the fixture writer ignored; 15 CLI, three
directory-distribution, three documentation-command, three replay-fixture,
and two real-process MCP session tests passed. The five bounded Linux load or
delegated-cgroup acceptance tests remained intentionally ignored. The OpenAI
plugin passed the plugin-creator validator; both packaging scripts passed
shell syntax checks. A locked release build was packaged into the Linux
x86-64 MCPB, its portable SHA-256 sidecar verified, the official Anthropic
MCPB 2.1.2 validator accepted the extracted manifest, and the extracted
binary reported 0.5.1 and completed a real initialize handshake. Registry
metadata rendered with the artifact's actual checksum, all JSON inputs
parsed, `cargo package --locked --allow-dirty` built and verified the 147-file
source package, and `git diff --check` passed. No tag, GitHub Release,
Registry version, or vendor directory listing was created during this
validation.

On 2026-08-25, the owner authorized the v0.5.0 release. PR #11 (`stallhunt
mcp`, ADR-0017/ADR-0018) passed CI (`msrv` and `stable` jobs) and was merged
into `main`; a multi-agent code review found nine confirmed correctness/
robustness findings, all fixed in the same PR with a regression test per
finding (one, `run_hunt` blocking the single-threaded server for its full
duration, was an accepted disclosed tradeoff, recorded under Known
limitations rather than changed). The `v0.5.0` tag was pushed and
`release.yml` built the release binary, packaged the
`x86_64-unknown-linux-gnu` tarball and SHA-256 sidecar, and published the
GitHub Release. See
<https://github.com/guillem/stallhunt/releases/tag/v0.5.0>.

On 2026-08-25, the owner authorized the v0.4.1 release. PR #9 (the code-review
bugfix pass below) passed CI (`msrv` and `stable` jobs) and was merged into
`main`; the `v0.4.1` tag was pushed and `release.yml` built the release
binary, packaged the `x86_64-unknown-linux-gnu` tarball and SHA-256 sidecar,
and published the GitHub Release. See
<https://github.com/guillem/stallhunt/releases/tag/v0.4.1>.

On 2026-08-25, a pre-release code review of the unpublished v0.4.0 tree found
six issues, five confirmed fixable in a v0.4.1 patch and one recorded as a
known limitation (see "Known limitations" and "Known bugs" above). Each fix
has a new deterministic test; see `## [0.4.1]` in
[`CHANGELOG.md`](../CHANGELOG.md) for the list. The one issue not fixed here
was verified rather than assumed: hosts above the 512-TGID taskstats cap
already report `Partial` capability (never a false `Available`) via the
existing `tgid_limit_reached` path, so the host-wide-before-cgroup-scoping TGID
selection is a coverage/fairness gap with honest completeness signaling, not a
silent correctness bug — fixing it needs cgroup membership threaded through
the collection pipeline ahead of the bounded procfs walk, a collection-path
restructure out of scope for a patch release. `cargo fmt --all -- --check`,
locked offline Clippy, and locked offline tests all passed (266 unit tests, up
from 262; 15 CLI, three documentation, and three replay-fixture integration
tests; five Linux acceptance tests remain ignored). No release build, manual,
or tarball re-validation was performed as part of this pass.

On 2026-08-24, operator-provided `CAP_NET_ADMIN` enabled bounded TASKSTATS GET
without Stallhunt performing elevation. Controlled CPU, memory, and I/O
workloads produced PSI-backed taskstats victims in both host and exact child-
cgroup scopes: CPU reached 16.66%/13.86% host/child PSI with five candidates;
memory reached 29.38%/35.58% with a direct reclaim-dominant victim; and I/O
reached 11.70%/11.75% with two 1.49–1.52 s block-delay victims. A stable
512-extra-process run completed 1,024 GETs and 512 intervals while the cgroup
walk reached its 512-PID ceiling, retained 97 groups, and stayed within all
budgets. Three release runs took 1.20–1.23 s wall, 0.04–0.05 s user,
0.15–0.17 s system, and 10,216–14,240 KiB RSS. Equivalent duplicate cgroupfs
mounts were safely disambiguated by commit `5699fd4`; different device/root
views remain rejected. All owned workloads and generated cgroups/directories
were cleaned, and rebuilding the release binary removed its temporary file
capability. The operator then restored `kernel.task_delayacct=0`, which
Stallhunt verified. See EXP-0010.

On 2026-08-24, the operator enabled `kernel.task_delayacct` before owned
workloads on Linux 7.2.0-ogc4.1.fc44.x86_64. Rootless Stallhunt correctly
reported delay accounting enabled but taskstats permission denied. A
512-extra-process run selected exactly 512 TGIDs, set the limit flag, made zero
successful queries after two endpoint permission denials, and exhausted no
protocol budgets. CPU acceptance passed with 46.51% exact PSI `some`, five
victims, and three suspects. Bounded I/O produced 12.69% exact PSI `some` and
procfs I/O victims, while correctly retaining partial process-I/O capability.
Release-binary one-second overhead remained 1.14–1.17 s wall, 0.02–0.03 s
user, 0.11–0.14 s system, and 8,476–11,040 KiB RSS with 512 extra processes.
That first phase preceded the capable and scoped continuation recorded above.

Release preparation on 2026-08-24 changed the package, binary, manual, and
recording example version to 0.4.0 without publishing it. The current local
tree passed formatting, locked offline Clippy, and locked offline tests (262
passed, one fixture writer ignored; 15 CLI, three documentation, and three
replay-fixture integration tests passed; five Linux acceptance tests remain
ignored). The release build printed `stallhunt 0.4.0`; `groff -man -Tascii`
accepted the manual; and the release-binary PTY check verified alternate-screen
cleanup and terminal-state restoration. A local v0.4.0 tarball staging
inspection contained exactly the binary, README, both licenses, and manual. No
tag or GitHub Release was made.

`cargo-audit` 0.22.2's supported full-lockfile command exited 0 with three
warnings: RUSTSEC-2024-0436 for `paste`, and RUSTSEC-2026-0002 plus
RUSTSEC-2026-0253 for `lru`, transitively via ratatui 0.29. Its help has no
`--omit=dev` option; the planned literal command is not valid for this version.
Technical review accepted this narrow exposure for v0.4.0 because the advised
`lru` APIs are not used by ratatui's production path and `paste` is a
maintenance-only warning. The audit is not clean; warnings remain visible and
must be revisited when the call path, advisories, dependencies, or MSRV change.

On 2026-08-24, the v0.4 procfs/taskstats collector slices passed deterministic
parser, protocol, scripted collection, and interval tests for leader RSS,
missing/negative fields, fault and block-I/O counter regression, overflow,
task churn, PID/TID reuse, lowest-512 TGID selection, identity bracketing,
`ESRCH`, TASKSTATS UAPI version prefixes/offsets, malformed nested replies,
response/time budgets, and capability degradation. Recording
redaction and schema-1 replay compatibility were also exercised. The complete
local formatting, locked offline Clippy, and locked offline test gates passed:

```bash
cargo fmt --all -- --check
cargo clippy --locked --offline --workspace --all-targets --all-features -- -D warnings
cargo test --locked --offline --workspace --all-features
```

The bounded local PTY check observed alternate-screen enter/leave and restored
the original terminal state after one TUI window. At this release-preparation
point the optional Linux acceptance tests remained skipped and no controlled-
host taskstats validation had run. EXP-0010 subsequently recorded rootless and
permitted CPU, block-I/O, and memory acceptance in host/cgroup scopes plus
capable 512-TGID and 512-PID membership-ceiling overhead.

On 2026-08-24, the v0.3.0 release preparation validated implicit root-hunt
option parity and conflicts, typed watch process attribution across lifecycle,
piped text, JSON, and the 80x24 TUI, the tracked-document command audit, and
the updated manual and release metadata. The complete local gate passed:

```bash
cargo fmt --all -- --check
cargo clippy --locked --offline --workspace --all-targets --all-features -- -D warnings
cargo test --locked --offline --workspace --all-features
cargo build --release --locked --offline
./target/release/stallhunt version
groff -man -Tascii docs/stallhunt.1
```

The release binary reported `stallhunt 0.3.0`. The default gate ran 196 unit
tests (195 passed and one fixture writer was ignored), 15 CLI tests, three
documentation-command tests, three replay-fixture tests, and five ignored Linux
acceptance tests. Release-binary smoke checks confirmed root help and Bash
completions expose all implicit-hunt flags, root `--json` mixed with
`capabilities` exits 2, a 100 ms implicit JSON hunt emits schema 1, and a one-
window watch JSON stream carries `stallhunt.watch_window` plus process-candidate
fields. The man page rendered successfully. Pressure-generating acceptance
tests remain opt-in because they require explicit host or delegated-cgroup
setup.

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
was already at its pre-v0.4 PID cap. The current collector cap is 512. Adding 64 sleepers or 512 sleeping threads
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
