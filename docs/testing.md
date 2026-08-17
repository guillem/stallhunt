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
checks structural capability/degradation behavior; it is not controlled harmful
memory-pressure validation.

M3 adds deterministic diskstats/process-I/O/PSI parser and interval coverage,
normalized I/O fixtures for healthy high activity, pressure ranking, low
boundary, missing context, and short windows, plus renderer/executable healthy
smoke coverage. Its ignored rootless acceptance test also ran a bounded
competing-I/O scenario: exactly two owned `stress-ng` HDD workers on a
checkout-local temporary path, with direct/sync/fsync behavior and an
eight-second coordinator bound. The test asserts a PSI-backed I/O-pressure
finding while preserving the lack of victim, process-device, and causal claims.

M4 must add deterministic cgroup-v2 fixture trees for mountinfo and `0::`
membership parsing, normalized-path validation, ancestor selection, every
collection budget, controller/missing-permission degradation, process movement
and PID reuse across the stat-cgroup-stat check, scoped PSI interval rules, and
path-derived systemd candidate labeling. Analyzer coverage must include positive,
negative, boundary, missing-data, and contradictory host-versus-cgroup PSI
cases. No test may encode cgroup membership or counter activity as causal proof.

Any live cgroup test must be ignored by default, use only a uniquely owned
delegated/readable subtree, enforce cleanup and timeouts, and skip rather than
mutate an arbitrary host hierarchy when delegation is absent.

Mark environment-dependent tests clearly.

The current normal deterministic gate contains 103 unit tests and six CLI
tests. Three host-workload acceptance tests are ignored by default and run only
when intentionally requested.

### 6. Synthetic load scenarios

Create opt-in tests/scripts that deliberately create known contention.

Examples:

#### CPU

- start N+M busy loops on N CPUs,
- run a victim workload,
- verify CPU pressure finding appears.

#### Memory

Later:
- constrained cgroup,
- controlled allocation/reclaim,
- verify memory pressure evidence.

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
installed and is never installed by the harness. Results are recorded as ranges,
not CI pass/fail timing gates. In constrained sandboxes, helper-heavy runs may
hit fork limits; use the smallest safe process/churn setup and isolate the
optional CPU scenario instead of treating that limit as a product result.

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

M2 has satisfied deterministic and healthy-host smoke layers, but not item 4:
do not call the memory diagnosis fully validated until a safe, controlled
real-host harmful-pressure scenario is demonstrated.

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
