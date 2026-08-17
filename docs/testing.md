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

### 5. Host integration tests

Run against real procfs/sysfs where safe.

These tests should primarily verify:

- files can be discovered,
- parsers work on current host,
- races do not crash the tool.

Do not assert that the host is currently bottlenecked.

Mark environment-dependent tests clearly.

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

Later:
- disposable filesystem/device/test file,
- controlled writers/readers,
- verify I/O pressure.

Synthetic tests must be safe and bounded.

Never assume destructive access to production disks.

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

## Fixture architecture

Recommended directory:

```text
tests/
  fixtures/
    cpu/
      healthy.json
      saturated.json
      saturated_no_schedstat.json
      busy_but_not_pressured.json
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
