# Experiments and validation log

This document is for **durable experimental conclusions**, not routine command transcripts.

Use it to record controlled tests that establish or challenge diagnostic behavior.

## Why keep this in Git?

The inference engine will contain heuristics and thresholds whose validity must be established empirically.

A later developer or coding agent should be able to answer:

- Why is this threshold here?
- Which kernels/machines were tested?
- What workload generated this finding?
- Which false positives have been observed?
- How much overhead did collection add?

Git history will preserve evolution; this file preserves current durable conclusions and links to fixture/test names.

## Experiment template

Copy this section for a meaningful experiment.

```markdown
## EXP-NNNN: Short title

Date:
Commit:
Host/kernel:
CPU:
Memory:
Storage:
Container/cgroup setup:
Relevant privileges/config:

### Question

What are we trying to determine?

### Setup

Exact workload shape and important commands/configuration.

### Expected behavior

What should the tool conclude, and why?

### Observed telemetry

Only the values needed to support the conclusion.

### Tool finding

What did Bottleneck Finder report?

### Result

Pass / fail / ambiguous.

### Conclusion

What durable design conclusion follows?

### Follow-up

Tests, threshold changes, missing telemetry, or open questions.
```

## Planned CPU experiments

### CPU-1: idle/healthy

Goal:

Ensure low CPU activity produces no contention finding.

### CPU-2: busy but not meaningfully pressured

Goal:

Demonstrate that high utilization alone does not necessarily trigger a severe finding.

Exact workload will depend on CPU topology and scheduler behavior.

### CPU-3: oversubscribed CPU

Setup concept:

- determine available logical CPUs,
- run more CPU-bound workers than CPUs,
- observe sustained CPU PSI,
- include at least one identifiable victim process.

Expected:

- CPU contention found,
- elevated severity,
- major CPU consumers appear as suspects,
- schedstat-capable victims show runnable delay.

### CPU-4: missing schedstat

Goal:

Verify CPU resource diagnosis remains possible while victim attribution confidence decreases.

### CPU-5: short transient spike

Goal:

Determine how observation duration and transient PSI should affect severity/confidence.

## Planned memory experiments

Do not run until Milestone 2.

- high cache/occupancy with negligible pressure,
- constrained cgroup with reclaim pressure,
- swap pressure if safe and reproducible,
- memory churn/thrashing scenario.

## Planned I/O experiments

Do not run destructive tests against arbitrary real devices.

Prefer:

- disposable test files,
- controlled filesystem,
- cgroup limits where useful,
- bounded workload durations.

Cases:

- high sequential throughput without severe stalls,
- competing readers/writers with measurable I/O PSI,
- process attribution incomplete due to permissions.

## Overhead experiments

At minimum measure:

- idle host,
- typical developer workstation,
- many-process host,
- rapid process churn,
- already CPU-stressed host.

Record:

- Bottleneck Finder CPU time,
- peak RSS,
- number/size of procfs reads if measurable,
- observation timing skew,
- impact of richer per-process sampling.

## Current experimental conclusions

No controlled M1.6 experiment has produced a durable conclusion yet. M1.5 CPU
collection and conservative inference are implemented, but its provisional
thresholds and collector-overhead limits still require the controlled
experiments described above.
