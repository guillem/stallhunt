# Product definition

## Problem

Linux already offers excellent performance monitoring and profiling tools, but many require an experienced operator to correlate multiple views:

- CPU consumption,
- scheduler state,
- memory occupancy,
- pressure,
- disk throughput,
- queueing,
- process state,
- cgroups,
- latency,
- kernel accounting.

The machine may visibly be "busy" without being bottlenecked, or apparently underutilized while important work is stalled.

The missing product abstraction is **automated local performance triage**.

## Product statement

Bottleneck Finder observes a Linux system for a bounded period and produces ranked findings that explain:

- **resource**: what is constrained,
- **impact**: how much progress is being lost,
- **victims**: which workloads are being delayed,
- **suspects**: which workloads are likely contributing,
- **evidence**: what measurements support the conclusion,
- **confidence**: how strongly the evidence supports causal language.

## Primary user questions

The CLI should eventually answer:

1. "Why is this machine slow?"
2. "Is CPU actually the problem?"
3. "Is high memory use harmful right now?"
4. "Which process is hurting the others?"
5. "Which service/container is affected?"
6. "Is disk throughput high but healthy, or is it creating stalls?"
7. "What changed during this 30-second incident?"
8. "Can I save enough evidence to analyze this later?"

## Intended users

Primary:

- Linux developers,
- systems programmers,
- SREs,
- system administrators,
- performance engineers,
- advanced desktop/server users.

Secondary:

- coding agents performing local diagnostics,
- CI systems diagnosing noisy/overloaded workers,
- support engineers collecting compact evidence.

## Product category

Prefer describing the project as:

> **Linux performance triage**

Avoid positioning it primarily as:

- monitoring,
- observability,
- APM,
- profiling,
- benchmarking,
- anomaly detection.

It may use techniques from all of these, but triage is the user-level purpose.

## Core conceptual model

### Consumption is not contention

Examples:

- 95% RAM used with negligible memory PSI may be healthy.
- 100% CPU utilization may be expected batch work with no important victim.
- moderate CPU utilization with runnable latency can still harm an interactive workload.
- high disk throughput may be healthy sequential I/O.
- low throughput with deep latency can indicate pathological storage behavior.

Therefore:

> The most important signal is often **time in which work wanted to progress but could not**.

### Findings, not dashboards

The default output should be ranked findings.

A finding is an evidence-backed interpretation such as:

- CPU scheduling contention,
- memory reclaim pressure,
- storage latency contention,
- likely lock contention,
- no meaningful bottleneck observed.

Raw metrics remain available for explanation/debugging but are not the main UX.

## Goals

### G1: Detect genuine contention

Prefer direct or near-direct stall signals over occupancy thresholds.

### G2: Attribute impact

Identify affected processes, threads, services, cgroups or devices where feasible.

### G3: Attribute likely causes

Rank likely contributing consumers separately from victims.

A process may be both.

### G4: Explain findings

Every finding must retain evidence sufficient to explain why it exists.

### G5: Express uncertainty

Causal attribution is frequently probabilistic.

The tool should be credible precisely because it says when evidence is weak.

### G6: Low operational overhead

Sampling overhead should remain small enough for production-like diagnostics.

### G7: Useful without elevated privileges

The tool should provide a useful baseline as a normal user and progressively expose richer diagnostics when capabilities permit.

### G8: Deterministic offline analysis

Analysis logic should be runnable against recorded/fixture observations for tests and future replay.

## Non-goals for early versions

- Full APM tracing.
- Distributed-system root cause analysis.
- Cross-host correlation.
- General log analysis.
- Full flamegraph/profiler replacement.
- Always-on metric storage.
- Prometheus replacement.
- Kernel debugger.
- Perfect generic wait-chain reconstruction.
- Automatic remediation.
- AI/LLM-based diagnosis in the core product.
- Cross-platform parity.

## Important negative finding

The tool should confidently report when a commonly alarming metric is **not currently supported by evidence of a bottleneck**.

Examples:

```text
Memory utilization: 93%
Memory PSI: negligible
Swap activity: none
Reclaim delay: negligible

Finding: no meaningful memory bottleneck observed.
```

This is a first-class product feature, not absence of output.

## Observation modes

### `hunt`

Bounded active diagnosis.

Example:

```bash
bottleneck hunt --duration 10s
```

This should be the primary early workflow.

### `watch`

Continuous rolling diagnosis.

Later milestone.

### `explain`

Expand a finding, process, cgroup, resource or device.

Later milestone.

### `record` / `replay`

Store normalized observations and re-run analysis offline.

Design for this early even if the first release implements fixtures before a user-facing recording format.

## Severity vs confidence

These are independent.

**Severity** asks:

> How much harm is occurring?

**Confidence** asks:

> How strong is the evidence for this interpretation/attribution?

Examples:

- severe CPU pressure, low-confidence suspect attribution;
- moderate I/O stalls, high-confidence device attribution;
- low-severity memory pressure, high confidence.

Never collapse both into one opaque score.

## Success criteria for v0.1

A useful v0.1 should:

- compile on a documented Linux baseline,
- collect PSI and basic CPU/process telemetry,
- observe over a bounded interval,
- detect meaningful CPU scheduling pressure,
- identify likely CPU consumers,
- identify tasks suffering runnable delay when data permits,
- produce a clear evidence-backed finding,
- produce a "no CPU bottleneck" result when appropriate,
- expose JSON output,
- have deterministic tests using fixtures,
- degrade gracefully when optional telemetry is unavailable.

## Success criteria for the first broader release

The first broad release should diagnose at least:

- CPU scheduler contention,
- memory pressure,
- block I/O contention,

with:

- severity,
- confidence,
- evidence,
- victims,
- suspects,
- bounded runtime overhead,
- stable structured output.
