# Glossary

## Bottleneck

A resource or synchronization condition that materially prevents useful work from progressing.

High utilization alone is not necessarily a bottleneck.

## Contention

Multiple workloads competing for a finite resource in a way that delays at least one workload.

## Pressure

Time-based indication that work is stalled because a resource is unavailable. In Linux, PSI is a primary pressure source.

## Stall / lost time

Time during which work wanted to make progress but could not because it was waiting for a constrained resource or synchronization condition.

## Victim

A process, thread, cgroup or workload measurably delayed by a bottleneck.

"Victim" describes role in a finding, not importance.

## Suspect / likely contributor

An entity that evidence indicates may be materially contributing to contention.

This is deliberately weaker than "cause" unless direct causality can be established.

## Evidence

A recorded observation or derived metric supporting or weakening a finding.

## Finding

A user-facing diagnosis produced by the inference engine.

Examples:

- CPU scheduler contention,
- memory reclaim pressure,
- block I/O contention,
- no meaningful memory bottleneck.

## Severity

Estimated magnitude of harm/impact.

Independent from confidence.

## Confidence

Strength and completeness of evidence supporting a diagnosis or attribution.

Independent from severity.

## PSI

Linux Pressure Stall Information.

Provides CPU, memory and I/O pressure metrics, including cumulative stalled time that can be used to calculate pressure over a bounded observation interval.

## Runnable delay

Time during which a task was runnable (eligible to execute) but waiting to be scheduled on a CPU.

## Off-CPU time

Time a task is not executing on CPU.

Off-CPU time can be normal sleeping or harmful blocking; context is required.

## Utilization

Fraction of resource capacity currently or recently in use.

Utilization does not by itself measure harm.

## Saturation

A resource has more demand than it can immediately serve, causing queueing or stalls.

## Observation window

Bounded interval over which snapshots/events are collected and normalized.

## Collector

Platform-specific component that reads raw telemetry.

## Normalization

Conversion of raw cumulative counters/gauges into interval-level metrics suitable for analysis.

## Capability

A telemetry or analysis feature available on the current machine with current permissions/configuration.

## Qualifier

A limitation or contextual statement attached to a finding.

Example:

> Process-level I/O attribution is incomplete because some `/proc/<pid>/io` files were not readable.

## Recording

A versioned JSON document of normalized interval observations captured by
`record`. Replay re-runs current inference against that observation. Hunt JSON
is a diagnostic report, not a recording.

## Watch window

A rolling observation interval produced by `watch`. Consecutive windows reuse
the previous endpoint snapshot. Watch reports finding lifecycle rather than a
resource dashboard.
