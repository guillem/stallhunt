# ADR-0004: Model diagnosis as evidence plus confidence, not absolute root cause

- Status: Accepted
- Date: 2026-08-17

## Context

Many performance relationships are not directly observable from coarse host telemetry.

Example:

- CPU pressure is high.
- `rustc` consumes most CPU.
- `postgres` has runnable delay.

This strongly suggests `rustc` contributes to `postgres` delay, but coarse interval data does not prove each delayed scheduling event was caused by `rustc`.

Overstating causality would make the tool misleading.

## Decision

Every diagnosis must distinguish:

- observed measurements,
- derived metrics,
- resource-level finding,
- victim attribution,
- suspect attribution,
- confidence,
- qualifiers/limitations.

Severity and confidence are separate.

Human text must use causal language appropriate to evidence strength.

## Consequences

Positive:

- more trustworthy output,
- easier incorporation of stronger future telemetry,
- missing data becomes explicit,
- users can inspect why a conclusion was reached.

Costs:

- more complex internal model,
- more verbose output design,
- scoring requires discipline.

## Alternatives considered

### Single bottleneck score

Rejected because it conflates impact and certainty.

### Always name the largest consumer as root cause

Rejected because high consumption is not proof of harmful interference.

### Raw metrics only

Rejected because automated inference is the point of the project.
