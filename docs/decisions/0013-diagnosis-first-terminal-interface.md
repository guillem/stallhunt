# ADR-0013: Use a diagnosis-first terminal interface

- Status: Accepted
- Date: 2026-08-23
- Supersedes: ADR-0008's decision to defer an interactive TUI

## Context

The inference and evidence model is useful, but the default hunt renderer
repeats evidence, attribution limits, and timing for every resource. Operators
reported that this reads as a wall of text. Watch clears and rewrites plain
text but provides no navigation or on-demand explanation, leaving modern
terminals underused.

ADR-0008 deliberately deferred a TUI while diagnosis was immature. CPU,
memory, I/O, cgroup, recording/replay, lifecycle, and two evidence-chain slices
now provide a stable enough diagnostic surface to present interactively. The
product must still avoid becoming a utilization dashboard or an `htop` clone.

## Decision

Human presentation is diagnosis-first:

- `hunt` and `replay` default to a compact resource summary and bounded ranked
  findings. `--details` renders the complete evidence and explanations.
- Interactive `watch` uses an alternate-screen Ratatui/Crossterm TUI when both
  input and output are terminals and `TERM` is not `dumb`.
- The TUI prioritizes resource verdicts, finding lifecycle, attribution, and
  evidence. Sixteen compact PSI samples support trends; only the current full
  diagnosis is retained.
- `watch --plain`, redirected input/output, and `TERM=dumb` use append-only
  compact text. `watch --json` retains the existing schema-1 JSON-lines stream.
- `--no-color` and `NO_COLOR` produce monochrome human output. Words and
  symbols always carry status independently of color.
- Unlimited watch preserves first-SIGINT drain and second-SIGINT status 130.
  `q` exits an interactive watch immediately with status 0. Terminal state is
  restored before every ordinary return, error, or unwinding panic.

The presentation layer consumes existing analyzer results. It may rank,
truncate, and format them but must not derive a new resource verdict or causal
claim. Recordings, hunt JSON, watch JSON, finding identities, and inference
thresholds do not change.

Use Ratatui 0.29 and Crossterm 0.28.1. Ratatui 0.30 requires Rust 1.88, while
0.29 supports the project's Rust 1.85 baseline. Raising MSRV is not justified
by presentation work.

## Consequences

Positive:

- the normal hunt path answers the primary question in one bounded view;
- explanations remain available without making every run verbose;
- watch can expose changing diagnoses and candidates without extra collection;
- pipes and machine consumers keep explicit, noninteractive interfaces.

Costs:

- the binary gains a terminal framework and its transitive dependencies;
- alternate-screen/raw-mode lifecycle and responsive layouts need dedicated
  tests;
- watch input handling may pause briefly during the already-bounded endpoint
  collection;
- human output changes before 1.0 and must be evaluated with operators.

## Alternatives considered

### Interactive hunt and watch

Rejected for this slice. A bounded hunt should remain a classical command that
can be run, read, redirected, and copied without navigation.

### Opt-in TUI command

Rejected. Watch is explicitly the continuous operator workflow; terminal
detection and `--plain` provide a predictable compatibility boundary.

### Process-table-first dashboard

Rejected. Consumption is context, not the product's primary abstraction.
Findings, lost progress, evidence, severity, and confidence remain dominant.

### Current Ratatui release with a higher MSRV

Rejected. The UI does not require Ratatui 0.30 features, and increasing the
Rust baseline would impose an unrelated deployment cost.
