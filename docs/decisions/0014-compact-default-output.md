# ADR-0014: Compact human output by default, explanations on request

- Status: Accepted
- Date: 2026-08-23

## Context

The v0.1.x default `hunt` text prints a full explanation for every resource:
verdict line, evidence line, candidate lists, qualifiers, and timing. Each
piece is individually justified, but together they overwhelm the one question
an operator asks first: "is anything contending, and where?" Field feedback
calls the default mode a wall of text, while also noting that the explanatory
lines (correlation caveats, capability limits, mechanism context) are the
tool's most valuable insight and should not be deleted.

Human output may evolve freely before 1.0 (stable output policy in
`docs/cli-ux.md`), so this is the right moment to change the default. JSON is
the full structured-evidence interface and must not change shape because of a
presentation choice.

## Decision

Default human output is **compact and verdict-first**. Full explanations are
available **on request** via `--explain`.

- `stallhunt` / `stallhunt hunt` / `stallhunt replay` print a compact report:
  - a one-line headline derived from the ranked findings
    (contention detected / no significant contention / inconclusive or
    unavailable assessment, with observation duration);
  - one line per host resource with verdict word, severity, and exact-interval
    PSI `some`;
  - for contention findings, the leading victim and suspect candidates, still
    labeled as observed-delay and same-window-correlation respectively;
  - prominent scoped cgroup pressure, one line per scope;
  - one line per evidence-chain relation, with its confidence;
  - a footer pointing at `--explain` and `--json`.
- `hunt --explain` and `replay --explain` print the full explanatory report:
  the v0.1.x text with evidence lines, candidate lists, context and
  limitations, capability notes, and timing. Nothing is removed from the
  detailed path.
- `--json` is unaffected: it remains the complete structured-evidence surface
  and has no verbosity switch.
- Watch: the TUI detail pane (`e`) shows the full per-finding summaries for
  the current window; classic watch text and the `stallhunt.watch_window`
  JSON stream are unchanged.
- Compact output keeps the causality guardrails of ADR-0004: victims are
  "observed delay, not confirmed harm", suspects are "same window, not proven
  causal", chain relations say "consistent with", and unavailable telemetry is
  reported as unavailable rather than omitted silently.
- Compact output never introduces claims, thresholds, or categories that do
  not exist in the analysis layer. It is a projection, not a second analysis.

## Consequences

Positive:

- the default answer fits in a glance and in narrow terminals;
- the detailed explanation survives verbatim behind `--explain`, so muscle
  memory, docs, and support workflows keep working;
- scripts that parse the detailed text can add one flag instead of pinning an
  old release;
- recordings replayed later inherit both verbosity levels automatically.

Costs:

- any downstream scraper of the v0.1.x default text must switch to
  `--explain` or `--json` (pre-1.0 output has no compatibility promise);
- two text layouts must be maintained and fixture-tested;
- the compact projection must be reviewed each time a new finding dimension
  appears so it stays honest.

## Alternatives considered

### Keep one verbosity and add a pager

Rejected: the problem is density, not length. Paging the same report does not
answer the first question faster.

### Delete the explanatory lines from the default

Rejected: the correlation/capability caveats are the difference between
diagnosis and a dashboard. They move behind `--explain` intact.

### Express verbosity as `--verbose`/`-v`

Considered. `--explain` was chosen because the flag adds explanations rather
than diagnostic-log noise; `--verbose` is reserved for future collector or
debug context, as anticipated in `docs/cli-ux.md`.
