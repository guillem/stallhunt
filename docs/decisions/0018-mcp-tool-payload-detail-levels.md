# ADR-0018: MCP tool payloads default to a deduplicated "lean" projection

- Status: Accepted
- Date: 2026-08-25

## Context

ADR-0017 committed to embedding stallhunt's existing schema-version-2
documents in MCP tool results "unchanged." In real use against
`fake_workload.sh`'s CPU-oversubscription phase — the same scenario the
script exists to simulate — `get_current_pressure` returned a 187,674-byte
`structuredContent` payload for a single sampling window, and `run_hunt`
returned 429,542 bytes for a 2-second observation. Both were large enough
to visibly slow down and clutter an agent's reasoning over what should be a
quick pressure check.

Measurement (captured against the live payload, reproduced with a
synthetic fixture in `src/mcp/tools.rs`'s test suite) found two distinct
causes, not one:

1. **Restatement.** System-wide CPU pressure cascades up the entire cgroup
   ancestry (root, `user.slice`, `user-N.slice`, `user@N.service`,
   `app.slice`, each running application's scope, each tab's scope — 12
   pressured cgroups in the reproduction). For every pressured resource,
   the *same* candidate-process evidence is serialized three times: once in
   `window.current.{cpu,memory,io}` / `current.cgroups[*]` (as
   `ResourceSignal.process_candidates` /
   `process_candidate_availability` / `process_role_lists` — fields
   `WindowSignals.process_scopes`'s doc comment already calls "legacy...
   for compatibility only"), once in `window.lifecycle[*]`
   (`TrackedFinding.process_candidates` / `process_role_lists`), and once
   in `window.process_scopes` (the canonical, correctly-scoped view). A
   hunt's `findings[].victims` / `.suspects` / `.process_suspects`
   duplicate the same host-scope candidates a second time against
   `process_scopes[0]`. This is pure duplication: `process_scopes`
   (respectively `findings`) already carries every one of these candidates
   in the intended shape.
2. **Raw telemetry.** A hunt's `observation` field carries the full
   normalized snapshot the analyzer consumed: every process's raw CPU
   ticks, IO byte counters, scheduling-delay numbers, and the raw cgroup
   tree — 347,202 of the reproduction's 429,542 bytes. `findings`,
   `process_scopes`, and `cgroup_findings` already report the analyzer's
   *verdict* on this data; an agent asking "what's slow" needs the verdict,
   not the inputs that produced it. This is not deduplication — the
   information is genuinely absent afterward — so it needs an explicit
   trade-off, not a free cut.

## Decision

Every MCP tool that can return this cascade (`get_current_pressure`,
`get_recent_history`, `run_hunt`) accepts a `detail` argument, `"lean"`
(default) or `"full"`. `"full"` returns the exact schema-version-2 document
ADR-0017 described — byte-identical to what the CLI's `--json` output would
produce from the same observation. `"lean"` applies two independent
projections, implemented in `src/mcp/tools.rs` only (never `render.rs` or
`watch.rs`, which stay the single source of truth both modes serialize
from):

1. **Strip restatements.** Remove `process_candidates`,
   `process_candidate_availability`, and `process_role_lists` from every
   `ResourceSignal` in `current`; remove `process_candidates` and
   `process_role_lists` from every `TrackedFinding` in `lifecycle`; remove
   `victims`, `suspects`, and `process_suspects` from every hunt finding.
   `process_scopes` (and `findings`' remaining fields) are untouched and
   remain the canonical place to find suspect/victim processes. Every
   field this drops is a byte-for-byte restatement already present
   elsewhere in the same document, so this loses no information.
2. **Omit raw observation telemetry.** For a hunt document only, remove
   five `observation` keys — `cgroup`, `process_resource_evidence`,
   `scheduler_delay_candidates`, `processes`, `process_io` — that carry
   per-process/per-cgroup raw numbers, and record which keys were removed
   under a new `observation.omitted_for_detail_lean` array. Every
   completeness signal ADR-0015 depends on — `taskstats_capability`,
   `delay_accounting`, the `*_collection_issues` counters,
   `process_resource_capability`, `task_stat_capability`, the PSI blocks,
   `memory_context`, `diskstats`, and the `*_duration_us` scalars — is kept
   unchanged, so a lean document still supports ADR-0015's degraded-vs-
   complete reasoning. This *is* a real reduction in detail: the raw
   per-process numbers behind the verdict are gone until re-requested at
   `detail: "full"`, or durably captured via `stallhunt record` /
   `replay`.

Measured effect on the reproduction: `get_current_pressure` 187,674 →
55,229 bytes (70.6% smaller, restatement-only). `run_hunt` 429,542 →
85,707 bytes (80.0% smaller, both projections; process_scopes 41,091 +
cgroup_findings 34,228 + findings 6,036 + a ~5,200-byte trimmed
`observation` account for nearly all of what remains — the residual
cost of 12 individually-evidenced pressured cgroups, which this ADR does
not attempt to cap).

## Consequences

- The default MCP response an agent sees is smaller and cheaper to reason
  over, with no loss of the verdict — findings, process scopes, cgroup
  findings, capabilities, and completeness signals are all present in lean
  mode.
- `detail: "full"` keeps ADR-0017's byte-identical promise available as an
  explicit opt-in for an agent that needs the raw evidence (e.g. cross-
  checking a specific process's numbers), so nothing is permanently lost —
  only deferred behind a parameter.
- `get_recent_history` and `get_current_pressure`'s lean mode is pure
  deduplication (case 1 only); a hunt's lean mode combines both cases, so
  its size reduction is larger but represents a real trade-off an agent
  should understand from the tool description, not just a compression
  trick.
- The remaining lean-mode cost for a hunt under wide cgroup pressure is
  still driven by `process_scopes` and `cgroup_findings` growing linearly
  with the number of pressured cgroup levels; this ADR intentionally does
  not cap or deduplicate across cascading ancestor cgroups (e.g. collapsing
  `user.slice` and `user-1000.slice` when they report the same suspects) —
  that would be a real information trade-off of its own and needs its own
  decision if it becomes the next bottleneck.

## Alternatives considered

- **Hard-coded truncation instead of a parameter.** Rejected: it would
  retract ADR-0017's "unchanged" promise outright rather than keep it
  available as `detail: "full"`, and an agent has no way to ask for more
  evidence when the lean summary is not enough.
- **Route documents through `serde_json::Value` and reorder/rebuild them
  wholesale.** Rejected: risks silently reordering the stable
  schema-version-2 key order (`serde_json::Value`'s map is unordered
  without the `preserve_order` feature, which this crate does not take on)
  and would blur the line between "presentation" (allowed in
  `src/mcp/tools.rs`) and "re-deriving a diagnosis" (not allowed anywhere
  outside `render.rs`/`watch.rs`, per `docs/architecture.md`'s
  presentation-purity rule). Targeted key removal on the already-built
  document value avoids both risks.
- **Drop `observation` wholesale in lean mode.** Rejected: it is the only
  place an MCP client can see `taskstats_capability` and the
  `*_collection_issues` counters — deleting it would silently remove the
  completeness signal ADR-0015 was built to make visible, letting a hunt
  with zero taskstats evidence read as a confident clean verdict again.
  Keying the omission to five specific arrays keeps every completeness
  field intact.
