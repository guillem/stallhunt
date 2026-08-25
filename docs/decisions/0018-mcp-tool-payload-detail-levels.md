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

`get_current_pressure` and `run_hunt` accept a `detail` argument, `"lean"`
(default) or `"full"`. `get_recent_history` does not — see below.
`"full"` returns every field of the schema-version-2 document ADR-0017
described, with the same content as the CLI's `--json` output; key order
is not guaranteed to match, since the MCP path serializes through
`serde_json::Value` (a `BTreeMap`-backed map, alphabetically ordered)
rather than printing the typed struct directly — this crate does not take
on the `preserve_order` feature (see Alternatives). `"lean"` applies two
independent projections, implemented in `src/mcp/tools.rs` only (never
`render.rs` or `watch.rs`, which stay the single source of truth both
modes serialize from):

1. **Strip restatements, gated on whether they are actually restated.**
   Remove `process_candidates`, `process_candidate_availability`, and
   `process_role_lists` from every `ResourceSignal` in `current`
   (unconditional — a `current` entry always corresponds to a
   `process_scopes` entry for that window); remove the same two fields
   from a `TrackedFinding` in `lifecycle` only when
   `process_candidates_stale` is `false` — `true` means the finding
   resolved or went unconfirmed *this* window and is carrying its last
   confirmed candidates forward, which are therefore *not* in this
   window's `process_scopes` and would be lost outright if stripped;
   remove `victims`, `suspects`, and `process_suspects` from every hunt
   finding. `process_scopes` (and `findings`' remaining fields) are
   untouched and remain the canonical place to find suspect/victim
   processes. `get_recent_history`'s response carries lifecycle entries
   but no `process_scopes`/`window` anywhere for a stripped entry to
   point back to, so it takes no `detail` argument and never strips
   anything — there is nothing safe to remove in that tool's output.
2. **Omit raw observation telemetry, without deleting completeness data
   that lives at the same level.** For a hunt document only: drop three
   flat `observation` arrays wholesale (`processes`,
   `scheduler_delay_candidates`, `process_resource_evidence` — each has no
   completeness data mixed in; that lives in separate sibling fields).
   `cgroup` and `process_io` are different — each mixes raw per-member/
   per-process data with completeness data (`cgroup.issues`,
   `process_io.{capability,issues,regressed}`) *inside the same object*,
   so only the raw child (`cgroup.groups`, `cgroup.members`,
   `process_io.processes`) is removed, not the parent. What was actually
   present and non-null before pruning — never a field that was already
   absent because collection never ran — is recorded as a dotted-path
   list under `observation.omitted_for_detail_lean`. Every completeness
   signal ADR-0015 depends on (`taskstats_capability`, `delay_accounting`,
   the `*_collection_issues` counters, `process_resource_capability`,
   `task_stat_capability`, the PSI blocks, `memory_context`, `diskstats`,
   the `*_duration_us` scalars, and now `cgroup.issues` /
   `process_io.{capability,issues,regressed}`) is kept unchanged, so a
   lean document still supports ADR-0015's degraded-vs-complete
   reasoning. This *is* a real reduction in detail: the raw per-process
   numbers behind the verdict are gone until re-requested at
   `detail: "full"`, or durably captured via `stallhunt record` /
   `replay`.

`run_hunt`'s `structuredContent` is `{"detail": "lean"|"full", "hunt":
<document>}` rather than splicing `detail` into the document itself —
consistent with `get_current_pressure`'s `{"detail", "sampler", "window"}`
shape, and it keeps `"full"` from carrying a field the CLI's own JSON
output never has.

Measured effect on the reproduction: `get_current_pressure` 187,674 →
55,229 bytes (70.6% smaller, restatement-only). `run_hunt` 429,542 →
86,499 bytes (79.9% smaller, both projections; process_scopes 41,091 +
cgroup_findings 34,228 + findings 6,036 + a ~6,000-byte trimmed
`observation` — now keeping `cgroup.issues` and `process_io`'s
completeness fields — account for nearly all of what remains: the
residual cost of 12 individually-evidenced pressured cgroups, which this
ADR does not attempt to cap).

## Consequences

- The default MCP response an agent sees is smaller and cheaper to reason
  over, with no loss of the verdict — findings, process scopes, cgroup
  findings, capabilities, and completeness signals are all present in lean
  mode.
- `detail: "full"` keeps every field of ADR-0017's document available as
  an explicit opt-in for an agent that needs the raw evidence (e.g.
  cross-checking a specific process's numbers), so nothing is permanently
  lost — only deferred behind a parameter. The "byte-identical" wording in
  ADR-0017 is superseded: the MCP path always serializes through
  `serde_json::Value`, so key order can differ from the CLI's typed-struct
  output even at `detail: "full"` — the *content* is what matches.
- `get_current_pressure`'s lean mode is pure deduplication (case 1,
  stale-gated); a hunt's lean mode combines both cases, so its size
  reduction is larger but represents a real trade-off an agent should
  understand from the tool description, not just a compression trick.
  `get_recent_history` has no lean mode at all — its lifecycle entries are
  the one place stale/resolved findings' process evidence survives, so
  nothing there is safe to strip.
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
- **Hand-build a separate lean struct/document instead of pruning the
  already-serialized `Value`.** Rejected: embedding into MCP's
  `structuredContent` requires a `serde_json::Value` regardless (that is
  the wire format), so a second parallel struct would either duplicate
  `render.rs`'s document-building logic in `src/mcp/tools.rs` — risking
  drift between what the CLI's document contains and what the lean
  projection thinks it contains — or re-derive fields from the raw
  observation, crossing the "presentation never re-derives a diagnosis"
  line `docs/architecture.md` draws. Targeted key removal on the value
  `render.rs`/`watch.rs` already built keeps a single source of truth for
  content; the key-order side effect of going through `Value` is
  unavoidable either way and is documented above rather than hidden.
- **Drop `observation` wholesale in lean mode.** Rejected: `cgroup` and
  `process_io` are not raw-data-only — `cgroup.issues` and
  `process_io.{capability,issues,regressed}` are completeness data nested
  *inside* them, with no field anywhere else in the document to fall back
  on. Deleting the whole object would silently remove that completeness
  signal, letting a hunt with failed cgroup/process-IO collection read as
  a confident clean verdict again — the exact bug class ADR-0015 exists to
  prevent. Removing only the raw child key from each (`cgroup.groups`,
  `cgroup.members`, `process_io.processes`) keeps every completeness field
  intact while still cutting the bulk of the size.
