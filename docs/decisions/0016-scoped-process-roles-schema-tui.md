# ADR-0016: Scope process roles, adopt schema 2, and use a responsive attribution TUI

- Status: Accepted
- Date: 2026-08-24

## Context

ADR-0014 added a limited set of host process candidates to watch schema 1.
It explicitly left memory roles, I/O victims, and cgroup process roles
unsupported. That additive contract is no longer sufficient for a complete,
consistent model: host and cgroup pressure each need six independently ranked
lists, source-specific evidence, explicit availability/completeness, and a
clear replay migration path.

The existing TUI is optimized for narrow terminal layouts. It cannot show the
full bounded attribution set alongside lifecycle, current state, history, and
detail on a sufficiently large terminal. A wider presentation must preserve the
finding-lifecycle focus established by ADR-0013 rather than becoming a resource
utilization dashboard.

## Decision

The analyzer owns scoped process attribution. It defines `ProcessScope`, the
six-value `ProcessRole`, `ProcessRoleList`, typed availability/completeness,
and tagged `ProcessCandidateEvidence`; watch and renderers only transport or
format those results. The six roles are CPU, memory, and I/O victims and
suspects. Each role retains at most five candidates, ranked deterministically
with stable `ProcessKey` tie-breaking. Direct evidence precedes heuristic
fallback.

Run the same pure role builders independently for host PSI and for every
cgroup's own PSI. A cgroup scope admits stable direct or descendant members
matched by `ProcessKey`; cgroup candidates are not removed from host findings.
Ancestor and descendant findings may legitimately repeat a process and must
never be summed.

Roles are assessed only when their scope has PSI-backed pressure:

- CPU victims use schedstat runnable delay, with taskstats CPU delay as
  corroboration or fallback; CPU suspects require the existing threshold of at
  least 25% of one CPU.
- Memory victims use taskstats memory-delay components, with major faults only
  as a low-confidence fallback; memory suspects require strictly positive RSS
  growth, and static RSS alone never qualifies.
- I/O victims use taskstats block-I/O delay, with procfs block-I/O delay as
  fallback or corroboration; I/O suspects use the existing positive process-I/O
  accounting rule.

Candidate confidence is separate from the resource confidence. Major faults
and RSS growth are always Low. Procfs I/O delay and CPU/I/O suspects are at
most Medium. Complete direct evidence may reach the resource confidence.
General collection gaps make the relevant role list partial without weakening
unrelated valid candidates. Existing device candidates, cgroup members,
findings, evidence, qualifiers, and causal caveats remain; candidates are
evidence-backed correlation, not proof of causality.

All CLI JSON documents move to schema version 2. Hunt and watch JSON expose a
canonical `process_scopes` collection containing all six role lists for each
host/cgroup scope, while retaining current document kinds and existing
candidate/evidence fields. New recordings use schema 2 and continue to record
normalized observations—not derived candidates—so replay runs the current
analyzer. Replay and redaction accept schema versions 1 and 2 and reject all
others. A schema-1 recording preserves the CPU/I/O attribution it contains;
new evidence is explicitly unavailable. Redaction covers every new process
name and scoped identifier while preserving the input recording version.

All human surfaces carry the same analyzer-owned roles: legacy hunt/replay
text, compact TTY reports, piped watch text, selected detail, and the TUI show
all six role lists or an explicit empty/unavailable state. Confirmed lifecycle
findings replace their lists with the current window's scoped results.
Unconfirmed persistent and resolved findings retain the last confirmed lists
only when they are labeled stale or `last observed`; renderers never present
retained attribution as current evidence.

The TUI switches layout at 120 columns by 30 rows or larger. Wide mode splits
the body approximately 55%/45%: Lifecycle, Current, History, and scrollable
Detail remain visible on the left, and the right shows a CPU/Memory/I/O by
Victim/Suspect two-column, three-row grid. Every grid cell displays all five
retained candidates or an explicit unavailable/empty state. The grid follows
the selected host or cgroup scope and labels that scope clearly. Stale data is
matched by both scope and resource identity, not merely a selected resource
row.

Detail visibility has `automatic`, `explicitly shown`, and `explicitly hidden`
preferences. Automatic behavior follows responsive layout defaults; user
preferences survive resize. Detail supports PageUp/PageDown and Home/End
scrolling. Compact mode defaults Detail to collapsed, shows six role
counts/top summaries, can replace Current/History only when explicitly
expanded, and retains navigation to full candidate and detail content.

This supersedes the affected compatibility and attribution portions of
ADR-0007 (schema-1-only recordings without a compatibility promise), ADR-0013
(the fixed earlier TUI layout), and ADR-0014 (additive schema-1 watch process
attribution). Their accepted recording-as-normalized-observations,
finding-lifecycle/non-dashboard, and cautious-causality principles remain in
force. Those accepted ADRs are preserved as historical decisions.

## Consequences

Positive:

- every PSI-backed host or cgroup finding has one consistent, bounded process
  attribution surface;
- JSON consumers and recordings receive an explicit schema migration rather
  than a silent expansion of schema 1;
- wide terminals show complete scoped attribution without hiding lifecycle or
  detail, while narrow terminals remain usable.

Costs:

- consumers must support schema 2 and recording readers must retain a bounded
  schema-1 migration path;
- role availability, collection completeness, stale lifecycle state, and
  responsive layout substantially expand fixture and renderer coverage;
- repeated candidates across host and overlapping cgroup scopes require clear
  labels so users do not interpret them as additive delay.

## Alternatives considered

### Keep additive schema 1 fields

Rejected: six scoped role lists and their availability semantics change the
document contract enough to require an explicit schema version.

### Let watch or renderers build their own role lists

Rejected: duplicated ranking would allow incompatible causal language or stale
candidate handling across hunt, replay, watch, and the TUI.

### Show only a single top candidate per role

Rejected: the bounded five-candidate lists are useful triage evidence, and a
wide terminal has space to show the complete retained set simultaneously.

### Replace the TUI with a utilization dashboard

Rejected: it would reopen the non-goal rejected by ADR-0008 and ADR-0013;
the UI continues to present finding lifecycle and evidence.
