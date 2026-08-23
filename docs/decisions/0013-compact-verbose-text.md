# ADR-0013: Compact-by-default human output with `--verbose` full detail

- Status: Accepted
- Date: 2026-08-24

## Context

User feedback on v0.1.2 found the default `hunt` text output a "wall of text":
a healthy host produced roughly forty lines dominated by qualifiers,
limitation prose, and per-resource timing sentences before any overall
verdict. The explanations it buried are genuinely valuable — they carry the
project's evidence-first, no-false-causality contract — but they were all
shown at the same volume regardless of whether anything was wrong.

The M1.6 "concise finding-first" renderer had already moved in this
direction, but per-resource sections still each printed verdict, evidence,
candidates, full qualifier lists, and timing, so total output scaled with the
number of resources rather than with the number of findings that need
explaining.

## Decision

Human `hunt`/`replay` text output is **compact by default**:

1. A one-line overall verdict (highest-severity pressured finding, an explicit
   healthy result, an explicit inconclusive result, or an explicit
   no-telemetry result).
2. A three-row resource table (CPU / Memory / I/O) with status word, severity
   when pressured, and the deciding exact-interval PSI evidence including
   cumulative stalled time.
3. Short candidate lists (at most three victims, three suspects, three
   devices, three processes) only for resources that are pressured, with the
   correlation caveats kept inline ("not confirmed harm", "not proven
   causal").
4. Scoped cgroup pressure reduced to at most three lines plus an overflow
   count; a one-line bounded-selection statement when no scoped pressure
   exists, and one line naming the capability when the cgroup observation is
   unavailable.
5. One-line related-evidence (chain) summaries when chains exist.
6. A dim footer pointing at `--verbose` for the full explanation and `--json`
   for the machine-readable report, plus one dim line of measured intervals.

`--verbose` reproduces the complete pre-redesign renderer unchanged: every
qualifier, limitation, ranked role, controller context line, and timing
sentence. JSON output is unchanged by this ADR.

The compact renderer re-formats the same analyzer findings; it never
recomputes or weakens a diagnosis, and the only content it drops relative to
verbose is prose — every evidence class (PSI fractions, stalled time,
victims, suspects, candidates, chains, scoped findings, availability limits)
retains a representation.

## Consequences

Positive:

- default output answers "is anything wrong, where, how badly" in the first
  two lines and fits on a fraction of a screen;
- healthy hosts get a genuinely compact negative result, which the product
  definition treats as a first-class feature;
- the full explanation remains one flag away and stays git-golden-covered as
  the `--verbose` renderer.

Costs:

- two text renderers must be maintained; golden fixtures now cover both;
- users who scripted the verbose text shape must add `--verbose` (JSON
  consumers are unaffected);
- compact candidate lists truncate ranked roles that verbose shows in full.

## Alternatives considered

### Keep the single verbose renderer and add `--quiet`

Rejected: the default is what every user sees first; hiding the compact view
behind a flag would preserve the complaint rather than fix it.

### Drop the verbose renderer entirely

Rejected: the qualifier prose is where the no-false-causality contract lives;
removing it would make the tool overclaim.

### Move all explanation into JSON only

Rejected: the product's primary user question ("why is this machine slow?")
deserves a complete human answer without a second tool.
