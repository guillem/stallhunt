# ADR-0014: Implicit hunt options and watch process attribution

- Status: Accepted
- Date: 2026-08-24

## Context

ADR-0012 made bare `stallhunt` an alias for the default `hunt`, but its root
parser did not accept the useful `hunt` options. Users could write
`stallhunt hunt --json`, but not the equivalent `stallhunt --json`; some root
flags were also easy to overlook when an explicit subcommand followed.

ADR-0008 deliberately made watch a compact finding-lifecycle stream and
omitted victims, suspects, and raw evidence. ADR-0013 retained that contract
when it added the TUI. The analyzers now have bounded, typed same-window process
attribution that is useful in every watch surface, but presenting it must not
overstate correlation or make stale lifecycle data look current.

## Decision

Bare `stallhunt` is a complete implicit `hunt`. At the command root it accepts
`--duration`, `--json`, `--verbose`, and `--no-color`, with the same defaults
and meaning as the explicit `hunt` subcommand. These root options conflict with
an explicit subcommand, so an invocation such as `stallhunt --json
capabilities` is rejected with CLI exit status 2 instead of being ignored.
Root help and generated shell completions expose these options.

Watch JSON keeps `schema_version: 1` and gains additive typed process candidates
on current signals and lifecycle findings. Supported roles are:

- CPU victims: runnable-delay evidence;
- CPU suspects: same-window CPU-consumption evidence;
- I/O suspects: same-window process-I/O evidence.

Candidates carry the stable process key, name, role, confidence, analyzer
label, and typed evidence. I/O victims, and process roles for memory or cgroup
findings, remain explicitly unsupported. Every watch renderer contains an
attribution area with clear empty or unavailable states.
Process names are measured in terminal display columns, not Unicode scalar
values, so wide names cannot displace evidence or confidence. The existing
transitive `unicode-width` crate becomes a direct dependency for that bounded
rendering calculation.

Confirmed persistent findings replace their candidates with the current
window's candidates. Unconfirmed persistent and resolved findings retain the
last confirmed candidates only with an explicit `last observed`/stale label.
Candidates remain evidence-backed correlation, never proof that one process
caused another to stall.

This supersedes the presentation and compatibility portions of ADR-0008 that
said watch JSON omits victims and suspects, and ADR-0013's statement that the
watch JSON stream is unchanged. Their lifecycle model, bounded history,
TTY-versus-pipe dispatch, and non-dashboard intent remain accepted.

## Consequences

Users can choose terse root invocations without losing hunt controls, while
ambiguous mixed invocations fail early. Scripts receive additive process data
without a schema-version bump during the pre-1.0 period, and must tolerate its
absence from older producers. Watch becomes more useful for triage but remains
conservative about causality and historical data.

## Alternatives considered

### Keep root invocation optionless

Rejected because an alias that cannot express `hunt`'s normal controls is
surprising and encourages inconsistent examples.

### Add an independent watch attribution model

Rejected because it would duplicate analyzer ranking and risk renderer-specific
causal claims. Watch transports the existing typed candidates instead.

### Bump the watch schema version

Rejected for this additive pre-1.0 field. Consumers already need to tolerate
evolving fields; changing an existing field's meaning would require a version
bump or a later compatibility decision.
