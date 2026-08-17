# ADR-0012: Stallhunt product identity

- Status: Accepted
- Date: 2026-08-18

## Context

The project reached a functionally useful v0.1 diagnostic surface under the
working title Bottleneck Finder with provisional binary names (`bottleneck`,
`bottleneck-finder`) and bootstrap CLI parsing. Before wider distribution,
several product commitments needed explicit decisions:

- final crate, package, and binary name,
- license,
- CLI framework and default invocation,
- minimum supported Rust version,
- minimum supported Linux baseline,
- JSON `kind` strings for on-disk and streaming documents.

Documentation and experiments already treat performance **bottlenecks** as the
domain concept. The product name should describe what the tool does—find stalls
and lost progress—without colliding with generic "bottleneck" language in
findings and architecture docs.

## Decision

Adopt **Stallhunt** as the product, crate, package, and binary name:

- Cargo package and binary: `stallhunt`
- Human-facing name: Stallhunt

License the project under **MIT OR Apache-2.0**, at the recipient's option.

Set **MSRV to Rust 1.85**, recorded in `Cargo.toml` as `rust-version`.

Set the **minimum supported Linux baseline to kernel 4.20+**, required for PSI
and the procfs interfaces used by the initial vertical slices.

Use **clap 4 with derive** for CLI parsing. The interface is:

- subcommands: `hunt`, `watch`, `record`, `replay`, `redact`, `capabilities`,
  `completions`, `version`
- bare `stallhunt` runs `hunt` with the default 10-second duration
- `stallhunt completions <shell>` writes shell completions to stdout

Use Stallhunt-branded JSON kinds for new documents:

- recordings: `stallhunt.recording`
- watch windows: `stallhunt.watch_window`

Replay accepts legacy recordings with `kind` `bottleneck.recording` so
existing fixtures and early captures remain analyzable. New recordings write
`stallhunt.recording` only.

Semantic references to performance **bottlenecks** in findings, architecture,
and inference docs remain unchanged; they describe the domain, not the binary
name.

## Consequences

Positive:

- one stable name across docs, binary, package managers, and JSON kinds,
- explicit license and toolchain baselines for contributors and packagers,
- installed-binary ergonomics (`stallhunt`, completions) without `cargo run`,
- legacy replay compatibility without perpetuating the old kind on write.

Costs:

- documentation and scripts must distinguish product name from domain term,
- environment variables and acceptance harness names still use historical
  `BOTTLENECK_*` prefixes until a separate migration chooses new names,
- pre-1.0 JSON hunt output and recordings still have no external compatibility
  promise beyond explicit schema versioning.

## Alternatives considered

### Keep Bottleneck Finder / `bottleneck`

Rejected: the working title was explicitly provisional, collides with generic
performance language, and is awkward as a single-word command.

### Rename domain concept to "stall" everywhere

Rejected: "bottleneck" remains accurate for resource-level findings; only the
product identity changes.

### GPL or single-license (MIT-only)

Rejected: dual MIT/Apache-2.0 matches common Rust ecosystem expectations and
keeps downstream licensing flexible.

### Pin MSRV only in CI, not in manifest

Rejected: `rust-version` documents the commitment where tooling and packagers
look first.

### Break legacy `bottleneck.recording` on replay

Rejected: the migration cost is low—accept on read, write the new kind—and early
recordings are still valuable for regression testing.
