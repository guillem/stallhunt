# ADR-0017: MCP server over stdio with a hand-rolled synchronous JSON-RPC loop

- Status: Accepted
- Date: 2026-08-25
- Amended by [ADR-0018](0018-mcp-tool-payload-detail-levels.md): the
  "structured documents unchanged" claim below now describes `detail:
  "full"`; the default tool response is deduplicated. The server, sampler,
  and tool architecture decided here are unchanged.

## Context

Coding agents have become a primary user class for performance triage: they
already run `stallhunt --json` through a shell, wait a full observation
window, and parse strings. Two gaps make that integration worse than it
needs to be. First, every question costs a full hunt duration — an agent
asking "why did that build feel slow?" pays 10 seconds per answer and can
never see a stall that ended before it asked. Second, shell invocation
loses typed discovery: nothing tells an agent which questions Stallhunt can
answer or how to ask them.

The Model Context Protocol (MCP) is the established integration surface
for agent tooling: a client (Claude Code, Claude Desktop, and other MCP
clients) spawns a server and exchanges newline-delimited JSON-RPC 2.0
messages over stdin/stdout. `docs/status.md` requires a concrete diagnostic
gap before new feature work; the gap here is the missing instant
recent-past answer, which no existing command shape can provide to a
stateless caller.

## Decision

Add a `stallhunt mcp` subcommand that serves MCP over stdio:

- **Hand-rolled synchronous server.** The transport is a blocking
  read-line → dispatch → write-line loop implemented on `serde_json` and
  `std::thread` only. No `rmcp`, no tokio, no new dependencies. The
  protocol surface is pinned to revision `2025-06-18` and limited to
  `initialize`, `notifications/initialized`, `ping`, `tools/list`, and
  `tools/call` plus JSON-RPC error responses. stdout carries protocol
  frames exclusively; diagnostics go to stderr; stdin EOF is the shutdown
  signal (no signal handler is installed).
- **A resident sampler, on by default.** A background thread re-implements
  the watch loop against the public observation seams
  (`observe::read_start_endpoint` / `read_end_endpoint` /
  `observation_from_endpoints`, `watch::signals_from_observation`,
  `WatchTracker::ingest_signals`) and stores each completed window as a
  shared snapshot. `--interval` (default 2s, same 100ms–5m bounds as
  `watch`) and `--no-sampler` configure it.
- **Four tools.** `get_current_pressure` and `get_recent_history` answer
  instantly from the sampler; `run_hunt` is the blocking one-shot deep
  dive; `get_capabilities` runs the same probes as the `capabilities`
  subcommand. Every tool result carries a text summary in `content` and
  the corresponding schema_version-2 document in `structuredContent`,
  serialized from the same structs as the CLI's JSON output — the
  presentation-purity rule holds: no surface re-derives a diagnosis.

## Consequences

- Zero new dependencies; the binary stays a single synchronous artifact.
- We own spec maintenance: protocol revision bumps and any capability we
  later opt into (resources, prompts, notifications) are ours to implement.
  The pinned version and minimal capability surface (`{"tools": {}}`)
  keep that exposure small.
- The default-on sampler adds watch-equivalent steady overhead for the
  lifetime of an MCP session. Sessions are client-managed and end with the
  client, and `--no-sampler` opts out.
- The schema_version-2 hunt, watch-window, and capabilities documents are
  now consumed verbatim by a second surface, raising the cost of breaking
  them — which ADR-0012 already treats as a contract.

## Alternatives considered

- **The official Rust MCP SDK (`rmcp`).** Rejected: it is tokio-based, and
  an async runtime for a single-client blocking pipe fails the dependency
  test ("what complexity does this remove that we would otherwise own?") —
  the whole transport is a few dozen lines of synchronous code.
- **Content-Length header framing.** Rejected as simply wrong: that is the
  Language Server Protocol's framing. MCP stdio messages are
  newline-delimited JSON.
- **An HTTP transport.** Rejected: stdio covers every current client,
  and a listening socket adds security surface ADR-0015's no-privilege
  stance would then have to reason about.
- **No resident sampler (one-shot tools only).** Rejected: it forfeits the
  motivating capability — instant answers about the recent past — and
  forces every question to block for a full observation window.
