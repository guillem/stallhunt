# MCP server

`stallhunt mcp` serves Stallhunt's diagnoses to coding agents over the
Model Context Protocol. An MCP client (Claude Code, Claude Desktop, or any
other) spawns the process and exchanges newline-delimited JSON-RPC 2.0
messages over stdin/stdout. The design is recorded in
[ADR-0017](decisions/0017-mcp-server.md) and
[ADR-0018](decisions/0018-mcp-tool-payload-detail-levels.md).

## Registration

For Claude Code:

```bash
claude mcp add stallhunt -- stallhunt mcp
```

Any other MCP client is configured with `stallhunt` as the command and
`mcp` as the argument, plus optional flags:

- `--interval <DURATION>` — resident sampler window, 100ms to 5m
  (default 2s, the same bounds and parser as `stallhunt watch`).
- `--no-sampler` — disable the resident sampler; only the one-shot tools
  return live data.

Installable directory packaging is documented in
[`directory-distribution.md`](directory-distribution.md). The OpenAI plugin
and Linux MCPB both launch this same stdio command; they do not introduce a
remote Stallhunt service.

## Transport and protocol

- Protocol revision `2025-06-18`; declared capabilities are `tools` only.
- Messages are newline-delimited JSON-RPC 2.0. stdout carries protocol
  frames exclusively; diagnostics go to stderr.
- stdin EOF is the shutdown signal. The server installs no signal handler;
  the client owns the process lifetime.
- Handled methods: `initialize`, `notifications/initialized`, `ping`,
  `tools/list`, `tools/call`. Anything else receives a JSON-RPC error.
- Every tool has a human-readable title and advertises `readOnlyHint: true`,
  `destructiveHint: false`, `idempotentHint: true`, and
  `openWorldHint: false`. The tools observe local kernel interfaces but do not
  modify the machine or contact external services.

## The resident sampler

Unless `--no-sampler` is passed, a background thread samples host pressure
every interval into the same finding-lifecycle tracker that `stallhunt
watch` uses (ADR-0008), retaining up to 16 windows of history. This is the
point of the MCP surface: an agent asking "what has been constraining work
recently?" gets an instant answer that covers the recent past — including
stalls that already resolved — instead of paying a full observation window
per question.

Until the first window completes, the sampler-backed tools report
`warming_up`; with `--no-sampler` they report `disabled`. Both are ordinary
results that point the agent at `run_hunt`, not errors.

## Tools

Every tool result carries a human-readable summary in `content` and a
schema_version-2 document in `structuredContent`, built from the same
structs as the CLI's JSON output — no surface re-derives a diagnosis (see
[data-model.md](data-model.md)). `get_current_pressure` and `run_hunt`
accept a `detail` argument that chooses the projection; `get_recent_history`
does not, and always returns full lifecycle detail (see below).

- `"lean"` (default) — every field that would otherwise restate the same
  process candidates a second or third time is removed;
  `structuredContent.detail` is `"lean"` in the response so an agent can
  tell which projection it got. `process_scopes` remains the canonical
  place to read suspects and victims for the current window; a lifecycle
  entry that has resolved or gone unconfirmed *this* window keeps its
  candidates, since those are its only surviving copy (not stale = current
  and stripped; stale = kept). For `run_hunt` only, lean mode additionally
  omits raw per-process telemetry from `observation` — the flat
  `processes`, `scheduler_delay_candidates`, and `process_resource_evidence`
  arrays entirely, and only the `groups`/`members`/`processes` children of
  `cgroup`/`process_io` (their completeness fields — `cgroup.issues`,
  `process_io.capability` — are kept) — listed back under
  `observation.omitted_for_detail_lean`. Every completeness signal
  (`taskstats_capability`, `delay_accounting`, the `*_collection_issues`
  counters, PSI, `memory_context`, `diskstats`) stays intact, and a field
  that was never collected is never listed as omitted. Typically 60–80%
  smaller than `"full"`.
- `"full"` — every field of the schema_version-2 document, with the same
  content as the CLI's `--json` output. Key order is not guaranteed to
  match: the MCP path serializes through a JSON value rather than printing
  the typed struct directly.

`run_hunt`'s `structuredContent` is `{"detail", "hunt": <document>}`;
`get_current_pressure`'s is `{"detail", "sampler", "window": <document>}`.

See [ADR-0018](decisions/0018-mcp-tool-payload-detail-levels.md) for the
measurements and reasoning behind the split.

### `get_current_pressure`

Optional `detail` (`"lean"` default, `"full"`). Instant. Returns the latest
sampling window — the `stallhunt.watch_window` document with CPU, memory,
I/O, and cgroup signals, lifecycle states, and scoped process roles — plus
sampler coverage metadata (`interval_ms`, `windows_completed`,
`latest_window_at_unix_ms`).

### `get_recent_history`

No parameters. Instant. Returns the lifecycle entries and the retained
history ring (up to 16 windows) with per-window completion timestamps:
what appeared, persisted, and resolved recently — always with full
process-candidate detail, since this is the only place a resolved or
stale finding's process evidence survives.

### `run_hunt`

Optional `duration` (string, `100ms`–`5m`, default `5s`) and `detail`
(`"lean"` default, `"full"`). Blocks for the full duration — the tool
description warns agents to keep their client timeout above the requested
window. Returns the hunt document: findings, evidence chains, process
scopes, qualifiers, capabilities, and (at `detail: "full"`, or trimmed at
`"lean"`) the raw observation.

### `get_capabilities`

No parameters. Instant. Runs the same probes as `stallhunt capabilities`
and returns the schema_version-2 capabilities document. Note that
taskstats availability is not probed here; it is derived during collection
and appears inside hunt observations (ADR-0015).

## Verification

The end-to-end test (`tests/mcp.rs`) drives a real session over pipes:
handshake, tool listing, every tool family, EOF shutdown, and the framing
guarantee that every stdout line parses standalone as JSON. Server and
sampler unit tests live in `src/mcp/`.
