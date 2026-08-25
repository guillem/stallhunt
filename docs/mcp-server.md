# MCP server

`stallhunt mcp` serves Stallhunt's diagnoses to coding agents over the
Model Context Protocol. An MCP client (Claude Code, Claude Desktop, or any
other) spawns the process and exchanges newline-delimited JSON-RPC 2.0
messages over stdin/stdout. The design is recorded in
[ADR-0017](decisions/0017-mcp-server.md).

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

## Transport and protocol

- Protocol revision `2025-06-18`; declared capabilities are `tools` only.
- Messages are newline-delimited JSON-RPC 2.0. stdout carries protocol
  frames exclusively; diagnostics go to stderr.
- stdin EOF is the shutdown signal. The server installs no signal handler;
  the client owns the process lifetime.
- Handled methods: `initialize`, `notifications/initialized`, `ping`,
  `tools/list`, `tools/call`. Anything else receives a JSON-RPC error.

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

Every tool result carries a human-readable summary in `content` and the
corresponding schema_version-2 document (see
[data-model.md](data-model.md)) in `structuredContent`. Both serialize the
same structs as the CLI's JSON output; no surface re-derives a diagnosis.

### `get_current_pressure`

No parameters. Instant. Returns the latest sampling window — the
`stallhunt.watch_window` document with CPU, memory, I/O, and cgroup
signals, lifecycle states, and scoped process roles — plus sampler
coverage metadata (`interval_ms`, `windows_completed`,
`latest_window_at_unix_ms`).

### `get_recent_history`

No parameters. Instant. Returns the lifecycle entries and the retained
history ring (up to 16 windows) with per-window completion timestamps:
what appeared, persisted, and resolved recently.

### `run_hunt`

One optional parameter, `duration` (string, `100ms`–`5m`, default `5s`).
Blocks for the full duration — the tool description warns agents to keep
their client timeout above the requested window. Returns the full
schema_version-2 hunt document: findings, evidence chains, process scopes,
qualifiers, and capabilities.

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
