# ADR-0019: Distribute Stallhunt as a local MCP server

- Status: Accepted
- Date: 2026-08-26

## Context

OpenAI, Anthropic, and the official MCP Registry provide discovery and
installation surfaces for MCP integrations. Stallhunt is useful to those
clients only when it observes the same Linux host whose performance the user is
investigating.

A public Streamable HTTP service would instead collect telemetry from the
service host. Forwarding arbitrary customer host telemetry to such a service
would add authentication, tenancy, privacy, network, and privilege boundaries
without improving the local diagnosis. ADR-0017 already selected stdio and
rejected an HTTP listener for the initial server.

## Decision

Keep `stallhunt mcp` local and distribute it through installable packages:

- an OpenAI plugin whose `.mcp.json` invokes `stallhunt mcp`;
- a Linux MCPB binary extension for compatible clients and the Anthropic
  Connectors Directory;
- official MCP Registry metadata pointing to the public, checksummed MCPB
  release artifact.

Directory packages reuse the existing binary and MCP protocol implementation.
They do not add a daemon, socket, remote collector, account system, OAuth flow,
or telemetry transmission. All tools advertise accurate titles and read-only,
non-destructive, idempotent, closed-world annotations.

The MCPB checksum is rendered into `server.json` only after the artifact is
built. Registry publication and vendor-directory submissions remain explicit
owner actions because they create externally reviewed, persistent listings.

## Consequences

- The integration diagnoses the user's host and preserves Stallhunt's offline,
  no-elevation trust model.
- The same MCPB can feed Anthropic's local extension path and the vendor-neutral
  Registry instead of maintaining two native package formats.
- OpenAI repository/workspace plugins work locally, but the public universal
  directory remains unavailable while its form requires a public MCP URL.
- Binary MCPBs are platform-specific. The first package matches the existing
  `x86_64-unknown-linux-gnu` release; arm64 and libc portability remain future
  delivery work.
- Public privacy, terms, support, artwork, and tool metadata become release
  inputs and must remain accurate.

## Implementation outcome (2026-08-27)

The Linux MCPB remains useful for compatible clients and the vendor-neutral MCP
Registry, but the assumption that it could also be listed in Anthropic's
Connectors Directory was disproved during submission. Anthropic's official MCPB
builder guide limits Claude Desktop extensions to macOS and Windows and
requires testing on both platforms. Stallhunt must not submit its Linux-only
artifact through that form. This does not change the local-stdio decision: a
macOS/Windows or hosted substitute would not diagnose the target Linux host.

## Alternatives considered

- **Add Streamable HTTP for public-directory eligibility.** Rejected: a remote
  deployment measures the wrong machine, while a local listener adds security
  surface without solving distribution.
- **Publish only an installation guide.** Rejected: it preserves manual setup
  and does not provide verifiable package metadata to directories.
- **Publish the Cargo crate as the Registry artifact.** Deferred: crates.io
  publication is permanent, the crate is currently `publish = false`, and MCPB
  also serves the Anthropic packaging path.
