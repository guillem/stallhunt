# MCP directory distribution

Stallhunt is a local Linux diagnostic. Directory packaging must preserve that
property: an internet-hosted Stallhunt server would observe its own host rather
than the user's machine and would answer the wrong diagnostic question.

ADR-0019 therefore defines three distribution surfaces over the same stdio MCP
server:

- an OpenAI repository/local plugin under `plugins/stallhunt/`;
- an MCP Bundle (MCPB) desktop extension assembled from
  `distribution/mcpb/manifest.json` and the release binary;
- official MCP Registry metadata rendered from
  `distribution/mcp-registry/server.json.in` after the MCPB checksum exists.

None of these packages changes telemetry collection, inference, or tool
results. They only install and launch `stallhunt mcp`.

## OpenAI plugin

The plugin manifest is `plugins/stallhunt/.codex-plugin/plugin.json`; its
`.mcp.json` launches the installed `stallhunt` command with the `mcp` argument.
The repository plugin therefore requires Stallhunt to already be installed and
on `PATH`. It is suitable for repository, personal, or workspace distribution.

OpenAI's universal public directory currently asks MCP-backed submissions for
a public server URL. Stallhunt deliberately does not provide one. Do not add an
HTTP transport solely to satisfy that form; use the local plugin distribution
path unless OpenAI adds public bundled-local-server submission.

Validate the plugin with the `validate_plugin.py` command supplied by the
installed OpenAI plugin-creator tooling. The repository's deterministic
manifest and asset checks also run with `cargo test --test distribution`.

## MCPB desktop extension

The release workflow packages the Linux x86-64 release binary as:

```text
stallhunt-<version>-x86_64-unknown-linux-gnu.mcpb
```

The bundle is local-only, uses stdio, needs no authentication, and declares
Linux compatibility. Build it from a release binary with:

```bash
tools/package-mcpb.sh --binary target/release/stallhunt --output-dir dist
```

The current artifact inherits the release binary's limitations: x86-64 GNU
Linux only and no defined old-glibc compatibility. Add Linux arm64 and an
explicit libc baseline before claiming broader platform support.

## Official MCP Registry

The Registry stores metadata, not the binary. After building the MCPB, render a
concrete `server.json` containing its immutable SHA-256 digest:

```bash
tools/render-mcp-registry-metadata.sh \
  --artifact dist/stallhunt-0.5.1-x86_64-unknown-linux-gnu.mcpb \
  --output dist/server.json
```

The release workflow performs both steps and uploads the MCPB, checksum, and
rendered `server.json` beside the normal tarball. Publishing the metadata with
`mcp-publisher` is intentionally a separate owner-authorized action because a
published Registry version is immutable external state.

## Directory review material

The shared public review material is:

- `PRIVACY.md` — local telemetry, client transmission boundary, recording, and
  retention disclosures;
- `TERMS.md` — license, warranty, authorization, and diagnostic limitations;
- `assets/stallhunt-icon.png` — original transparent directory artwork;
- `assets/stallhunt-icon-512.png` — MCPB-sized derivative;
- MCP tool titles and read-only, non-destructive, closed-world annotations.

Before submission, the owner must verify the publisher identity and public
URLs in each portal, prepare portal-specific screenshots if requested, and run
the documented test prompts on the packaged artifact.
