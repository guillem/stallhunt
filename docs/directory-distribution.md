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

Current official OpenAI documentation does not establish a public submission
path for bundled local stdio servers. Stallhunt deliberately does not provide
a hosted endpoint. Do not add an HTTP transport solely for directory
eligibility; use the local plugin distribution path unless OpenAI documents a
public bundled-local-server submission.

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

## Post-v0.5.1 next steps

Release v0.5.1 is published at
<https://github.com/guillem/stallhunt/releases/tag/v0.5.1>. Its tarball and
MCPB checksum sidecars verify, and its released `server.json` contains the
published MCPB digest.

### 1. Publish the official MCP Registry entry

Download `server.json` from the v0.5.1 release into an otherwise empty working
directory. Install the current official `mcp-publisher` binary using the MCP
Registry quickstart, inspect the JSON one final time, then run:

```bash
mcp-publisher login github
mcp-publisher publish
```

The GitHub-authenticated namespace must remain
`io.github.guillem/stallhunt`. Publication is immutable for that version. After
publishing, verify discovery:

```bash
curl "https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.guillem/stallhunt"
```

Official references:

- <https://modelcontextprotocol.io/registry/quickstart>
- <https://modelcontextprotocol.io/registry/package-types#mcpb-packages>

### 2. Prepare and submit the Anthropic desktop extension

Do not submit the v0.5.1 MCPB. Anthropic's current local-connector checklist
requires both the manifest `privacy_policies` array and a `Privacy Policy`
section in the bundled README. The array is present in v0.5.1, but the README
section was added to main only after the immutable release was built.

For the next patch release:

1. confirm the MCPB contains the updated README and unchanged public policy;
2. run the pinned MCPB validator and verify its SHA-256 sidecar;
3. install the exact released MCPB on compatible Linux Claude Desktop and run
   all four tools, including a bounded `run_hunt`;
4. prepare the listing name, tagline, description, categories, documentation,
   privacy/support URLs, icon, company/contact details, and setup/test steps;
5. submit through the desktop-extension form linked by Anthropic's current
   submission guide and retain the reviewer correspondence in project status.

Official reference:
<https://claude.com/docs/connectors/building/submission>.

### 3. OpenAI distribution

The repository/workspace plugin remains the supported OpenAI path. Current
official OpenAI documentation does not establish a public directory submission
flow for a bundled local stdio server. Recheck official OpenAI documentation
before each release; do not substitute a hosted server, because it would
measure the hosted machine rather than the user's Linux host.
