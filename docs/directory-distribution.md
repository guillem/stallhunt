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

## Directory publication state

Release v0.5.1 is published at
<https://github.com/guillem/stallhunt/releases/tag/v0.5.1>. Its tarball and
MCPB checksum sidecars verify, and its released `server.json` contains the
published MCPB digest.

Release v0.5.2 is published at
<https://github.com/guillem/stallhunt/releases/tag/v0.5.2>. It is the first
immutable MCPB that bundles both Anthropic-required privacy surfaces. Its
public MCPB checksum and checksum-bound `server.json` verify, the pinned MCPB
validator accepts it, and all four tools pass a real protocol session from the
downloaded bundle.

### 1. Official MCP Registry — published

On 2026-08-27, the owner published `io.github.guillem/stallhunt` v0.5.1 using
the released `server.json` and GitHub authentication. The Registry API reports
the version active and latest, and its package digest matches the released
MCPB. The publication commands were:

```bash
mcp-publisher login github
mcp-publisher publish
```

The GitHub-authenticated namespace remains `io.github.guillem/stallhunt`.
Verify discovery with:

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

Release v0.5.2 is the first artifact that bundles both required privacy
surfaces. Before submission:

1. confirm the MCPB contains the updated README and unchanged public policy
   (complete for v0.5.2);
2. run the pinned MCPB validator and verify its SHA-256 sidecar (complete for
   v0.5.2);
3. install the exact released MCPB on compatible Claude Desktop and run
   all four tools, including a bounded `run_hunt` (complete for v0.5.2 on
   Bazzite Claude Desktop);
4. prepare the listing name, tagline, description, categories, documentation,
   privacy/support URLs, icon, company/contact details, and setup/test steps
   (the non-personal packet below is complete);
5. submit through the desktop-extension form linked by Anthropic's current
   submission guide and retain the reviewer correspondence in project status.

Official reference:
<https://claude.com/docs/connectors/building/submission>.

On Bazzite/KDE, do not use generic `xdg-open` for this check unless the user has
explicitly associated `.mcpb` with Claude: the default ZIP association opens
Ark. Invoke Claude Desktop with the MCPB path directly. The Linux AppImage used
for the initial v0.5.2 check recognized the path in its DXT/MCPB handler, but
installation still requires the user-facing confirmation dialog and must not be
reported complete until Claude lists and runs the extension.

#### Anthropic submission packet

Use the exact immutable artifact and metadata below. Do not substitute a local
candidate build.

- **Connector type:** Desktop extension (MCPB)
- **Artifact:**
  `https://github.com/guillem/stallhunt/releases/download/v0.5.2/stallhunt-0.5.2-x86_64-unknown-linux-gnu.mcpb`
- **SHA-256:**
  `f157469d399261d8373b43753e2b6c71284ce2637c0027814c7dd2e28407871f`
- **Name:** Stallhunt
- **Tagline:** Find what is stalling this Linux host.
- **Description:** Stallhunt diagnoses CPU scheduling, memory, block-I/O, and
  cgroup contention on the local Linux machine. It reports whether meaningful
  pressure exists, which workloads are likely suffering or contributing, how
  much progress is being lost, the evidence supporting each finding, and the
  confidence and limitations of every attribution. It is read-only, runs
  locally without elevated privileges or authentication, and does not transmit
  telemetry independently.
- **Documentation:**
  `https://github.com/guillem/stallhunt/blob/main/docs/mcp-server.md`
- **Privacy policy:**
  `https://github.com/guillem/stallhunt/blob/main/PRIVACY.md`
- **Terms:** `https://github.com/guillem/stallhunt/blob/main/TERMS.md`
- **Support:** `https://github.com/guillem/stallhunt/issues`
- **Website/source:** `https://github.com/guillem/stallhunt`
- **Icon:** `assets/stallhunt-icon-512.png` (512x512 transparent PNG)
- **Access:** Read-only; no write actions, external links, authentication, test
  account, health data, sponsored content, or third-party API proxying.
- **Compatibility disclosure:** Linux x86-64 GNU; Linux 4.20 or newer with
  readable procfs/PSI. Older-glibc compatibility is not defined.
- **Setup:** Download the MCPB, open it directly with Claude Desktop, review the
  unsigned local-extension warning and declared read-only tools, then allow and
  enable Stallhunt. On Bazzite/KDE invoke the Claude AppImage with the MCPB path
  directly if the desktop ZIP association sends generic open actions to Ark.

Suggested test prompts, one per tool:

1. `Use Stallhunt get_capabilities and explain which Linux telemetry is available.`
2. `Use Stallhunt get_current_pressure and summarize current contention.`
3. `Use Stallhunt get_recent_history and describe any recent or resolved pressure.`
4. `Use Stallhunt run_hunt for one second with lean detail and explain the evidence.`

The v0.5.2 Bazzite/Claude Desktop run completed all four prompts successfully.
Claude's MCP log recorded four new `tools/call` requests and four results with
no errors; the final call took about 1.17 seconds, consistent with the requested
one-second hunt.

Select the closest one to five developer/system-administration categories
offered by the live form. The owner must supply and verify the publisher/company
name, website association, primary contact name/email, and any requested support
email. The owner must personally review and accept the directory terms, policy,
and compliance attestations; repository metadata cannot answer those on the
owner's behalf.

### 3. OpenAI distribution

The repository/workspace plugin remains the supported OpenAI path. OpenAI now
documents public submission for MCP-backed plugins, but requires a publicly
hosted domain and explicitly excludes local/testing endpoints from review;
development tunnels are for testing only. Recheck official OpenAI documentation
before each release, but do not substitute a hosted server, because it would
measure the hosted machine rather than the user's Linux host.
