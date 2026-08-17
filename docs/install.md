# Install

Stallhunt ships as a single `stallhunt` binary. It is Linux-only.

## Requirements

| Component | Minimum |
|---|---|
| Linux kernel | 4.20+ |
| procfs | mounted at `/proc` |
| PSI | readable under `/proc/pressure/{cpu,memory,io}` for pressure verdicts |
| Rust (source builds) | 1.85+ |

Most features work as an ordinary user. Some per-process or cgroup paths may be unreadable without matching permissions; the tool reports those limits through `capabilities` and collection qualifiers rather than failing silently.

## Install from source

From a clone of this repository:

```bash
cargo install --path .
```

This builds the release profile and installs `stallhunt` into Cargo's bin directory (typically `~/.cargo/bin`). Ensure that directory is on your `PATH`.

To build without installing:

```bash
cargo build --release --locked
./target/release/stallhunt
```

For day-to-day development, use the same locked build and test commands documented in [`development.md`](development.md).

## Release tarballs

Pre-built release tarballs, when published, contain:

- the `stallhunt` binary for a specific `x86_64-unknown-linux-gnu` target,
- `LICENSE-MIT` and `LICENSE-APACHE`,
- a short README with version and checksum.

Extract and place the binary on your `PATH`:

```bash
tar xzf stallhunt-<version>-x86_64-unknown-linux-gnu.tar.gz
install -m 0755 stallhunt-<version>-x86_64-unknown-linux-gnu/stallhunt ~/.local/bin/stallhunt
```

Verify the published SHA-256 checksum before use. Download release tarballs from the [GitHub Releases](https://github.com/guillem/stallhunt/releases) page for tagged versions such as `v0.1.0`.

## Shell completions

After install:

```bash
stallhunt completions bash > ~/.local/share/bash-completion/completions/stallhunt
stallhunt completions zsh > ~/.local/share/zsh/site-functions/_stallhunt
stallhunt completions fish > ~/.config/fish/completions/stallhunt.fish
```

Reload the shell or follow your distribution's completion install conventions.

## Support matrix

| Environment | Support |
|---|---|
| Linux 4.20+ with PSI | supported baseline |
| Linux without PSI | installs; pressure verdicts unavailable |
| Non-Linux | out of scope |
| Rust 1.85+ | required for source builds |
| Rust < 1.85 | unsupported |
| `x86_64-unknown-linux-gnu` | primary target |
| Other Linux architectures | best-effort source builds; not CI-gated yet |
| Root / sudo | not required for baseline collection |
| eBPF | not required |

## Quick verification

```bash
stallhunt version
stallhunt capabilities
stallhunt
```

Bare `stallhunt` runs the default 10-second hunt. Use `stallhunt hunt --duration 1s --json` for a short telemetry smoke check.

## Uninstall

If installed with Cargo:

```bash
cargo uninstall stallhunt
```

Remove any manually installed completion files.
