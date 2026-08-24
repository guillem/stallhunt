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

Published release tarballs currently contain:

- the `stallhunt` binary for a specific `x86_64-unknown-linux-gnu` target,
- `LICENSE-MIT` and `LICENSE-APACHE`,
- the project `README.md`,
- the `stallhunt.1` manual page.

Each tarball has a separate `.sha256` checksum asset. The binary is built on a
GitHub-hosted Ubuntu runner; the Linux 4.20 kernel baseline does not by itself
guarantee compatibility with older glibc userspaces.

Extract and place the binary on your `PATH`:

```bash
tar xzf stallhunt-<version>-x86_64-unknown-linux-gnu.tar.gz
install -m 0755 stallhunt-<version>-x86_64-unknown-linux-gnu/stallhunt ~/.local/bin/stallhunt
```

Verify a published SHA-256 checksum before use. For the prepared v0.4.0
release, once it is published:

```bash
sha256sum -c stallhunt-0.4.0-x86_64-unknown-linux-gnu.tar.gz.sha256
```

Download release tarballs from the
[GitHub Releases](https://github.com/guillem/stallhunt/releases) page; the
currently published release is `v0.3.0`. Version `v0.4.0` is prepared in this
source tree but is not published until its controlled-host release gates pass
and the dependency-audit warnings have a reviewed disposition.

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
| `x86_64-unknown-linux-gnu` | published tarball; older-glibc compatibility is undefined |
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
