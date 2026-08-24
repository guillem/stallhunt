#!/usr/bin/env bash
# Opt-in real-terminal restoration check. This is intentionally separate from
# cargo test: a pseudo-terminal utility is not guaranteed in every CI image.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: tools/check-tui-pty.sh [--binary PATH]

Run one bounded text `stallhunt watch` session under `script`, then compare the
terminal settings before and after it. Requires util-linux `script`, `stty`,
`cmp`, and `grep`. It does not alter sysctls, cgroups, or workload state.
EOF
}

binary=target/debug/stallhunt
while (($#)); do
    case $1 in
        --binary)
            if (($# < 2)); then
                echo "error: --binary requires a path" >&2
                exit 2
            fi
            binary=$2
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown option '$1'" >&2
            usage >&2
            exit 2
            ;;
    esac
done

for command in script stty cmp grep mktemp; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "error: $command is required" >&2
        exit 2
    fi
done
if [[ ! -x $binary ]]; then
    echo "error: built executable not found: $binary" >&2
    exit 2
fi

scratch=$(mktemp -d "${TMPDIR:-/tmp}/stallhunt-tui-pty.XXXXXX")
cleanup() {
    local status=$?
    rm -rf "$scratch"
    exit "$status"
}
trap cleanup EXIT
before=$scratch/before
after=$scratch/after
transcript=$scratch/transcript

# `script -c` runs a shell. Quote the fixed paths and caller-selected binary
# as shell words before constructing that short command line.
printf -v quoted_binary '%q' "$binary"
printf -v quoted_before '%q' "$before"
printf -v quoted_after '%q' "$after"
command="stty -g >$quoted_before; $quoted_binary watch --interval 100ms --count 1; result=\$?; stty -g >$quoted_after; exit \$result"

# The child owns the pseudo-terminal's stdout. `script` stores that stream in
# the transcript while its outer copy is discarded so raw escape bytes never
# pollute a caller's terminal or CI log.
script -q -e -c "$command" "$transcript" >/dev/null
cmp -- "$before" "$after"
if ! LC_ALL=C grep -Fq -- $'\033[?1049h' "$transcript"; then
    echo "error: TUI alternate-screen enter sequence was not observed" >&2
    exit 1
fi
if ! LC_ALL=C grep -Fq -- $'\033[?1049l' "$transcript"; then
    echo "error: TUI alternate-screen leave sequence was not observed" >&2
    exit 1
fi
echo "TUI PTY restoration check passed"
