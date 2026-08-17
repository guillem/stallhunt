#!/usr/bin/env bash
# Rootless, opt-in observer-overhead harness. It measures the built binary,
# never Cargo, and intentionally does not serve as a CI performance gate.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: tools/measure-overhead.sh [options]

Measure a pre-built bottleneck binary across bounded scenarios. Results are
environment-dependent; record ranges, not pass/fail thresholds.

Options:
  --binary PATH       Built bottleneck executable (default: target/debug/bottleneck)
  --duration SECONDS  Hunt duration, integer 1..30 (default: 2)
  --repetitions N     Repetitions per scenario, integer 1..10 (default: 3)
  --max-workers N     CPU workers/process helpers, integer 1..8 (default: 4)
  --cpu-load P        stress-ng CPU duty cycle, integer 1..100 (default: 100)
  --scenario NAME     all, baseline, processes, churn, or cpu (default: all)
  --short             Equivalent to --duration 1 --repetitions 1
  -h, --help          Show this help

CPU stress runs N+1 workers only when available logical CPUs are at most
--max-workers. Otherwise that scenario is explicitly skipped. No root,
affinity, cgroup, or other system setting is used.

When installed, stress-ng is used for the CPU scenario; it is optional and
this harness never installs it. If absent, bounded owned shell workers are used.
EOF
}

binary=target/debug/bottleneck
duration=2
repetitions=3
max_workers=4
cpu_load=100
scenario=all

is_uint_in_range() {
    local value=$1 minimum=$2 maximum=$3
    [[ $value =~ ^[0-9]+$ ]] && (( value >= minimum && value <= maximum ))
}

require_option_value() {
    if (($# < 2)); then
        echo "error: option '$1' requires a value" >&2
        exit 2
    fi
}

while (($#)); do
    case $1 in
        --binary) require_option_value "$@"; binary=$2; shift 2 ;;
        --duration) require_option_value "$@"; duration=$2; shift 2 ;;
        --repetitions) require_option_value "$@"; repetitions=$2; shift 2 ;;
        --max-workers) require_option_value "$@"; max_workers=$2; shift 2 ;;
        --cpu-load) require_option_value "$@"; cpu_load=$2; shift 2 ;;
        --scenario) require_option_value "$@"; scenario=$2; shift 2 ;;
        --short) duration=1; repetitions=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "error: unknown option '$1'" >&2; usage >&2; exit 2 ;;
    esac
done

if ! is_uint_in_range "$duration" 1 30; then echo "error: --duration must be 1..30" >&2; exit 2; fi
if ! is_uint_in_range "$repetitions" 1 10; then echo "error: --repetitions must be 1..10" >&2; exit 2; fi
if ! is_uint_in_range "$max_workers" 1 8; then echo "error: --max-workers must be 1..8" >&2; exit 2; fi
if ! is_uint_in_range "$cpu_load" 1 100; then echo "error: --cpu-load must be 1..100" >&2; exit 2; fi
if [[ ! $scenario =~ ^(all|baseline|processes|churn|cpu)$ ]]; then
    echo "error: --scenario must be all, baseline, processes, churn, or cpu" >&2
    exit 2
fi
if [[ ! -x $binary ]]; then echo "error: built executable not found: $binary" >&2; exit 2; fi
if ! command -v timeout >/dev/null; then echo "error: timeout is required for bounded measurements" >&2; exit 2; fi

scratch=$(mktemp -d "${TMPDIR:-/tmp}/bottleneck-overhead.XXXXXX")
helpers=()
helper_setup_failure=
measurement_failure_reason=
stress_ng_pid=
cleanup() {
    local pid
    for pid in "${helpers[@]}"; do kill "$pid" 2>/dev/null || true; done
    for pid in "${helpers[@]}"; do wait "$pid" 2>/dev/null || true; done
    helpers=()
    stress_ng_pid=
    rm -rf "$scratch"
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

start_sleepers() {
    local count=$1 _
    # The maximum configured scenario is ten 30-second runs, each with a
    # ten-second timeout allowance. Keep helpers alive beyond that bound.
    helper_setup_failure=
    for ((_=0; _<count; _++)); do
        sleep 600 &
        local pid=$!
        if [[ -z $pid ]] || ! kill -0 "$pid" 2>/dev/null; then
            helper_setup_failure="could not start sleeper helper (resource limit or process launch failure)"
            return 1
        fi
        helpers+=("$pid")
    done
}
start_churn() {
    helper_setup_failure=
    ( while :; do /bin/true; done ) &
    local pid=$!
    if [[ -z $pid ]] || ! kill -0 "$pid" 2>/dev/null; then
        helper_setup_failure="could not start churn helper (resource limit or process launch failure)"
        return 1
    fi
    helpers+=("$pid")
}
start_cpu_stress() {
    local count=$1 _
    helper_setup_failure=
    if command -v stress-ng >/dev/null 2>&1; then
        local stress_timeout_seconds=$(((duration + 10) * repetitions + 10))
        stress-ng --cpu "$count" --cpu-load "$cpu_load" --timeout "${stress_timeout_seconds}s" --quiet &
        local pid=$!
        if [[ -z $pid ]] || ! kill -0 "$pid" 2>/dev/null; then
            helper_setup_failure="stress-ng CPU coordinator could not start (resource limit or launch failure)"
            return 1
        fi
        helpers+=("$pid")
        stress_ng_pid=$pid
        return 0
    fi
    if (( cpu_load < 100 )); then
        helper_setup_failure="stress-ng is unavailable; shell-worker fallback cannot provide --cpu-load $cpu_load"
        return 1
    fi
    for ((_=0; _<count; _++)); do
        ( while :; do :; done ) &
        local pid=$!
        if [[ -z $pid ]] || ! kill -0 "$pid" 2>/dev/null; then
            helper_setup_failure="could not start CPU worker (resource limit or process launch failure)"
            return 1
        fi
        helpers+=("$pid")
    done
}
stop_helpers() {
    local pid
    for pid in "${helpers[@]}"; do kill "$pid" 2>/dev/null || true; done
    for pid in "${helpers[@]}"; do wait "$pid" 2>/dev/null || true; done
    helpers=()
    stress_ng_pid=
}

extract_skew_ms() {
    local output=$1 observed
    observed=$(sed -n 's/.*"psi_window_us": *\([0-9][0-9]*\).*/\1/p' "$output" | head -n 1)
    if [[ -z $observed ]]; then printf 'unavailable'; return; fi
    awk -v actual="$observed" -v expected="$duration" 'BEGIN { d=actual-(expected*1000000); if (d < 0) d=-d; printf "%.3f", d/1000 }'
}

extract_json_integer() {
    local output=$1 field=$2 value
    value=$(sed -n "s/.*\"$field\": *\([0-9][0-9]*\).*/\1/p" "$output" | head -n 1)
    if [[ -n $value ]]; then printf '%s' "$value"; else printf 'unavailable'; fi
}

extract_json_number() {
    local output=$1 field=$2 value
    value=$(sed -n "s/.*\"$field\": *\([-0-9.eE][0-9.eE-]*\).*/\1/p" "$output" | head -n 1)
    if [[ -n $value ]]; then printf '%s' "$value"; else printf 'unavailable'; fi
}

extract_json_string() {
    local output=$1 field=$2 value
    value=$(sed -n "s/.*\"$field\": *\"\([^\"]*\)\".*/\1/p" "$output" | head -n 1)
    if [[ -n $value ]]; then printf '%s' "$value"; else printf 'unavailable'; fi
}

measure() {
    local scenario=$1 run=$2 output timefile
    local timeout_seconds=$((duration + 10))
    output="$scratch/$scenario-$run.json"
    timefile="$scratch/$scenario-$run.time"
    local time_format='wall_s=%e user_s=%U system_s=%S maxrss_kib=%M'
    if [[ -x /usr/bin/time ]]; then
        if ! /usr/bin/time -f "$time_format" -o "$timefile" timeout --signal=TERM --kill-after=2s "${timeout_seconds}s" "$binary" hunt --duration "${duration}s" --json >"$output"; then
            measurement_failure_reason="measurement command could not run or timed out (resource limit or launch failure)"
            return 1
        fi
        printf '%-16s run=%s %s observation_skew_ms=%s cpu_psi_some_fraction=%s finding_severity=%s loadavg_total_tasks=%s schedstat_tasks_read=%s\n' "$scenario" "$run" "$(<"$timefile")" "$(extract_skew_ms "$output")" "$(extract_json_number "$output" some_fraction)" "$(extract_json_string "$output" severity)" "$(extract_json_integer "$output" total_tasks)" "$(extract_json_integer "$output" tasks_read)"
    else
        if ! timeout --signal=TERM --kill-after=2s "${timeout_seconds}s" "$binary" hunt --duration "${duration}s" --json >"$output"; then
            measurement_failure_reason="measurement command could not run or timed out (resource limit or launch failure)"
            return 1
        fi
        printf '%-16s run=%s wall_s=unavailable user_s=unavailable system_s=unavailable maxrss_kib=unavailable observation_skew_ms=%s cpu_psi_some_fraction=%s finding_severity=%s loadavg_total_tasks=%s schedstat_tasks_read=%s\n' "$scenario" "$run" "$(extract_skew_ms "$output")" "$(extract_json_number "$output" some_fraction)" "$(extract_json_string "$output" severity)" "$(extract_json_integer "$output" total_tasks)" "$(extract_json_integer "$output" tasks_read)"
    fi
}

run_scenario() {
    local name=$1 setup=$2 run
    shift 2
    stop_helpers
    if ! "$setup" "$@"; then
        stop_helpers
        printf '%-16s skipped: %s\n' "$name" "${helper_setup_failure:-helper setup failed}"
        return 0
    fi
    for ((run=1; run<=repetitions; run++)); do
        if [[ -n $stress_ng_pid ]] && ! kill -0 "$stress_ng_pid" 2>/dev/null; then
            stop_helpers
            measurement_failure_reason="stress-ng CPU coordinator exited before repetition $run"
            printf '%-16s failed: %s\n' "$name" "$measurement_failure_reason" >&2
            return 1
        fi
        if ! measure "$name" "$run"; then
            stop_helpers
            printf '%-16s failed: %s\n' "$name" "${measurement_failure_reason:-measurement failed}" >&2
            return 1
        fi
        if [[ -n $stress_ng_pid ]] && ! kill -0 "$stress_ng_pid" 2>/dev/null; then
            stop_helpers
            measurement_failure_reason="stress-ng CPU coordinator exited during repetition $run"
            printf '%-16s failed: %s\n' "$name" "$measurement_failure_reason" >&2
            return 1
        fi
    done
    stop_helpers
}

echo "observer-overhead harness: binary=$binary duration=${duration}s repetitions=$repetitions max_workers=$max_workers cpu_load=$cpu_load scenario=$scenario"
had_failure=0
if [[ $scenario == all || $scenario == baseline ]]; then run_scenario baseline true || had_failure=1; fi
if [[ $scenario == all || $scenario == processes ]]; then run_scenario moderate_processes start_sleepers "$max_workers" || had_failure=1; fi
if [[ $scenario == all || $scenario == churn ]]; then run_scenario process_churn start_churn || had_failure=1; fi
if [[ $scenario == all || $scenario == cpu ]]; then
    available_cpus=$(getconf _NPROCESSORS_ONLN 2>/dev/null || true)
    if is_uint_in_range "$available_cpus" 1 "$max_workers"; then
        run_scenario cpu_stress start_cpu_stress "$((available_cpus + 1))" || had_failure=1
    else
        echo "cpu_stress       skipped: available logical CPUs '${available_cpus:-unavailable}' exceed safe cap $max_workers (or are unavailable)"
    fi
fi
exit "$had_failure"
