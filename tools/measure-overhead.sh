#!/usr/bin/env bash
# Rootless, opt-in observer-overhead harness. It measures the built binary,
# never Cargo, and intentionally does not serve as a CI performance gate.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: tools/measure-overhead.sh [options]

Measure a pre-built stallhunt binary across bounded scenarios. Results are
environment-dependent; record ranges, not pass/fail thresholds.

Options:
  --binary PATH       Built stallhunt executable (default: target/debug/stallhunt)
  --duration SECONDS  Hunt duration, integer 1..30 (default: 2)
  --repetitions N     Repetitions per scenario, integer 1..10 (default: 3)
  --max-workers N     CPU workers/process helpers, integer 1..8 (default: 4)
  --sleepers N        Sleeping processes for many_pids, integer 32..1024 (default: 256)
  --tasks N           Sleeping threads for many_tasks, integer 32..1024 (default: 256)
  --cpu-load P        stress-ng CPU duty cycle, integer 1..100 (default: 100)
  --scenario NAME     all, baseline, processes, churn, cpu, many_pids, many_tasks,
                      or high (default: all)
  --short             Equivalent to --duration 1 --repetitions 1
  -h, --help          Show this help

CPU stress runs N+1 workers only when available logical CPUs are at most
--max-workers. Otherwise that scenario is explicitly skipped. No root,
affinity, cgroup, or other system setting is used.

`all` keeps the original small helper set so constrained sandboxes do not fork
hundreds of processes. `many_pids`, `many_tasks`, and `high` are opt-in; they
skip when the user process limit cannot hold the helpers with a reserve.

When installed, stress-ng is used for the CPU scenario; it is optional and
this harness never installs it. If absent, bounded owned shell workers are used.
many_pids spawns sleepers from a Python helper so a fork failure stops the
batch and cleans up; it does not use bash background `sleep` (which retries
EAGAIN and can leak helpers).
EOF
}

binary=target/debug/stallhunt
duration=2
repetitions=3
max_workers=4
sleepers=256
tasks=256
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
        --sleepers) require_option_value "$@"; sleepers=$2; shift 2 ;;
        --tasks) require_option_value "$@"; tasks=$2; shift 2 ;;
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
if ! is_uint_in_range "$sleepers" 32 1024; then echo "error: --sleepers must be 32..1024" >&2; exit 2; fi
if ! is_uint_in_range "$tasks" 32 1024; then echo "error: --tasks must be 32..1024" >&2; exit 2; fi
if ! is_uint_in_range "$cpu_load" 1 100; then echo "error: --cpu-load must be 1..100" >&2; exit 2; fi
if [[ ! $scenario =~ ^(all|baseline|processes|churn|cpu|many_pids|many_tasks|high)$ ]]; then
    echo "error: --scenario must be all, baseline, processes, churn, cpu, many_pids, many_tasks, or high" >&2
    exit 2
fi
if [[ ! -x $binary ]]; then echo "error: built executable not found: $binary" >&2; exit 2; fi
if ! command -v timeout >/dev/null; then echo "error: timeout is required for bounded measurements" >&2; exit 2; fi

scratch=$(mktemp -d "${TMPDIR:-/tmp}/stallhunt-overhead.XXXXXX")
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
    local count=$1 script
    helper_setup_failure=
    if ! process_quota_allows "$count"; then
        return 1
    fi
    if ! command -v python3 >/dev/null 2>&1; then
        helper_setup_failure="python3 is unavailable; many_pids needs it to spawn sleepers without bash fork-retry"
        return 1
    fi
    script="$scratch/sleeping-pids.py"
    cat >"$script" <<'PY'
import os
import signal
import sys
import time

count = int(sys.argv[1])
children = []

def cleanup(_signum=None, _frame=None):
    for pid in children:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    for pid in children:
        try:
            os.waitpid(pid, 0)
        except OSError:
            pass
    os._exit(0)

signal.signal(signal.SIGTERM, cleanup)
signal.signal(signal.SIGINT, cleanup)

for _ in range(count):
    try:
        pid = os.fork()
    except OSError as error:
        sys.stderr.write(f"fork failed after {len(children)} children: {error}\n")
        cleanup()
    if pid == 0:
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        time.sleep(600)
        os._exit(0)
    children.append(pid)

signal.pause()
PY
    python3 "$script" "$count" &
    local pid=$!
    if [[ -z $pid ]] || ! kill -0 "$pid" 2>/dev/null; then
        helper_setup_failure="could not start sleeper helper (resource limit or process launch failure)"
        return 1
    fi
    helpers+=("$pid")
}
start_many_tasks() {
    local count=$1 script
    helper_setup_failure=
    if ! command -v python3 >/dev/null 2>&1; then
        helper_setup_failure="python3 is unavailable; many_tasks needs it to create sleeping threads"
        return 1
    fi
    if ! process_quota_allows 1; then
        return 1
    fi
    script="$scratch/sleeping-threads.py"
    cat >"$script" <<'PY'
import sys
import threading
import time

count = int(sys.argv[1])
stop = threading.Event()
threads = [
    threading.Thread(target=stop.wait, daemon=True)
    for _ in range(count)
]
for thread in threads:
    thread.start()
try:
    time.sleep(600)
finally:
    stop.set()
PY
    python3 "$script" "$count" &
    local pid=$!
    if [[ -z $pid ]] || ! kill -0 "$pid" 2>/dev/null; then
        helper_setup_failure="could not start sleeping-thread helper (resource limit or launch failure)"
        return 1
    fi
    helpers+=("$pid")
}
process_quota_allows() {
    local needed=$1 limit current remaining
    limit=$(ulimit -u)
    if [[ $limit == unlimited ]]; then
        return 0
    fi
    if ! [[ $limit =~ ^[0-9]+$ ]]; then
        helper_setup_failure="could not parse user process limit '$limit'"
        return 1
    fi
    current=$(pgrep -u "$(id -u)" 2>/dev/null | wc -l | tr -d ' ')
    if ! [[ $current =~ ^[0-9]+$ ]]; then
        helper_setup_failure="could not count current user processes"
        return 1
    fi
    remaining=$((limit - current))
    if (( remaining < needed + 32 )); then
        helper_setup_failure="user process quota remaining $remaining is below $needed helpers plus a 32-process reserve"
        return 1
    fi
    return 0
}
count_visible_pids() {
    find /proc -maxdepth 1 -regex '/proc/[0-9]+' 2>/dev/null | wc -l | tr -d ' '
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

extract_observation_counts() {
    local output=$1
    if ! command -v python3 >/dev/null 2>&1; then
        printf 'cpu_process_intervals=unavailable process_io_intervals=unavailable process_limit_reached=unavailable task_limit_reached=unavailable stable_tasks=unavailable cgroup_process_limit_reached=unavailable cgroup_groups=unavailable cpu_duration_us=unavailable process_io_duration_us=unavailable cgroup_duration_us=unavailable'
        return
    fi
    python3 - "$output" <<'PY'
import json, sys
path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    payload = json.load(handle)
observation = payload.get("observation") or {}
cpu_processes = observation.get("processes") or []
process_io = observation.get("process_io") or {}
io_processes = process_io.get("processes") or []
issues = observation.get("process_collection_issues") or {}
sched = observation.get("schedstat_collection_issues") or {}
cgroup = observation.get("cgroup") or {}
cgroup_issues = cgroup.get("issues") or {}

def flag(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    return "unavailable"

def number(value):
    return str(value) if isinstance(value, int) else "unavailable"

print(
    "cpu_process_intervals=" + str(len(cpu_processes)),
    "process_io_intervals=" + str(len(io_processes)),
    "process_limit_reached=" + flag(issues.get("limit_reached")),
    "task_limit_reached=" + flag(sched.get("task_limit_reached")),
    "stable_tasks=" + number(sched.get("stable_tasks")),
    "cgroup_process_limit_reached=" + flag(cgroup_issues.get("process_limit_reached")),
    "cgroup_groups=" + str(len(cgroup.get("groups") or [])),
    "cpu_duration_us=" + number(observation.get("cpu_duration_us")),
    "process_io_duration_us=" + number(observation.get("process_io_duration_us")),
    "cgroup_duration_us=" + number(observation.get("cgroup_duration_us")),
)
PY
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
        printf '%-16s run=%s %s observation_skew_ms=%s cpu_psi_some_fraction=%s finding_severity=%s loadavg_total_tasks=%s schedstat_tasks_read=%s visible_proc_pids=%s %s\n' "$scenario" "$run" "$(<"$timefile")" "$(extract_skew_ms "$output")" "$(extract_json_number "$output" some_fraction)" "$(extract_json_string "$output" severity)" "$(extract_json_integer "$output" total_tasks)" "$(extract_json_integer "$output" tasks_read)" "$(count_visible_pids)" "$(extract_observation_counts "$output")"
    else
        if ! timeout --signal=TERM --kill-after=2s "${timeout_seconds}s" "$binary" hunt --duration "${duration}s" --json >"$output"; then
            measurement_failure_reason="measurement command could not run or timed out (resource limit or launch failure)"
            return 1
        fi
        printf '%-16s run=%s wall_s=unavailable user_s=unavailable system_s=unavailable maxrss_kib=unavailable observation_skew_ms=%s cpu_psi_some_fraction=%s finding_severity=%s loadavg_total_tasks=%s schedstat_tasks_read=%s visible_proc_pids=%s %s\n' "$scenario" "$run" "$(extract_skew_ms "$output")" "$(extract_json_number "$output" some_fraction)" "$(extract_json_string "$output" severity)" "$(extract_json_integer "$output" total_tasks)" "$(extract_json_integer "$output" tasks_read)" "$(count_visible_pids)" "$(extract_observation_counts "$output")"
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

echo "observer-overhead harness: binary=$binary duration=${duration}s repetitions=$repetitions max_workers=$max_workers sleepers=$sleepers tasks=$tasks cpu_load=$cpu_load scenario=$scenario visible_proc_pids=$(count_visible_pids)"
had_failure=0
if [[ $scenario == all || $scenario == baseline || $scenario == high ]]; then run_scenario baseline true || had_failure=1; fi
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
if [[ $scenario == many_pids || $scenario == high ]]; then run_scenario many_pids start_sleepers "$sleepers" || had_failure=1; fi
if [[ $scenario == many_tasks || $scenario == high ]]; then run_scenario many_tasks start_many_tasks "$tasks" || had_failure=1; fi
exit "$had_failure"
