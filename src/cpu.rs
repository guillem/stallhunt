use std::collections::{BTreeMap, BinaryHeap};
use std::fs;
use std::io;
use std::path::Path;
use std::time::Duration;

use serde::Serialize;

const MAX_PROCESSES: usize = 4_096;
// Schedstat is thread-scoped. This global cap bounds selected task samples
// while retaining deterministic lowest-PID/lowest-TID selection. A successful
// sample brackets one schedstat read with two task-stat identity reads.
const MAX_SCHEDSTAT_TASKS: usize = 16_384;
const MAX_PROCESS_NAME_CHARS: usize = 80;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ProcessKey {
    pub pid: u32,
    pub start_time_ticks: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessRaw {
    pub key: ProcessKey,
    pub comm: String,
    pub state: char,
    pub user_ticks: u64,
    pub system_ticks: u64,
    pub schedstat: BTreeMap<ThreadKey, SchedstatRaw>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SchedstatRaw {
    pub running_ns: u64,
    pub runnable_wait_ns: u64,
    pub timeslices: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ThreadKey {
    pub tid: u32,
    pub start_time_ticks: u64,
}

impl ProcessRaw {
    fn cpu_ticks(&self) -> Option<u64> {
        self.user_ticks.checked_add(self.system_ticks)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCpuRaw {
    pub total_without_iowait_ticks: u64,
    pub busy_ticks: u64,
    pub iowait_ticks: u64,
    pub cpu_count: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LoadAverageRaw {
    pub avg1: f64,
    pub avg5: f64,
    pub avg15: f64,
    pub runnable_tasks: u64,
    pub total_tasks: u64,
    pub last_pid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadAverageAvailability {
    Available,
    Unreadable,
    Malformed,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ProcessCollectionIssues {
    pub enumeration_failed: bool,
    pub enumeration_errors: u32,
    pub disappeared: u32,
    pub permission_denied: u32,
    pub unreadable: u32,
    pub malformed: u32,
    pub counter_regressed: u32,
    pub appeared: u32,
    pub exited: u32,
    pub limit_reached: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SchedstatCollectionIssues {
    pub task_enumeration_failed: u32,
    pub task_enumeration_errors: u32,
    pub task_disappeared: u32,
    pub task_unsupported: u32,
    pub task_appeared: u32,
    pub task_exited: u32,
    pub task_identity_changed: u32,
    pub task_permission_denied: u32,
    pub task_unreadable: u32,
    pub task_malformed: u32,
    pub aggregate_overflow: u32,
    pub counter_regressed: u32,
    pub task_limit_reached: bool,
    pub tasks_read: u32,
    pub stable_tasks: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CpuSnapshot {
    pub host: HostCpuRaw,
    pub load: Option<LoadAverageRaw>,
    pub load_availability: LoadAverageAvailability,
    pub processes: BTreeMap<ProcessKey, ProcessRaw>,
    pub issues: ProcessCollectionIssues,
    pub schedstat_issues: SchedstatCollectionIssues,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HostCpuInterval {
    pub total_ticks: u64,
    pub busy_ticks: u64,
    pub idle_ticks: u64,
    pub utilization_fraction: f64,
    pub cpu_count: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProcessCpuInterval {
    pub key: ProcessKey,
    pub name: String,
    pub state: char,
    pub cpu_ticks: u64,
    pub cpu_fraction_of_one: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProcessSchedulerDelayInterval {
    pub key: ProcessKey,
    pub name: String,
    pub task_count: u32,
    pub running_ns: u64,
    pub runnable_wait_ns: u64,
    pub timeslices: u64,
    // This is the sum of all sampled threads in the process and can exceed
    // one wall-clock interval on a multi-threaded process.
    pub runnable_delay_fraction: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CpuProcessObservation {
    pub elapsed: Duration,
    pub clock_ticks_per_second: u64,
    pub host: HostCpuInterval,
    pub load: Option<LoadAverageRaw>,
    pub load_availability: LoadAverageAvailability,
    pub processes: Vec<ProcessCpuInterval>,
    pub collection_issues: ProcessCollectionIssues,
    pub scheduler_delay_candidates: Vec<ProcessSchedulerDelayInterval>,
    pub schedstat_collection_issues: SchedstatCollectionIssues,
    pub schedstat_capability: SchedstatCapability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuError {
    Unreadable,
    Malformed,
    EmptyInterval,
    CounterRegressed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectorCapability {
    Available,
    Partial,
    Failed,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SchedstatCapability {
    Available,
    Partial,
    Unsupported,
    PermissionDenied,
    Failed,
}
impl SchedstatCapability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Partial => "partial",
            Self::Unsupported => "unsupported",
            Self::PermissionDenied => "permission_denied",
            Self::Failed => "failed",
        }
    }
    pub fn explanation(self) -> &'static str {
        match self {
            Self::Available => {
                "Task schedstat counters were read and aggregated to stable process identities."
            }
            Self::Partial => {
                "Task schedstat collection was incomplete; any stable scheduler-delay evidence remains explicitly qualified."
            }
            Self::Unsupported => "Task schedstat counters were not available on this kernel.",
            Self::PermissionDenied => {
                "Task schedstat counters could not be read with the current permissions."
            }
            Self::Failed => "Task schedstat collection failed before usable evidence was obtained.",
        }
    }
}
impl CollectorCapability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Partial => "partial",
            Self::Failed => "failed",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuTelemetryCapabilities {
    pub host_cpu: CollectorCapability,
    pub process_stat: CollectorCapability,
    pub process_schedstat: SchedstatCapability,
}
pub fn probe_cpu_telemetry() -> CpuTelemetryCapabilities {
    probe_cpu_telemetry_at(Path::new("/proc"))
}

fn probe_cpu_telemetry_at(proc_root: &Path) -> CpuTelemetryCapabilities {
    telemetry_capabilities(read_snapshot(proc_root))
}

fn telemetry_capabilities(snapshot: Result<CpuSnapshot, CpuError>) -> CpuTelemetryCapabilities {
    match snapshot {
        Err(_) => CpuTelemetryCapabilities {
            host_cpu: CollectorCapability::Failed,
            process_stat: CollectorCapability::Failed,
            process_schedstat: SchedstatCapability::Failed,
        },
        Ok(snapshot) => {
            let issues = snapshot.issues;
            let process_stat = process_capability(&issues);
            CpuTelemetryCapabilities {
                host_cpu: CollectorCapability::Available,
                process_stat,
                process_schedstat: schedstat_capability(&snapshot.schedstat_issues, &issues),
            }
        }
    }
}

pub fn schedstat_capability(
    issues: &SchedstatCollectionIssues,
    process_issues: &ProcessCollectionIssues,
) -> SchedstatCapability {
    if process_issues.enumeration_failed {
        return SchedstatCapability::Failed;
    }
    if issues.counter_regressed != 0 || issues.aggregate_overflow != 0 {
        return SchedstatCapability::Partial;
    }
    if issues.task_appeared != 0 || issues.task_exited != 0 || issues.task_identity_changed != 0 {
        return SchedstatCapability::Partial;
    }
    if issues.tasks_read != 0 {
        if issues.task_enumeration_failed != 0
            || issues.task_enumeration_errors != 0
            || issues.task_disappeared != 0
            || issues.task_unsupported != 0
            || issues.task_permission_denied != 0
            || issues.task_unreadable != 0
            || issues.task_malformed != 0
            || issues.aggregate_overflow != 0
            || issues.counter_regressed != 0
            || issues.task_limit_reached
            || issues.task_appeared != 0
            || issues.task_exited != 0
            || issues.task_identity_changed != 0
            || process_issues.disappeared != 0
            || process_issues.permission_denied != 0
            || process_issues.unreadable != 0
            || process_issues.malformed != 0
            || process_issues.enumeration_errors != 0
            || process_issues.limit_reached
            || process_issues.appeared != 0
            || process_issues.exited != 0
        {
            SchedstatCapability::Partial
        } else {
            SchedstatCapability::Available
        }
    } else if issues.task_permission_denied != 0 || process_issues.permission_denied != 0 {
        SchedstatCapability::PermissionDenied
    } else if issues.task_unsupported != 0 {
        SchedstatCapability::Unsupported
    } else {
        SchedstatCapability::Failed
    }
}

pub fn process_capability(issues: &ProcessCollectionIssues) -> CollectorCapability {
    if issues.enumeration_failed {
        CollectorCapability::Failed
    } else if issues.disappeared != 0
        || issues.permission_denied != 0
        || issues.unreadable != 0
        || issues.malformed != 0
        || issues.enumeration_errors != 0
        || issues.counter_regressed != 0
        || issues.limit_reached
    {
        CollectorCapability::Partial
    } else {
        CollectorCapability::Available
    }
}

impl CpuError {
    pub fn explanation(self) -> &'static str {
        match self {
            Self::Unreadable => "CPU counters could not be read from procfs.",
            Self::Malformed => "CPU counters did not match the expected procfs format.",
            Self::EmptyInterval => "CPU counters were collected over an empty interval.",
            Self::CounterRegressed => "CPU counters regressed during the observation window.",
        }
    }
}

pub(crate) fn read_snapshot(proc_root: &Path) -> Result<CpuSnapshot, CpuError> {
    let stat = fs::read_to_string(proc_root.join("stat")).map_err(map_io_error)?;
    let host = parse_proc_stat(&stat)?;
    let (load, load_availability) = match fs::read_to_string(proc_root.join("loadavg")) {
        Ok(contents) => match parse_loadavg(&contents) {
            Ok(load) => (Some(load), LoadAverageAvailability::Available),
            Err(_) => (None, LoadAverageAvailability::Malformed),
        },
        Err(_) => (None, LoadAverageAvailability::Unreadable),
    };
    let (processes, issues, schedstat_issues) = collect_processes(proc_root);
    Ok(CpuSnapshot {
        host,
        load,
        load_availability,
        processes,
        issues,
        schedstat_issues,
    })
}

fn map_io_error(_: io::Error) -> CpuError {
    CpuError::Unreadable
}

pub fn parse_proc_stat(input: &str) -> Result<HostCpuRaw, CpuError> {
    let line = input
        .lines()
        .find(|line| line.starts_with("cpu "))
        .ok_or(CpuError::Malformed)?;
    let fields: Vec<u64> = line
        .split_ascii_whitespace()
        .skip(1)
        .map(|field| field.parse().map_err(|_| CpuError::Malformed))
        .collect::<Result<_, _>>()?;
    if fields.len() < 4 {
        return Err(CpuError::Malformed);
    }
    let value = |index: usize| fields.get(index).copied().unwrap_or(0);
    let user = value(0);
    let nice = value(1);
    let system = value(2);
    let idle = value(3);
    let iowait = value(4);
    let irq = value(5);
    let softirq = value(6);
    let steal = value(7);
    // guest and guest_nice are already included in user and nice respectively.
    // iowait is intentionally separate because Linux documents it as capable
    // of decreasing. The remaining aggregate fields are used as the reliable
    // interval baseline if that happens.
    let total_without_iowait_ticks = [user, nice, system, idle, irq, softirq, steal]
        .into_iter()
        .try_fold(0_u64, u64::checked_add)
        .ok_or(CpuError::Malformed)?;
    let busy_ticks = [user, nice, system, irq, softirq, steal]
        .into_iter()
        .try_fold(0_u64, u64::checked_add)
        .ok_or(CpuError::Malformed)?;
    let cpu_count = input
        .lines()
        .filter(|line| {
            let Some(suffix) = line.strip_prefix("cpu") else {
                return false;
            };
            suffix.as_bytes().first().is_some_and(u8::is_ascii_digit)
                && suffix
                    .split_ascii_whitespace()
                    .next()
                    .is_some_and(|number| number.bytes().all(|byte| byte.is_ascii_digit()))
        })
        .count();
    let cpu_count = u32::try_from(cpu_count).map_err(|_| CpuError::Malformed)?;
    if cpu_count == 0 {
        return Err(CpuError::Malformed);
    }
    Ok(HostCpuRaw {
        total_without_iowait_ticks,
        busy_ticks,
        iowait_ticks: iowait,
        cpu_count,
    })
}

pub fn parse_loadavg(input: &str) -> Result<LoadAverageRaw, CpuError> {
    let fields: Vec<_> = input.split_ascii_whitespace().collect();
    if fields.len() != 5 {
        return Err(CpuError::Malformed);
    }
    let parse_float = |field: &str| {
        let value = field.parse::<f64>().map_err(|_| CpuError::Malformed)?;
        if value.is_finite() && value >= 0.0 {
            Ok(value)
        } else {
            Err(CpuError::Malformed)
        }
    };
    let (runnable, total) = fields[3].split_once('/').ok_or(CpuError::Malformed)?;
    let runnable_tasks = runnable.parse().map_err(|_| CpuError::Malformed)?;
    let total_tasks: u64 = total.parse().map_err(|_| CpuError::Malformed)?;
    if total_tasks == 0 || runnable_tasks > total_tasks {
        return Err(CpuError::Malformed);
    }
    Ok(LoadAverageRaw {
        avg1: parse_float(fields[0])?,
        avg5: parse_float(fields[1])?,
        avg15: parse_float(fields[2])?,
        runnable_tasks,
        total_tasks,
        last_pid: fields[4].parse().map_err(|_| CpuError::Malformed)?,
    })
}

pub fn parse_process_stat(input: &str) -> Result<ProcessRaw, CpuError> {
    let input = input.trim_end();
    let (pid, rest) = input.split_once(' ').ok_or(CpuError::Malformed)?;
    let pid = pid.parse().map_err(|_| CpuError::Malformed)?;
    let comm_start = rest.strip_prefix('(').ok_or(CpuError::Malformed)?;
    let close = comm_start.rfind(')').ok_or(CpuError::Malformed)?;
    let comm = &comm_start[..close];
    let remaining = comm_start[close + 1..]
        .strip_prefix(' ')
        .ok_or(CpuError::Malformed)?;
    let fields: Vec<_> = remaining.split_ascii_whitespace().collect();
    if fields.len() < 20 || fields[0].chars().count() != 1 {
        return Err(CpuError::Malformed);
    }
    Ok(ProcessRaw {
        key: ProcessKey {
            pid,
            start_time_ticks: fields[19].parse().map_err(|_| CpuError::Malformed)?,
        },
        comm: comm.to_owned(),
        state: fields[0].chars().next().ok_or(CpuError::Malformed)?,
        user_ticks: fields[11].parse().map_err(|_| CpuError::Malformed)?,
        system_ticks: fields[12].parse().map_err(|_| CpuError::Malformed)?,
        schedstat: BTreeMap::new(),
    })
}

pub fn parse_schedstat(input: &str) -> Result<SchedstatRaw, CpuError> {
    let fields: Vec<_> = input.split_ascii_whitespace().collect();
    if fields.len() != 3 {
        return Err(CpuError::Malformed);
    }
    Ok(SchedstatRaw {
        running_ns: fields[0].parse().map_err(|_| CpuError::Malformed)?,
        runnable_wait_ns: fields[1].parse().map_err(|_| CpuError::Malformed)?,
        timeslices: fields[2].parse().map_err(|_| CpuError::Malformed)?,
    })
}

fn collect_processes(
    proc_root: &Path,
) -> (
    BTreeMap<ProcessKey, ProcessRaw>,
    ProcessCollectionIssues,
    SchedstatCollectionIssues,
) {
    let mut issues = ProcessCollectionIssues::default();
    let mut schedstat_issues = SchedstatCollectionIssues::default();
    let Ok(entries) = fs::read_dir(proc_root) else {
        issues.enumeration_failed = true;
        return (BTreeMap::new(), issues, schedstat_issues);
    };
    let mut pids = BinaryHeap::with_capacity(MAX_PROCESSES);
    for entry in entries {
        match entry {
            Ok(entry) => {
                if let Some(pid) = entry
                    .file_name()
                    .to_str()
                    .and_then(|name| name.parse().ok())
                {
                    insert_lowest_pid(&mut pids, pid, &mut issues);
                }
            }
            Err(_) => issues.enumeration_errors = issues.enumeration_errors.saturating_add(1),
        }
    }
    let mut pids = pids.into_vec();
    pids.sort_unstable();
    let mut processes = BTreeMap::new();
    let mut remaining_tasks = MAX_SCHEDSTAT_TASKS;
    for pid in pids {
        match fs::read_to_string(proc_root.join(pid.to_string()).join("stat")) {
            Ok(contents) => match parse_process_stat(&contents) {
                Ok(mut process) => {
                    process.schedstat = collect_process_schedstat(
                        proc_root,
                        pid,
                        &mut remaining_tasks,
                        &mut schedstat_issues,
                    );
                    processes.insert(process.key, process);
                }
                Err(_) => issues.malformed += 1,
            },
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                issues.permission_denied += 1
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => issues.disappeared += 1,
            Err(_) => issues.unreadable += 1,
        }
    }
    (processes, issues, schedstat_issues)
}

fn collect_process_schedstat(
    proc_root: &Path,
    pid: u32,
    remaining_tasks: &mut usize,
    issues: &mut SchedstatCollectionIssues,
) -> BTreeMap<ThreadKey, SchedstatRaw> {
    if *remaining_tasks == 0 {
        issues.task_limit_reached = true;
        return BTreeMap::new();
    }
    let task_root = proc_root.join(pid.to_string()).join("task");
    let entries = match fs::read_dir(task_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            issues.task_disappeared = issues.task_disappeared.saturating_add(1);
            return BTreeMap::new();
        }
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            issues.task_permission_denied = issues.task_permission_denied.saturating_add(1);
            return BTreeMap::new();
        }
        Err(_) => {
            issues.task_enumeration_failed = issues.task_enumeration_failed.saturating_add(1);
            return BTreeMap::new();
        }
    };
    let mut tids = BinaryHeap::new();
    for entry in entries {
        match entry {
            Ok(entry) => match entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            {
                Some(tid) => {
                    insert_lowest_task(&mut tids, tid, *remaining_tasks, issues);
                }
                None => {
                    issues.task_enumeration_errors =
                        issues.task_enumeration_errors.saturating_add(1)
                }
            },
            Err(_) => {
                issues.task_enumeration_errors = issues.task_enumeration_errors.saturating_add(1)
            }
        }
    }
    let mut tids = tids.into_vec();
    tids.sort_unstable();
    let mut result = BTreeMap::new();
    for tid in tids {
        *remaining_tasks -= 1;
        let task_base = proc_root
            .join(pid.to_string())
            .join("task")
            .join(tid.to_string());
        let task_key = match fs::read_to_string(task_base.join("stat"))
            .and_then(|value| parse_process_stat(&value).map_err(|_| io::Error::other("malformed")))
        {
            Ok(stat) if stat.key.pid == tid => ThreadKey {
                tid,
                start_time_ticks: stat.key.start_time_ticks,
            },
            Ok(_) => {
                issues.task_identity_changed = issues.task_identity_changed.saturating_add(1);
                continue;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                issues.task_disappeared = issues.task_disappeared.saturating_add(1);
                continue;
            }
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                issues.task_permission_denied = issues.task_permission_denied.saturating_add(1);
                continue;
            }
            Err(_) => {
                issues.task_malformed = issues.task_malformed.saturating_add(1);
                continue;
            }
        };
        match fs::read_to_string(task_base.join("schedstat")) {
            Ok(contents) => match parse_schedstat(&contents) {
                Ok(raw) => {
                    match fs::read_to_string(task_base.join("stat"))
                        .ok()
                        .and_then(|value| parse_process_stat(&value).ok())
                    {
                        Some(stat)
                            if stat.key.pid == tid
                                && stat.key.start_time_ticks == task_key.start_time_ticks =>
                        {
                            result.insert(task_key, raw);
                            issues.tasks_read = issues.tasks_read.saturating_add(1);
                        }
                        _ => {
                            issues.task_identity_changed =
                                issues.task_identity_changed.saturating_add(1)
                        }
                    }
                }
                Err(_) => issues.task_malformed = issues.task_malformed.saturating_add(1),
            },
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                issues.task_permission_denied = issues.task_permission_denied.saturating_add(1)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match fs::read_to_string(task_base.join("stat"))
                    .ok()
                    .and_then(|value| parse_process_stat(&value).ok())
                {
                    Some(stat)
                        if stat.key.start_time_ticks == task_key.start_time_ticks
                            && stat.key.pid == tid =>
                    {
                        issues.task_unsupported = issues.task_unsupported.saturating_add(1);
                    }
                    Some(_) => {
                        issues.task_identity_changed =
                            issues.task_identity_changed.saturating_add(1);
                    }
                    None => {
                        issues.task_disappeared = issues.task_disappeared.saturating_add(1);
                    }
                }
            }
            Err(_) => issues.task_unreadable = issues.task_unreadable.saturating_add(1),
        }
    }
    result
}

fn insert_lowest_pid(pids: &mut BinaryHeap<u32>, pid: u32, issues: &mut ProcessCollectionIssues) {
    if pids.len() < MAX_PROCESSES {
        pids.push(pid);
    } else if pids.peek().is_some_and(|largest| pid < *largest) {
        pids.pop();
        pids.push(pid);
        issues.limit_reached = true;
    } else {
        issues.limit_reached = true;
    }
}

fn insert_lowest_task(
    tids: &mut BinaryHeap<u32>,
    tid: u32,
    limit: usize,
    issues: &mut SchedstatCollectionIssues,
) {
    if tids.len() < limit {
        tids.push(tid);
    } else if tids.peek().is_some_and(|largest| tid < *largest) {
        tids.pop();
        tids.push(tid);
        issues.task_limit_reached = true;
    } else {
        issues.task_limit_reached = true;
    }
}

pub fn interval_from_snapshots(
    start: CpuSnapshot,
    end: CpuSnapshot,
    elapsed: Duration,
) -> Result<CpuProcessObservation, CpuError> {
    if elapsed.is_zero() {
        return Err(CpuError::EmptyInterval);
    }
    let base_total_ticks = end
        .host
        .total_without_iowait_ticks
        .checked_sub(start.host.total_without_iowait_ticks)
        .ok_or(CpuError::CounterRegressed)?;
    let busy_ticks = end
        .host
        .busy_ticks
        .checked_sub(start.host.busy_ticks)
        .ok_or(CpuError::CounterRegressed)?;
    let total_ticks = match end.host.iowait_ticks.checked_sub(start.host.iowait_ticks) {
        Some(iowait_ticks) => base_total_ticks
            .checked_add(iowait_ticks)
            .ok_or(CpuError::CounterRegressed)?,
        None => base_total_ticks,
    };
    if total_ticks == 0 || busy_ticks > total_ticks {
        return Err(CpuError::CounterRegressed);
    }
    let idle_ticks = total_ticks - busy_ticks;
    let clock_ticks_per_second = rustix::param::clock_ticks_per_second();
    if clock_ticks_per_second == 0 {
        return Err(CpuError::Malformed);
    }
    let elapsed_seconds = elapsed.as_secs_f64();
    let mut collection_issues = merge_issues(start.issues, end.issues);
    collection_issues.appeared = u32::try_from(
        end.processes
            .keys()
            .filter(|key| !start.processes.contains_key(key))
            .count(),
    )
    .unwrap_or(u32::MAX);
    collection_issues.exited = u32::try_from(
        start
            .processes
            .keys()
            .filter(|key| !end.processes.contains_key(key))
            .count(),
    )
    .unwrap_or(u32::MAX);
    let mut processes = Vec::new();
    let mut scheduler_delay_candidates = Vec::new();
    let mut schedstat_collection_issues =
        merge_schedstat_issues(start.schedstat_issues, end.schedstat_issues);
    for (key, end_process) in &end.processes {
        let Some(start_process) = start.processes.get(key) else {
            continue;
        };
        if let (Some(start_ticks), Some(end_ticks)) =
            (start_process.cpu_ticks(), end_process.cpu_ticks())
        {
            if let Some(ticks) = end_ticks.checked_sub(start_ticks) {
                processes.push(ProcessCpuInterval {
                    key: *key,
                    name: sanitized_process_name(&end_process.comm),
                    state: end_process.state,
                    cpu_ticks: ticks,
                    cpu_fraction_of_one: ticks as f64
                        / clock_ticks_per_second as f64
                        / elapsed_seconds,
                });
            } else {
                collection_issues.counter_regressed =
                    collection_issues.counter_regressed.saturating_add(1);
            }
        } else {
            collection_issues.counter_regressed =
                collection_issues.counter_regressed.saturating_add(1);
        }
        let mut total = SchedstatRaw {
            running_ns: 0,
            runnable_wait_ns: 0,
            timeslices: 0,
        };
        let mut stable_tasks = 0_u32;
        for (thread, end_raw) in &end_process.schedstat {
            let Some(start_raw) = start_process.schedstat.get(thread) else {
                continue;
            };
            let (Some(running_ns), Some(runnable_wait_ns), Some(timeslices)) = (
                end_raw.running_ns.checked_sub(start_raw.running_ns),
                end_raw
                    .runnable_wait_ns
                    .checked_sub(start_raw.runnable_wait_ns),
                end_raw.timeslices.checked_sub(start_raw.timeslices),
            ) else {
                schedstat_collection_issues.counter_regressed = schedstat_collection_issues
                    .counter_regressed
                    .saturating_add(1);
                continue;
            };
            let (Some(next_running), Some(next_wait), Some(next_slices)) = (
                total.running_ns.checked_add(running_ns),
                total.runnable_wait_ns.checked_add(runnable_wait_ns),
                total.timeslices.checked_add(timeslices),
            ) else {
                schedstat_collection_issues.aggregate_overflow = schedstat_collection_issues
                    .aggregate_overflow
                    .saturating_add(1);
                continue;
            };
            total = SchedstatRaw {
                running_ns: next_running,
                runnable_wait_ns: next_wait,
                timeslices: next_slices,
            };
            stable_tasks = stable_tasks.saturating_add(1);
        }
        schedstat_collection_issues.stable_tasks = schedstat_collection_issues
            .stable_tasks
            .saturating_add(stable_tasks);
        if stable_tasks != 0 {
            scheduler_delay_candidates.push(ProcessSchedulerDelayInterval {
                key: *key,
                name: sanitized_process_name(&end_process.comm),
                task_count: stable_tasks,
                running_ns: total.running_ns,
                runnable_wait_ns: total.runnable_wait_ns,
                timeslices: total.timeslices,
                runnable_delay_fraction: total.runnable_wait_ns as f64 / elapsed.as_nanos() as f64,
            });
        }
    }
    processes.sort_unstable_by(|left, right| {
        right
            .cpu_ticks
            .cmp(&left.cpu_ticks)
            .then_with(|| left.key.cmp(&right.key))
    });
    scheduler_delay_candidates.sort_unstable_by(|left, right| {
        right
            .runnable_wait_ns
            .cmp(&left.runnable_wait_ns)
            .then_with(|| left.key.cmp(&right.key))
    });
    for (key, end_process) in &end.processes {
        if let Some(start_process) = start.processes.get(key) {
            for thread in end_process.schedstat.keys() {
                if !start_process.schedstat.contains_key(thread) {
                    schedstat_collection_issues.task_appeared =
                        schedstat_collection_issues.task_appeared.saturating_add(1);
                }
                if start_process.schedstat.keys().any(|old| {
                    old.tid == thread.tid && old.start_time_ticks != thread.start_time_ticks
                }) {
                    schedstat_collection_issues.task_identity_changed = schedstat_collection_issues
                        .task_identity_changed
                        .saturating_add(1);
                }
            }
            for thread in start_process.schedstat.keys() {
                if !end_process.schedstat.contains_key(thread) {
                    schedstat_collection_issues.task_exited =
                        schedstat_collection_issues.task_exited.saturating_add(1);
                }
            }
        }
    }
    let mut schedstat_capability =
        schedstat_capability(&schedstat_collection_issues, &collection_issues);
    if schedstat_capability == SchedstatCapability::Available
        && schedstat_collection_issues.tasks_read != 0
        && schedstat_collection_issues.stable_tasks == 0
    {
        schedstat_capability = SchedstatCapability::Partial;
    }
    if schedstat_capability == SchedstatCapability::Unsupported
        && start
            .processes
            .values()
            .any(|process| !process.schedstat.is_empty())
        && end
            .processes
            .values()
            .any(|process| !process.schedstat.is_empty())
    {
        schedstat_capability = SchedstatCapability::Partial;
    }
    Ok(CpuProcessObservation {
        elapsed,
        clock_ticks_per_second,
        host: HostCpuInterval {
            total_ticks,
            busy_ticks,
            idle_ticks,
            utilization_fraction: busy_ticks as f64 / total_ticks as f64,
            cpu_count: end.host.cpu_count,
        },
        load: end.load,
        load_availability: end.load_availability,
        processes,
        collection_issues,
        scheduler_delay_candidates,
        schedstat_collection_issues,
        schedstat_capability,
    })
}

fn merge_schedstat_issues(
    start: SchedstatCollectionIssues,
    end: SchedstatCollectionIssues,
) -> SchedstatCollectionIssues {
    SchedstatCollectionIssues {
        task_enumeration_failed: start
            .task_enumeration_failed
            .saturating_add(end.task_enumeration_failed),
        task_enumeration_errors: start
            .task_enumeration_errors
            .saturating_add(end.task_enumeration_errors),
        task_disappeared: start.task_disappeared.saturating_add(end.task_disappeared),
        task_unsupported: start.task_unsupported.saturating_add(end.task_unsupported),
        task_appeared: 0,
        task_exited: 0,
        task_identity_changed: start
            .task_identity_changed
            .saturating_add(end.task_identity_changed),
        task_permission_denied: start
            .task_permission_denied
            .saturating_add(end.task_permission_denied),
        task_unreadable: start.task_unreadable.saturating_add(end.task_unreadable),
        task_malformed: start.task_malformed.saturating_add(end.task_malformed),
        aggregate_overflow: start
            .aggregate_overflow
            .saturating_add(end.aggregate_overflow),
        counter_regressed: start
            .counter_regressed
            .saturating_add(end.counter_regressed),
        task_limit_reached: start.task_limit_reached || end.task_limit_reached,
        tasks_read: start.tasks_read.saturating_add(end.tasks_read),
        stable_tasks: 0,
    }
}

fn merge_issues(
    start: ProcessCollectionIssues,
    end: ProcessCollectionIssues,
) -> ProcessCollectionIssues {
    ProcessCollectionIssues {
        enumeration_failed: start.enumeration_failed || end.enumeration_failed,
        enumeration_errors: start
            .enumeration_errors
            .saturating_add(end.enumeration_errors),
        disappeared: start.disappeared.saturating_add(end.disappeared),
        permission_denied: start
            .permission_denied
            .saturating_add(end.permission_denied),
        unreadable: start.unreadable.saturating_add(end.unreadable),
        malformed: start.malformed.saturating_add(end.malformed),
        counter_regressed: start
            .counter_regressed
            .saturating_add(end.counter_regressed),
        appeared: 0,
        exited: 0,
        limit_reached: start.limit_reached || end.limit_reached,
    }
}

pub fn sanitized_process_name(name: &str) -> String {
    let mut result = String::new();
    for character in name.chars().take(MAX_PROCESS_NAME_CHARS) {
        result.push(if character.is_control() {
            '\u{fffd}'
        } else {
            character
        });
    }
    if name.chars().count() > MAX_PROCESS_NAME_CHARS {
        result.push('…');
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROC_STAT: &str = include_str!("../tests/fixtures/proc-stat-valid");
    const LOADAVG: &str = include_str!("../tests/fixtures/proc-loadavg-valid");
    const PID_STAT: &str = include_str!("../tests/fixtures/proc-pid-stat-unusual-name");
    const SCHEDSTAT: &str = include_str!("../tests/fixtures/proc-schedstat-valid");

    fn proc_fixture(with_sysctl_zero: bool) -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("bottleneck-proc-{}-{nonce}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("123/task/123")).unwrap();
        fs::write(root.join("stat"), PROC_STAT).unwrap();
        fs::write(root.join("loadavg"), LOADAVG).unwrap();
        fs::write(root.join("123/stat"), PID_STAT).unwrap();
        fs::write(root.join("123/task/123/stat"), PID_STAT).unwrap();
        fs::write(root.join("123/task/123/schedstat"), SCHEDSTAT).unwrap();
        if with_sysctl_zero {
            fs::create_dir_all(root.join("sys/kernel")).unwrap();
            fs::write(root.join("sys/kernel/sched_schedstats"), "0\n").unwrap();
        }
        root
    }

    #[test]
    fn parses_host_stat_without_double_counting_guest_ticks() {
        let parsed = parse_proc_stat(PROC_STAT).unwrap();
        assert_eq!(parsed.total_without_iowait_ticks, 900);
        assert_eq!(parsed.busy_ticks, 600);
        assert_eq!(parsed.iowait_ticks, 100);
        assert_eq!(parsed.cpu_count, 2);
    }

    #[test]
    fn parses_loadavg_and_unusual_process_name() {
        assert_eq!(parse_loadavg(LOADAVG).unwrap().runnable_tasks, 3);
        let process = parse_process_stat(PID_STAT).unwrap();
        assert_eq!(process.comm, "a weird ) name");
        assert_eq!(process.key.start_time_ticks, 987);
        assert_eq!(process.user_ticks, 42);
    }

    #[test]
    fn parses_exactly_three_schedstat_counters() {
        assert_eq!(
            parse_schedstat(SCHEDSTAT).unwrap(),
            SchedstatRaw {
                running_ns: 100,
                runnable_wait_ns: 200,
                timeslices: 3
            }
        );
        for input in [
            "10 20",
            "10 20 30 40",
            "10 nope 30",
            "18446744073709551616 1 1",
        ] {
            assert_eq!(parse_schedstat(input), Err(CpuError::Malformed));
        }
    }

    #[test]
    fn direct_schedstat_reads_ignore_sysctl_zero_or_absence() {
        for with_sysctl_zero in [false, true] {
            let root = proc_fixture(with_sysctl_zero);
            let snapshot = read_snapshot(&root).unwrap();
            assert_eq!(
                snapshot.processes.values().next().unwrap().schedstat.len(),
                1
            );
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn rejects_malformed_procfs_fields() {
        for input in [
            "cpu 1 2 3\n",
            "cpu 1 x 3 4\n",
            "cpu 18446744073709551615 1 1 1 1 1 1 1\n",
        ] {
            assert!(parse_proc_stat(input).is_err());
        }
        for input in [
            "0.1 0.2 0.3 1/nope 4\n",
            "nan 0.2 0.3 1/2 4\n",
            "0.1 0.2 0.3 0/0 4\n",
            "0.1 0.2 0.3 3/2 4\n",
        ] {
            assert!(parse_loadavg(input).is_err());
        }
        for input in ["1 no-parentheses S 0", "1 (x) S 0 0"] {
            assert!(parse_process_stat(input).is_err());
        }
    }

    fn snapshot(total: u64, busy: u64, iowait: u64, processes: Vec<ProcessRaw>) -> CpuSnapshot {
        CpuSnapshot {
            host: HostCpuRaw {
                total_without_iowait_ticks: total,
                busy_ticks: busy,
                iowait_ticks: iowait,
                cpu_count: 2,
            },
            load: Some(parse_loadavg(LOADAVG).unwrap()),
            load_availability: LoadAverageAvailability::Available,
            processes: processes
                .into_iter()
                .map(|process| (process.key, process))
                .collect(),
            issues: ProcessCollectionIssues::default(),
            schedstat_issues: SchedstatCollectionIssues::default(),
        }
    }
    fn process(pid: u32, start: u64, ticks: u64) -> ProcessRaw {
        ProcessRaw {
            key: ProcessKey {
                pid,
                start_time_ticks: start,
            },
            comm: format!("p{pid}"),
            state: 'R',
            user_ticks: ticks,
            system_ticks: 0,
            schedstat: BTreeMap::new(),
        }
    }

    #[test]
    fn normalizes_host_and_matching_processes_only() {
        let start = snapshot(1_000, 600, 400, vec![process(1, 10, 20), process(2, 20, 3)]);
        let end = snapshot(1_200, 720, 480, vec![process(1, 10, 45), process(3, 30, 9)]);
        let observation = interval_from_snapshots(start, end, Duration::from_secs(1)).unwrap();
        assert_eq!(observation.host.busy_ticks, 120);
        assert_eq!(observation.processes.len(), 1);
        assert_eq!(observation.processes[0].key.pid, 1);
        assert_eq!(observation.processes[0].cpu_ticks, 25);
        assert_eq!(observation.collection_issues.appeared, 1);
        assert_eq!(observation.collection_issues.exited, 1);
    }

    #[test]
    fn excludes_pid_reuse_and_rejects_regressing_counters() {
        let start = snapshot(100, 60, 40, vec![process(7, 1, 50)]);
        let end = snapshot(110, 70, 40, vec![process(7, 2, 1)]);
        assert!(
            interval_from_snapshots(start, end, Duration::from_secs(1))
                .unwrap()
                .processes
                .is_empty()
        );
        assert_eq!(
            interval_from_snapshots(
                snapshot(10, 5, 5, vec![]),
                snapshot(9, 5, 4, vec![]),
                Duration::from_secs(1)
            ),
            Err(CpuError::CounterRegressed)
        );
    }

    #[test]
    fn qualifies_a_regressing_process_counter_without_losing_host_evidence() {
        let start = snapshot(100, 60, 40, vec![process(7, 1, 50)]);
        let end = snapshot(110, 70, 40, vec![process(7, 1, 49)]);
        let observation = interval_from_snapshots(start, end, Duration::from_secs(1)).unwrap();
        assert!(observation.processes.is_empty());
        assert_eq!(observation.collection_issues.counter_regressed, 1);
    }

    #[test]
    fn enumeration_failure_keeps_host_capability_available() {
        let mut snapshot = snapshot(100, 60, 40, vec![]);
        snapshot.issues.enumeration_failed = true;
        assert_eq!(
            telemetry_capabilities(Ok(snapshot)),
            CpuTelemetryCapabilities {
                host_cpu: CollectorCapability::Available,
                process_stat: CollectorCapability::Failed,
                process_schedstat: SchedstatCapability::Failed,
            }
        );
    }

    #[test]
    fn bounded_pid_selection_keeps_the_lowest_pids() {
        let mut issues = ProcessCollectionIssues::default();
        let mut pids = BinaryHeap::with_capacity(MAX_PROCESSES);
        for pid in (0..=MAX_PROCESSES as u32).rev() {
            insert_lowest_pid(&mut pids, pid, &mut issues);
        }
        let mut selected = pids.into_vec();
        selected.sort_unstable();
        assert_eq!(selected.first(), Some(&0));
        assert_eq!(selected.last(), Some(&(MAX_PROCESSES as u32 - 1)));
        assert!(issues.limit_reached);
    }

    #[test]
    fn bounded_task_selection_keeps_lowest_tids() {
        let mut issues = SchedstatCollectionIssues::default();
        let mut tids = BinaryHeap::new();
        for tid in [9, 4, 8, 1, 3] {
            insert_lowest_task(&mut tids, tid, 3, &mut issues);
        }
        let mut selected = tids.into_vec();
        selected.sort_unstable();
        assert_eq!(selected, vec![1, 3, 4]);
        assert!(issues.task_limit_reached);
    }

    #[test]
    fn process_collection_errors_make_capability_partial() {
        for issues in [
            ProcessCollectionIssues {
                unreadable: 1,
                ..ProcessCollectionIssues::default()
            },
            ProcessCollectionIssues {
                enumeration_errors: 1,
                ..ProcessCollectionIssues::default()
            },
            ProcessCollectionIssues {
                counter_regressed: 1,
                ..ProcessCollectionIssues::default()
            },
        ] {
            assert_eq!(process_capability(&issues), CollectorCapability::Partial);
        }
    }

    #[test]
    fn mixed_schedstat_support_is_partial() {
        let issues = SchedstatCollectionIssues {
            tasks_read: 1,
            task_unsupported: 1,
            ..SchedstatCollectionIssues::default()
        };
        assert_eq!(
            schedstat_capability(&issues, &ProcessCollectionIssues::default()),
            SchedstatCapability::Partial
        );
    }

    #[test]
    fn tolerates_decreasing_iowait_when_aggregate_cpu_time_increases() {
        let start = snapshot(1_000, 600, 400, vec![]);
        let end = snapshot(1_100, 680, 390, vec![]);
        let observation = interval_from_snapshots(start, end, Duration::from_secs(1)).unwrap();
        assert_eq!(observation.host.idle_ticks, 20);
    }

    #[test]
    fn process_names_are_bounded_and_safe_for_terminal_output() {
        assert_eq!(sanitized_process_name("ok\nname"), "ok�name");
        assert_eq!(
            sanitized_process_name(&"x".repeat(81)),
            format!("{}…", "x".repeat(80))
        );
    }

    #[test]
    fn normalizes_thread_aggregated_scheduler_delay_for_stable_processes() {
        let mut first = process(7, 1, 10);
        first.schedstat = BTreeMap::from([
            (
                ThreadKey {
                    tid: 7,
                    start_time_ticks: 11,
                },
                SchedstatRaw {
                    running_ns: 100,
                    runnable_wait_ns: 200,
                    timeslices: 3,
                },
            ),
            (
                ThreadKey {
                    tid: 8,
                    start_time_ticks: 12,
                },
                SchedstatRaw {
                    running_ns: 50,
                    runnable_wait_ns: 50,
                    timeslices: 1,
                },
            ),
        ]);
        let mut second = process(7, 1, 20);
        second.schedstat = BTreeMap::from([
            (
                ThreadKey {
                    tid: 7,
                    start_time_ticks: 11,
                },
                SchedstatRaw {
                    running_ns: 180,
                    runnable_wait_ns: 600,
                    timeslices: 7,
                },
            ),
            (
                ThreadKey {
                    tid: 8,
                    start_time_ticks: 12,
                },
                SchedstatRaw {
                    running_ns: 70,
                    runnable_wait_ns: 100,
                    timeslices: 2,
                },
            ),
        ]);
        let observation = interval_from_snapshots(
            snapshot(100, 60, 40, vec![first]),
            snapshot(110, 70, 40, vec![second]),
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(observation.scheduler_delay_candidates.len(), 1);
        let candidate = &observation.scheduler_delay_candidates[0];
        assert_eq!(candidate.runnable_wait_ns, 450);
        assert_eq!(candidate.running_ns, 100);
        assert_eq!(candidate.task_count, 2);
        assert_eq!(candidate.runnable_delay_fraction, 0.000_000_45);
    }

    #[test]
    fn excludes_regressing_scheduler_delay_without_losing_cpu_observation() {
        let mut first = process(7, 1, 10);
        first.schedstat = BTreeMap::from([(
            ThreadKey {
                tid: 7,
                start_time_ticks: 11,
            },
            SchedstatRaw {
                running_ns: 10,
                runnable_wait_ns: 20,
                timeslices: 3,
            },
        )]);
        let mut second = process(7, 1, 20);
        second.schedstat = BTreeMap::from([(
            ThreadKey {
                tid: 7,
                start_time_ticks: 11,
            },
            SchedstatRaw {
                running_ns: 11,
                runnable_wait_ns: 19,
                timeslices: 4,
            },
        )]);
        let observation = interval_from_snapshots(
            snapshot(100, 60, 40, vec![first]),
            snapshot(110, 70, 40, vec![second]),
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(observation.processes.len(), 1);
        assert!(observation.scheduler_delay_candidates.is_empty());
        assert_eq!(observation.schedstat_collection_issues.counter_regressed, 1);
        assert_eq!(
            observation.schedstat_capability,
            SchedstatCapability::Partial
        );
    }

    #[test]
    fn tid_reuse_does_not_merge_scheduler_counters() {
        let mut first = process(7, 1, 10);
        first.schedstat.insert(
            ThreadKey {
                tid: 9,
                start_time_ticks: 10,
            },
            SchedstatRaw {
                running_ns: 10,
                runnable_wait_ns: 20,
                timeslices: 1,
            },
        );
        let mut second = process(7, 1, 20);
        second.schedstat.insert(
            ThreadKey {
                tid: 9,
                start_time_ticks: 11,
            },
            SchedstatRaw {
                running_ns: 100,
                runnable_wait_ns: 200,
                timeslices: 2,
            },
        );
        let observation = interval_from_snapshots(
            snapshot(100, 60, 40, vec![first]),
            snapshot(110, 70, 40, vec![second]),
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(observation.scheduler_delay_candidates.is_empty());
        assert_eq!(
            observation.schedstat_capability,
            SchedstatCapability::Partial
        );
    }

    #[test]
    fn thread_exit_is_counted_and_makes_schedstat_partial() {
        let mut first = process(7, 1, 10);
        first.schedstat.insert(
            ThreadKey {
                tid: 7,
                start_time_ticks: 1,
            },
            SchedstatRaw {
                running_ns: 1,
                runnable_wait_ns: 2,
                timeslices: 1,
            },
        );
        first.schedstat.insert(
            ThreadKey {
                tid: 8,
                start_time_ticks: 2,
            },
            SchedstatRaw {
                running_ns: 1,
                runnable_wait_ns: 2,
                timeslices: 1,
            },
        );
        let mut second = process(7, 1, 20);
        second.schedstat.insert(
            ThreadKey {
                tid: 7,
                start_time_ticks: 1,
            },
            SchedstatRaw {
                running_ns: 2,
                runnable_wait_ns: 4,
                timeslices: 2,
            },
        );
        let observation = interval_from_snapshots(
            snapshot(100, 60, 40, vec![first]),
            snapshot(110, 70, 40, vec![second]),
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(observation.schedstat_collection_issues.task_exited, 1);
        assert_eq!(
            observation.schedstat_capability,
            SchedstatCapability::Partial
        );
    }

    #[test]
    fn cpu_counter_regression_keeps_stable_scheduler_delay() {
        let mut first = process(7, 1, 20);
        first.schedstat.insert(
            ThreadKey {
                tid: 7,
                start_time_ticks: 10,
            },
            SchedstatRaw {
                running_ns: 10,
                runnable_wait_ns: 20,
                timeslices: 1,
            },
        );
        let mut second = process(7, 1, 10);
        second.schedstat.insert(
            ThreadKey {
                tid: 7,
                start_time_ticks: 10,
            },
            SchedstatRaw {
                running_ns: 20,
                runnable_wait_ns: 40,
                timeslices: 2,
            },
        );
        let observation = interval_from_snapshots(
            snapshot(100, 60, 40, vec![first]),
            snapshot(110, 70, 40, vec![second]),
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(observation.processes.is_empty());
        assert_eq!(
            observation.scheduler_delay_candidates[0].runnable_wait_ns,
            20
        );
    }
}
