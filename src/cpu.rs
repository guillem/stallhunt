use std::collections::{BTreeMap, BinaryHeap};
use std::fs;
use std::io;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::psi::{self, CpuPsiError, CpuPsiObservation};

const MAX_PROCESSES: usize = 4_096;
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

#[derive(Debug, Clone, PartialEq)]
pub struct CpuSnapshot {
    pub host: HostCpuRaw,
    pub load: Option<LoadAverageRaw>,
    pub load_availability: LoadAverageAvailability,
    pub processes: BTreeMap<ProcessKey, ProcessRaw>,
    pub issues: ProcessCollectionIssues,
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
pub struct CpuProcessObservation {
    pub elapsed: Duration,
    pub clock_ticks_per_second: u64,
    pub host: HostCpuInterval,
    pub load: Option<LoadAverageRaw>,
    pub load_availability: LoadAverageAvailability,
    pub processes: Vec<ProcessCpuInterval>,
    pub collection_issues: ProcessCollectionIssues,
}

#[derive(Debug)]
pub struct HuntObservation {
    pub psi: Result<CpuPsiObservation, CpuPsiError>,
    pub cpu: Result<CpuProcessObservation, CpuError>,
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
        },
        Ok(snapshot) => {
            let issues = snapshot.issues;
            let process_stat = process_capability(&issues);
            CpuTelemetryCapabilities {
                host_cpu: CollectorCapability::Available,
                process_stat,
            }
        }
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

pub fn observe_hunt(requested: Duration) -> HuntObservation {
    if requested.is_zero() {
        return HuntObservation {
            psi: Err(CpuPsiError::EmptyInterval),
            cpu: Err(CpuError::EmptyInterval),
        };
    }

    let psi_start = psi::read_cpu_psi();
    let psi_started_at = Instant::now();
    let cpu_start = read_snapshot(Path::new("/proc"));
    let cpu_started_at = Instant::now();
    thread::sleep(requested);
    let cpu_end = read_snapshot(Path::new("/proc"));
    let cpu_ended_at = Instant::now();
    let psi_end = psi::read_cpu_psi();
    let psi_ended_at = Instant::now();

    let psi = match (psi_start, psi_end) {
        (Ok(start), Ok(end)) => {
            psi::interval_from_raw(start, end, psi_ended_at.duration_since(psi_started_at)).map(
                |interval| CpuPsiObservation {
                    requested,
                    interval,
                    start,
                    end,
                },
            )
        }
        (Err(error), _) | (_, Err(error)) => Err(error),
    };
    let cpu = match (cpu_start, cpu_end) {
        (Ok(start), Ok(end)) => {
            interval_from_snapshots(start, end, cpu_ended_at.duration_since(cpu_started_at))
        }
        (Err(error), _) | (_, Err(error)) => Err(error),
    };

    HuntObservation { psi, cpu }
}

fn read_snapshot(proc_root: &Path) -> Result<CpuSnapshot, CpuError> {
    let stat = fs::read_to_string(proc_root.join("stat")).map_err(map_io_error)?;
    let host = parse_proc_stat(&stat)?;
    let (load, load_availability) = match fs::read_to_string(proc_root.join("loadavg")) {
        Ok(contents) => match parse_loadavg(&contents) {
            Ok(load) => (Some(load), LoadAverageAvailability::Available),
            Err(_) => (None, LoadAverageAvailability::Malformed),
        },
        Err(_) => (None, LoadAverageAvailability::Unreadable),
    };
    let (processes, issues) = collect_processes(proc_root);
    Ok(CpuSnapshot {
        host,
        load,
        load_availability,
        processes,
        issues,
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
    })
}

fn collect_processes(
    proc_root: &Path,
) -> (BTreeMap<ProcessKey, ProcessRaw>, ProcessCollectionIssues) {
    let mut issues = ProcessCollectionIssues::default();
    let Ok(entries) = fs::read_dir(proc_root) else {
        issues.enumeration_failed = true;
        return (BTreeMap::new(), issues);
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
    for pid in pids {
        match fs::read_to_string(proc_root.join(pid.to_string()).join("stat")) {
            Ok(contents) => match parse_process_stat(&contents) {
                Ok(process) => {
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
    (processes, issues)
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
    for (key, end_process) in &end.processes {
        let Some(start_process) = start.processes.get(key) else {
            continue;
        };
        let Some(end_ticks) = end_process.cpu_ticks() else {
            collection_issues.counter_regressed += 1;
            continue;
        };
        let Some(start_ticks) = start_process.cpu_ticks() else {
            collection_issues.counter_regressed += 1;
            continue;
        };
        let Some(ticks) = end_ticks.checked_sub(start_ticks) else {
            collection_issues.counter_regressed += 1;
            continue;
        };
        processes.push(ProcessCpuInterval {
            key: *key,
            name: sanitized_process_name(&end_process.comm),
            state: end_process.state,
            cpu_ticks: ticks,
            cpu_fraction_of_one: ticks as f64 / clock_ticks_per_second as f64 / elapsed_seconds,
        });
    }
    processes.sort_unstable_by(|left, right| {
        right
            .cpu_ticks
            .cmp(&left.cpu_ticks)
            .then_with(|| left.key.cmp(&right.key))
    });
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
    })
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
                process_stat: CollectorCapability::Failed
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
}
