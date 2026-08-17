//! Bounded procfs block-I/O context. This is raw activity context, not an I/O
//! bottleneck verdict or a causal attribution model.

use std::collections::{BTreeMap, BinaryHeap};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;
use std::time::Duration;

use serde::Serialize;

use crate::cpu::{ProcessKey, ProcessRaw, parse_process_stat, sanitized_process_name};

// Each endpoint selects at most 1,024 lowest PIDs. A successful sample reads
// stat -> io -> stat, so process-I/O file reads are bounded at 3,072 per
// endpoint (plus one bounded directory enumeration).
const MAX_PROCESSES: usize = 1_024;
const MAX_DEVICES: usize = 4_096;
const MAX_DISKSTATS_BYTES: u64 = 1_048_576;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct BlockDeviceKey {
    pub major: u32,
    pub minor: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiskstatsRaw {
    pub key: BlockDeviceKey,
    /// Presentation metadata only; major/minor is the stable identity.
    pub name: String,
    pub reads_completed: u64,
    /// Kernel diskstats sectors: raw 512-byte sector units, not bytes.
    pub sectors_read_512: u64,
    pub writes_completed: u64,
    /// Kernel diskstats sectors: raw 512-byte sector units, not bytes.
    pub sectors_written_512: u64,
    pub io_ticks_ms: u64,
    pub weighted_io_ticks_ms: u64,
    /// Endpoint gauge, not an interval counter.
    pub in_flight: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DiskstatsSnapshot {
    pub devices: BTreeMap<BlockDeviceKey, DiskstatsRaw>,
    pub issues: DiskstatsCollectionIssues,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct DiskstatsCollectionIssues {
    pub limit_reached: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IoCapability {
    Available,
    Partial,
    Unsupported,
    PermissionDenied,
    Failed,
}

impl IoCapability {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Partial => "partial",
            Self::Unsupported => "unsupported",
            Self::PermissionDenied => "permission_denied",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct IoCapabilities {
    pub diskstats: IoCapability,
    pub process_io: IoCapability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiskstatsError {
    Unsupported,
    PermissionDenied,
    Unreadable,
    Malformed,
    EmptyInterval,
}

impl DiskstatsError {
    const fn capability(self) -> IoCapability {
        match self {
            Self::Unsupported => IoCapability::Unsupported,
            Self::PermissionDenied => IoCapability::PermissionDenied,
            Self::Unreadable | Self::Malformed | Self::EmptyInterval => IoCapability::Failed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiskstatsInterval {
    pub key: BlockDeviceKey,
    pub name: String,
    pub reads_completed: Option<u64>,
    pub sectors_read_512: Option<u64>,
    pub writes_completed: Option<u64>,
    pub sectors_written_512: Option<u64>,
    pub io_ticks_ms: Option<u64>,
    pub weighted_io_ticks_ms: Option<u64>,
    pub end_in_flight: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct DiskstatsIntervalIssues {
    pub start_error: Option<DiskstatsError>,
    pub end_error: Option<DiskstatsError>,
    pub appeared: Vec<BlockDeviceKey>,
    pub exited: Vec<BlockDeviceKey>,
    pub identity_changed: Vec<BlockDeviceKey>,
    pub regressed: Vec<DiskstatsCounterRegression>,
    pub limit_reached: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiskstatsCounter {
    ReadsCompleted,
    SectorsRead512,
    WritesCompleted,
    SectorsWritten512,
    IoTicksMs,
    WeightedIoTicksMs,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiskstatsCounterRegression {
    pub key: BlockDeviceKey,
    pub counter: DiskstatsCounter,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiskstatsObservation {
    #[serde(skip)]
    pub elapsed: Duration,
    pub capability: IoCapability,
    pub devices: Vec<DiskstatsInterval>,
    pub issues: DiskstatsIntervalIssues,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProcessIoRaw {
    pub read_bytes: u64,
    /// Bytes charged at page-dirtying time, not proof they reached storage.
    pub write_bytes: u64,
    /// Dirty-byte charges cancelled by truncation; this may cancel I/O charged
    /// to another task, so it is not a safe per-process subtraction.
    pub cancelled_write_bytes: Option<u64>,
    /// Logical bytes read context; not a backing-storage attribution signal.
    pub rchar: Option<u64>,
    /// Logical bytes written context; not a backing-storage attribution signal.
    pub wchar: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProcessIoSnapshot {
    pub processes: BTreeMap<ProcessKey, ProcessIoSample>,
    pub issues: ProcessIoCollectionIssues,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessIoSample {
    pub name: String,
    pub counters: ProcessIoRaw,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct ProcessIoCollectionIssues {
    /// `/proc/<pid>/io` 64-bit counters may tear on 32-bit kernels/userspace.
    pub counter_width_unsupported: bool,
    pub enumeration_failed: bool,
    pub enumeration_errors: u32,
    pub disappeared: u32,
    pub identity_changed: u32,
    pub permission_denied: u32,
    pub unsupported: u32,
    pub unreadable: u32,
    pub malformed: u32,
    pub limit_reached: bool,
    pub appeared: u32,
    pub exited: u32,
    pub reused: u32,
    pub counter_regressed: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessIoCounter {
    ReadBytes,
    WriteBytes,
    CancelledWriteBytes,
    Rchar,
    Wchar,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProcessIoCounterRegression {
    pub key: ProcessKey,
    pub counter: ProcessIoCounter,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProcessIoInterval {
    pub key: ProcessKey,
    pub name: String,
    /// Individually available checked deltas. A regressed field is omitted
    /// without discarding other stable process I/O evidence.
    pub read_bytes: Option<u64>,
    pub write_bytes: Option<u64>,
    pub cancelled_write_bytes: Option<u64>,
    pub rchar: Option<u64>,
    pub wchar: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProcessIoObservation {
    #[serde(skip)]
    pub elapsed: Duration,
    pub capability: IoCapability,
    pub processes: Vec<ProcessIoInterval>,
    pub issues: ProcessIoCollectionIssues,
    pub regressed: Vec<ProcessIoCounterRegression>,
}

pub fn read_diskstats_at(proc_root: &Path) -> Result<DiskstatsSnapshot, DiskstatsError> {
    let file = File::open(proc_root.join("diskstats")).map_err(classify_diskstats_error)?;
    let mut contents = String::new();
    file.take(MAX_DISKSTATS_BYTES + 1)
        .read_to_string(&mut contents)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::InvalidData {
                DiskstatsError::Malformed
            } else {
                DiskstatsError::Unreadable
            }
        })?;
    if contents.len() as u64 > MAX_DISKSTATS_BYTES {
        return Err(DiskstatsError::Malformed);
    }
    parse_diskstats(&contents)
}

pub fn probe_io_context() -> IoCapabilities {
    let diskstats = match read_diskstats_at(Path::new("/proc")) {
        Ok(snapshot) if snapshot.issues.limit_reached => IoCapability::Partial,
        Ok(_) => IoCapability::Available,
        Err(error) => error.capability(),
    };
    let process_snapshot = read_process_io_snapshot_at(Path::new("/proc"));
    let process_io = process_io_capability(
        &process_snapshot.issues,
        !process_snapshot.processes.is_empty(),
    );
    IoCapabilities {
        diskstats,
        process_io,
    }
}

pub fn parse_diskstats(input: &str) -> Result<DiskstatsSnapshot, DiskstatsError> {
    let mut devices = BTreeMap::new();
    let mut issues = DiskstatsCollectionIssues::default();
    for line in input.lines().filter(|line| !line.trim().is_empty()) {
        let mut fields = line.split_ascii_whitespace();
        // major, minor, name, then at least the eleven historic fields through
        // weighted time. Later kernel fields are intentionally ignored.
        let key = BlockDeviceKey {
            major: next_diskstats_field(&mut fields)?
                .parse()
                .map_err(|_| DiskstatsError::Malformed)?,
            minor: next_diskstats_field(&mut fields)?
                .parse()
                .map_err(|_| DiskstatsError::Malformed)?,
        };
        let name = next_diskstats_field(&mut fields)?;
        if name.is_empty() || devices.contains_key(&key) {
            return Err(DiskstatsError::Malformed);
        }
        let raw = DiskstatsRaw {
            key,
            name: name.to_owned(),
            reads_completed: next_diskstats_number(&mut fields)?,
            sectors_read_512: {
                let _reads_merged = next_diskstats_number(&mut fields)?;
                next_diskstats_number(&mut fields)?
            },
            writes_completed: {
                let _read_ticks = next_diskstats_number(&mut fields)?;
                next_diskstats_number(&mut fields)?
            },
            sectors_written_512: {
                let _writes_merged = next_diskstats_number(&mut fields)?;
                next_diskstats_number(&mut fields)?
            },
            in_flight: {
                let _write_ticks = next_diskstats_number(&mut fields)?;
                next_diskstats_number(&mut fields)?
            },
            io_ticks_ms: next_diskstats_number(&mut fields)?,
            weighted_io_ticks_ms: next_diskstats_number(&mut fields)?,
        };
        insert_lowest_device(&mut devices, raw, &mut issues);
    }
    if devices.is_empty() {
        return Err(DiskstatsError::Malformed);
    }
    Ok(DiskstatsSnapshot { devices, issues })
}

pub fn diskstats_interval_from_snapshots(
    start: Result<DiskstatsSnapshot, DiskstatsError>,
    end: Result<DiskstatsSnapshot, DiskstatsError>,
    elapsed: Duration,
) -> Result<DiskstatsObservation, DiskstatsError> {
    if elapsed.is_zero() {
        return Err(DiskstatsError::EmptyInterval);
    }
    let (start, end) = match (start, end) {
        (Ok(start), Ok(end)) => (start, end),
        (Ok(_), Err(error)) => {
            return Ok(DiskstatsObservation {
                elapsed,
                capability: IoCapability::Partial,
                devices: Vec::new(),
                issues: DiskstatsIntervalIssues {
                    end_error: Some(error),
                    ..Default::default()
                },
            });
        }
        (Err(error), Ok(_)) => {
            return Ok(DiskstatsObservation {
                elapsed,
                capability: IoCapability::Partial,
                devices: Vec::new(),
                issues: DiskstatsIntervalIssues {
                    start_error: Some(error),
                    ..Default::default()
                },
            });
        }
        (Err(left), Err(right)) if left == right => {
            return Ok(DiskstatsObservation {
                elapsed,
                capability: left.capability(),
                devices: Vec::new(),
                issues: DiskstatsIntervalIssues {
                    start_error: Some(left),
                    end_error: Some(right),
                    ..Default::default()
                },
            });
        }
        (Err(left), Err(right)) => {
            return Ok(DiskstatsObservation {
                elapsed,
                capability: IoCapability::Failed,
                devices: Vec::new(),
                issues: DiskstatsIntervalIssues {
                    start_error: Some(left),
                    end_error: Some(right),
                    ..Default::default()
                },
            });
        }
    };
    let mut issues = DiskstatsIntervalIssues {
        limit_reached: start.issues.limit_reached || end.issues.limit_reached,
        ..Default::default()
    };
    let mut devices = Vec::new();
    for (key, end_raw) in &end.devices {
        let Some(start_raw) = start.devices.get(key) else {
            issues.appeared.push(*key);
            continue;
        };
        if start_raw.name != end_raw.name {
            issues.identity_changed.push(*key);
            continue;
        }
        let reads_completed = checked_disk_delta(
            key,
            DiskstatsCounter::ReadsCompleted,
            start_raw.reads_completed,
            end_raw.reads_completed,
            &mut issues.regressed,
        );
        let sectors_read_512 = checked_disk_delta(
            key,
            DiskstatsCounter::SectorsRead512,
            start_raw.sectors_read_512,
            end_raw.sectors_read_512,
            &mut issues.regressed,
        );
        let writes_completed = checked_disk_delta(
            key,
            DiskstatsCounter::WritesCompleted,
            start_raw.writes_completed,
            end_raw.writes_completed,
            &mut issues.regressed,
        );
        let sectors_written_512 = checked_disk_delta(
            key,
            DiskstatsCounter::SectorsWritten512,
            start_raw.sectors_written_512,
            end_raw.sectors_written_512,
            &mut issues.regressed,
        );
        let io_ticks_ms = checked_disk_delta(
            key,
            DiskstatsCounter::IoTicksMs,
            start_raw.io_ticks_ms,
            end_raw.io_ticks_ms,
            &mut issues.regressed,
        );
        let weighted_io_ticks_ms = checked_disk_delta(
            key,
            DiskstatsCounter::WeightedIoTicksMs,
            start_raw.weighted_io_ticks_ms,
            end_raw.weighted_io_ticks_ms,
            &mut issues.regressed,
        );
        if reads_completed.is_some()
            || sectors_read_512.is_some()
            || writes_completed.is_some()
            || sectors_written_512.is_some()
            || io_ticks_ms.is_some()
            || weighted_io_ticks_ms.is_some()
        {
            devices.push(DiskstatsInterval {
                key: *key,
                name: end_raw.name.clone(),
                reads_completed,
                sectors_read_512,
                writes_completed,
                sectors_written_512,
                io_ticks_ms,
                weighted_io_ticks_ms,
                end_in_flight: end_raw.in_flight,
            });
        }
    }
    for key in start.devices.keys() {
        if !end.devices.contains_key(key) {
            issues.exited.push(*key);
        }
    }
    let capability = if issues.appeared.is_empty()
        && issues.exited.is_empty()
        && issues.identity_changed.is_empty()
        && issues.regressed.is_empty()
        && !issues.limit_reached
    {
        IoCapability::Available
    } else {
        IoCapability::Partial
    };
    Ok(DiskstatsObservation {
        elapsed,
        capability,
        devices,
        issues,
    })
}

pub fn parse_process_io(input: &str) -> Result<ProcessIoRaw, DiskstatsError> {
    let mut values = BTreeMap::new();
    for line in input.lines().filter(|line| !line.trim().is_empty()) {
        let (name, value) = line.split_once(':').ok_or(DiskstatsError::Malformed)?;
        if !matches!(
            name,
            "read_bytes" | "write_bytes" | "cancelled_write_bytes" | "rchar" | "wchar"
        ) {
            continue;
        }
        if values.contains_key(name) {
            return Err(DiskstatsError::Malformed);
        }
        let value = value.trim();
        if value.is_empty() || value.bytes().any(|byte| !byte.is_ascii_digit()) {
            return Err(DiskstatsError::Malformed);
        }
        values.insert(name, value.parse().map_err(|_| DiskstatsError::Malformed)?);
    }
    Ok(ProcessIoRaw {
        read_bytes: required_io_value(&values, "read_bytes")?,
        write_bytes: required_io_value(&values, "write_bytes")?,
        cancelled_write_bytes: values.get("cancelled_write_bytes").copied(),
        rchar: values.get("rchar").copied(),
        wchar: values.get("wchar").copied(),
    })
}

pub fn read_process_io_snapshot_at(proc_root: &Path) -> ProcessIoSnapshot {
    let mut issues = ProcessIoCollectionIssues::default();
    if usize::BITS < 64 {
        issues.counter_width_unsupported = true;
        return ProcessIoSnapshot {
            processes: BTreeMap::new(),
            issues,
        };
    }
    let entries = match fs::read_dir(proc_root) {
        Ok(entries) => entries,
        Err(_) => {
            issues.enumeration_failed = true;
            return ProcessIoSnapshot {
                processes: BTreeMap::new(),
                issues,
            };
        }
    };
    let mut pids = BinaryHeap::new();
    for entry in entries {
        match entry {
            Ok(entry) => {
                if let Some(pid) = entry
                    .file_name()
                    .to_str()
                    .and_then(|name| name.parse::<u32>().ok())
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
        let base = proc_root.join(pid.to_string());
        let first = match read_process_key(&base) {
            Ok(key) if key.pid == pid => key,
            Ok(_) => {
                issues.identity_changed = issues.identity_changed.saturating_add(1);
                continue;
            }
            Err(ProcessReadError::Disappeared) => {
                issues.disappeared = issues.disappeared.saturating_add(1);
                continue;
            }
            Err(ProcessReadError::PermissionDenied) => {
                issues.permission_denied = issues.permission_denied.saturating_add(1);
                continue;
            }
            Err(ProcessReadError::Other) => {
                issues.malformed = issues.malformed.saturating_add(1);
                continue;
            }
        };
        let raw = match fs::read_to_string(base.join("io")) {
            Ok(contents) => match parse_process_io(&contents) {
                Ok(raw) => raw,
                Err(_) => {
                    issues.malformed = issues.malformed.saturating_add(1);
                    continue;
                }
            },
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                issues.permission_denied = issues.permission_denied.saturating_add(1);
                continue;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match read_process_key(&base) {
                    Ok(key) if key == first => {
                        issues.unsupported = issues.unsupported.saturating_add(1);
                        continue;
                    }
                    Ok(_) => {
                        issues.identity_changed = issues.identity_changed.saturating_add(1);
                        continue;
                    }
                    Err(_) => {
                        issues.disappeared = issues.disappeared.saturating_add(1);
                        continue;
                    }
                }
            }
            Err(_) => {
                issues.unreadable = issues.unreadable.saturating_add(1);
                continue;
            }
        };
        match read_process_stat_raw(&base) {
            Ok(second) if second.key == first => {
                processes.insert(
                    second.key,
                    ProcessIoSample {
                        name: sanitized_process_name(&second.comm),
                        counters: raw,
                    },
                );
            }
            Ok(_) => issues.identity_changed = issues.identity_changed.saturating_add(1),
            Err(ProcessReadError::Disappeared) => {
                issues.disappeared = issues.disappeared.saturating_add(1)
            }
            Err(ProcessReadError::PermissionDenied) => {
                issues.permission_denied = issues.permission_denied.saturating_add(1)
            }
            Err(ProcessReadError::Other) => issues.malformed = issues.malformed.saturating_add(1),
        }
    }
    ProcessIoSnapshot { processes, issues }
}

pub fn process_io_interval_from_snapshots(
    start: ProcessIoSnapshot,
    end: ProcessIoSnapshot,
    elapsed: Duration,
) -> Result<ProcessIoObservation, DiskstatsError> {
    if elapsed.is_zero() {
        return Err(DiskstatsError::EmptyInterval);
    }
    let mut issues = merge_process_issues(start.issues, end.issues);
    issues.appeared = count_u32(
        end.processes
            .keys()
            .filter(|key| !start.processes.contains_key(key))
            .count(),
    );
    issues.exited = count_u32(
        start
            .processes
            .keys()
            .filter(|key| !end.processes.contains_key(key))
            .count(),
    );
    issues.reused = count_u32(
        end.processes
            .keys()
            .filter(|end_key| {
                start
                    .processes
                    .keys()
                    .any(|start_key| start_key.pid == end_key.pid && start_key != *end_key)
            })
            .count(),
    );
    let mut processes = Vec::new();
    let mut regressed = Vec::new();
    for (key, end_raw) in &end.processes {
        let Some(start_raw) = start.processes.get(key) else {
            continue;
        };
        let read_bytes = checked_process_delta(
            key,
            ProcessIoCounter::ReadBytes,
            start_raw.counters.read_bytes,
            end_raw.counters.read_bytes,
            &mut regressed,
        );
        let write_bytes = checked_process_delta(
            key,
            ProcessIoCounter::WriteBytes,
            start_raw.counters.write_bytes,
            end_raw.counters.write_bytes,
            &mut regressed,
        );
        let cancelled_write_bytes = optional_process_delta(
            key,
            ProcessIoCounter::CancelledWriteBytes,
            start_raw.counters.cancelled_write_bytes,
            end_raw.counters.cancelled_write_bytes,
            &mut regressed,
        );
        let rchar = optional_process_delta(
            key,
            ProcessIoCounter::Rchar,
            start_raw.counters.rchar,
            end_raw.counters.rchar,
            &mut regressed,
        );
        let wchar = optional_process_delta(
            key,
            ProcessIoCounter::Wchar,
            start_raw.counters.wchar,
            end_raw.counters.wchar,
            &mut regressed,
        );
        if read_bytes.is_some()
            || write_bytes.is_some()
            || cancelled_write_bytes.is_some()
            || rchar.is_some()
            || wchar.is_some()
        {
            processes.push(ProcessIoInterval {
                key: *key,
                name: end_raw.name.clone(),
                read_bytes,
                write_bytes,
                cancelled_write_bytes,
                rchar,
                wchar,
            });
        }
    }
    issues.counter_regressed = count_u32(regressed.len());
    processes.sort_unstable_by(|left, right| {
        right
            .read_bytes
            .unwrap_or(0)
            .saturating_add(right.write_bytes.unwrap_or(0))
            .cmp(
                &left
                    .read_bytes
                    .unwrap_or(0)
                    .saturating_add(left.write_bytes.unwrap_or(0)),
            )
            .then_with(|| left.key.cmp(&right.key))
    });
    let capability = process_io_capability(&issues, !processes.is_empty());
    Ok(ProcessIoObservation {
        elapsed,
        capability,
        processes,
        issues,
        regressed,
    })
}

fn required_io_value(values: &BTreeMap<&str, u64>, name: &str) -> Result<u64, DiskstatsError> {
    values.get(name).copied().ok_or(DiskstatsError::Malformed)
}

fn checked_process_delta(
    key: &ProcessKey,
    counter: ProcessIoCounter,
    start: u64,
    end: u64,
    regressed: &mut Vec<ProcessIoCounterRegression>,
) -> Option<u64> {
    end.checked_sub(start).or_else(|| {
        regressed.push(ProcessIoCounterRegression { key: *key, counter });
        None
    })
}

fn checked_disk_delta(
    key: &BlockDeviceKey,
    counter: DiskstatsCounter,
    start: u64,
    end: u64,
    regressed: &mut Vec<DiskstatsCounterRegression>,
) -> Option<u64> {
    end.checked_sub(start).or_else(|| {
        regressed.push(DiskstatsCounterRegression { key: *key, counter });
        None
    })
}

fn optional_process_delta(
    key: &ProcessKey,
    counter: ProcessIoCounter,
    start: Option<u64>,
    end: Option<u64>,
    regressed: &mut Vec<ProcessIoCounterRegression>,
) -> Option<u64> {
    match (start, end) {
        (Some(start), Some(end)) => checked_process_delta(key, counter, start, end, regressed),
        _ => None,
    }
}

fn process_io_capability(issues: &ProcessIoCollectionIssues, any_valid: bool) -> IoCapability {
    if issues.counter_width_unsupported {
        IoCapability::Unsupported
    } else if issues.enumeration_failed {
        IoCapability::Failed
    } else if any_valid
        && (issues.enumeration_errors != 0
            || issues.disappeared != 0
            || issues.identity_changed != 0
            || issues.permission_denied != 0
            || issues.unsupported != 0
            || issues.unreadable != 0
            || issues.malformed != 0
            || issues.limit_reached
            || issues.appeared != 0
            || issues.exited != 0
            || issues.reused != 0
            || issues.counter_regressed != 0)
    {
        IoCapability::Partial
    } else if any_valid {
        IoCapability::Available
    } else if issues.permission_denied != 0 {
        IoCapability::PermissionDenied
    } else if issues.unsupported != 0 {
        IoCapability::Unsupported
    } else {
        IoCapability::Failed
    }
}

fn merge_process_issues(
    start: ProcessIoCollectionIssues,
    end: ProcessIoCollectionIssues,
) -> ProcessIoCollectionIssues {
    ProcessIoCollectionIssues {
        counter_width_unsupported: start.counter_width_unsupported || end.counter_width_unsupported,
        enumeration_failed: start.enumeration_failed || end.enumeration_failed,
        enumeration_errors: start
            .enumeration_errors
            .saturating_add(end.enumeration_errors),
        disappeared: start.disappeared.saturating_add(end.disappeared),
        identity_changed: start.identity_changed.saturating_add(end.identity_changed),
        permission_denied: start
            .permission_denied
            .saturating_add(end.permission_denied),
        unsupported: start.unsupported.saturating_add(end.unsupported),
        unreadable: start.unreadable.saturating_add(end.unreadable),
        malformed: start.malformed.saturating_add(end.malformed),
        limit_reached: start.limit_reached || end.limit_reached,
        appeared: 0,
        exited: 0,
        reused: 0,
        counter_regressed: 0,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcessReadError {
    Disappeared,
    PermissionDenied,
    Other,
}
fn read_process_stat_raw(base: &Path) -> Result<ProcessRaw, ProcessReadError> {
    fs::read_to_string(base.join("stat"))
        .map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => ProcessReadError::Disappeared,
            io::ErrorKind::PermissionDenied => ProcessReadError::PermissionDenied,
            _ => ProcessReadError::Other,
        })
        .and_then(|contents| parse_process_stat(&contents).map_err(|_| ProcessReadError::Other))
}
fn read_process_key(base: &Path) -> Result<ProcessKey, ProcessReadError> {
    read_process_stat_raw(base).map(|raw| raw.key)
}
fn insert_lowest_pid(pids: &mut BinaryHeap<u32>, pid: u32, issues: &mut ProcessIoCollectionIssues) {
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
fn insert_lowest_device(
    devices: &mut BTreeMap<BlockDeviceKey, DiskstatsRaw>,
    raw: DiskstatsRaw,
    issues: &mut DiskstatsCollectionIssues,
) {
    if devices.len() < MAX_DEVICES {
        devices.insert(raw.key, raw);
    } else if devices
        .last_key_value()
        .is_some_and(|(largest, _)| raw.key < *largest)
    {
        devices.pop_last();
        devices.insert(raw.key, raw);
        issues.limit_reached = true;
    } else {
        issues.limit_reached = true;
    }
}
fn next_diskstats_field<'a>(
    fields: &mut impl Iterator<Item = &'a str>,
) -> Result<&'a str, DiskstatsError> {
    fields.next().ok_or(DiskstatsError::Malformed)
}
fn next_diskstats_number<'a>(
    fields: &mut impl Iterator<Item = &'a str>,
) -> Result<u64, DiskstatsError> {
    next_diskstats_field(fields)?
        .parse()
        .map_err(|_| DiskstatsError::Malformed)
}
fn classify_diskstats_error(error: io::Error) -> DiskstatsError {
    match error.kind() {
        io::ErrorKind::NotFound => DiskstatsError::Unsupported,
        io::ErrorKind::PermissionDenied => DiskstatsError::PermissionDenied,
        _ => DiskstatsError::Unreadable,
    }
}
fn count_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    const DISKSTATS: &str = include_str!("../tests/fixtures/proc-diskstats-valid");
    const PROCESS_IO: &str = include_str!("../tests/fixtures/proc-pid-io-valid");

    fn key(pid: u32, start_time_ticks: u64) -> ProcessKey {
        ProcessKey {
            pid,
            start_time_ticks,
        }
    }
    fn process_snapshot(entries: Vec<(ProcessKey, ProcessIoRaw)>) -> ProcessIoSnapshot {
        ProcessIoSnapshot {
            processes: entries
                .into_iter()
                .map(|(key, counters)| {
                    (
                        key,
                        ProcessIoSample {
                            name: format!("process-{}", key.pid),
                            counters,
                        },
                    )
                })
                .collect(),
            issues: ProcessIoCollectionIssues::default(),
        }
    }

    #[test]
    fn parses_strict_diskstats_fixture_and_keeps_sector_units_raw() {
        let parsed = parse_diskstats(DISKSTATS).unwrap();
        let disk = &parsed.devices[&BlockDeviceKey {
            major: 259,
            minor: 0,
        }];
        assert_eq!(disk.name, "nvme0n1");
        assert_eq!(disk.sectors_read_512, 30);
        assert_eq!(disk.in_flight, 7);
        for invalid in [
            "8 0 sda 1 2\n",
            "8 x sda 1 0 2 3 0 4 5 6 7 8 9\n",
            "8 0 sda 1 0 2 3 0 4 5 6 7 8 9\n8 0 dup 1 0 2 3 0 4 5 6 7 8 9\n",
        ] {
            assert_eq!(parse_diskstats(invalid), Err(DiskstatsError::Malformed));
        }
    }

    #[test]
    fn diskstats_selector_keeps_lowest_device_keys_under_the_cap() {
        let mut devices = BTreeMap::new();
        let mut issues = DiskstatsCollectionIssues::default();
        for minor in (0..=MAX_DEVICES as u32).rev() {
            let key = BlockDeviceKey { major: 8, minor };
            insert_lowest_device(
                &mut devices,
                DiskstatsRaw {
                    key,
                    name: format!("d{minor}"),
                    reads_completed: 0,
                    sectors_read_512: 0,
                    writes_completed: 0,
                    sectors_written_512: 0,
                    io_ticks_ms: 0,
                    weighted_io_ticks_ms: 0,
                    in_flight: 0,
                },
                &mut issues,
            );
        }
        assert_eq!(devices.len(), MAX_DEVICES);
        assert_eq!(devices.first_key_value().unwrap().0.minor, 0);
        assert_eq!(
            devices.last_key_value().unwrap().0.minor,
            MAX_DEVICES as u32 - 1
        );
        assert!(issues.limit_reached);
    }

    #[test]
    fn disk_interval_marks_lifecycle_and_regression_without_inventing_deltas() {
        let start = parse_diskstats(DISKSTATS).unwrap();
        let mut end = start.clone();
        let key = BlockDeviceKey {
            major: 259,
            minor: 0,
        };
        end.devices.get_mut(&key).unwrap().reads_completed += 2;
        end.devices.get_mut(&key).unwrap().sectors_read_512 += 8;
        end.devices.get_mut(&key).unwrap().io_ticks_ms -= 1;
        end.devices.insert(
            BlockDeviceKey {
                major: 8,
                minor: 16,
            },
            DiskstatsRaw {
                key: BlockDeviceKey {
                    major: 8,
                    minor: 16,
                },
                name: "sdb".into(),
                reads_completed: 0,
                sectors_read_512: 0,
                writes_completed: 0,
                sectors_written_512: 0,
                io_ticks_ms: 0,
                weighted_io_ticks_ms: 0,
                in_flight: 0,
            },
        );
        let observed =
            diskstats_interval_from_snapshots(Ok(start), Ok(end), Duration::from_secs(1)).unwrap();
        assert_eq!(observed.devices.len(), 2);
        assert_eq!(
            observed.devices[0].key,
            BlockDeviceKey { major: 8, minor: 0 }
        );
        let nvme = observed
            .devices
            .iter()
            .find(|device| device.key == key)
            .unwrap();
        assert_eq!(nvme.reads_completed, Some(2));
        assert_eq!(nvme.io_ticks_ms, None);
        assert_eq!(
            observed.issues.regressed,
            vec![DiskstatsCounterRegression {
                key,
                counter: DiskstatsCounter::IoTicksMs,
            }]
        );
        assert_eq!(
            observed.issues.appeared,
            vec![BlockDeviceKey {
                major: 8,
                minor: 16
            }]
        );
        assert_eq!(observed.capability, IoCapability::Partial);
    }

    #[test]
    fn disk_name_change_does_not_merge_reused_major_minor_identity() {
        let start = parse_diskstats(DISKSTATS).unwrap();
        let mut end = start.clone();
        let key = BlockDeviceKey { major: 8, minor: 0 };
        end.devices.get_mut(&key).unwrap().name = "replacement".into();
        let observed =
            diskstats_interval_from_snapshots(Ok(start), Ok(end), Duration::from_secs(1)).unwrap();
        assert!(!observed.devices.iter().any(|device| device.key == key));
        assert_eq!(observed.issues.identity_changed, vec![key]);
        assert_eq!(observed.capability, IoCapability::Partial);
    }

    #[test]
    fn diskstats_interval_retains_endpoint_failure_reasons() {
        let snapshot = parse_diskstats(DISKSTATS).unwrap();
        let partial = diskstats_interval_from_snapshots(
            Ok(snapshot.clone()),
            Err(DiskstatsError::PermissionDenied),
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(partial.capability, IoCapability::Partial);
        assert_eq!(
            partial.issues.end_error,
            Some(DiskstatsError::PermissionDenied)
        );

        let unsupported = diskstats_interval_from_snapshots(
            Err(DiskstatsError::Unsupported),
            Err(DiskstatsError::Unsupported),
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(unsupported.capability, IoCapability::Unsupported);
        assert_eq!(
            unsupported.issues.start_error,
            Some(DiskstatsError::Unsupported)
        );

        let mixed = diskstats_interval_from_snapshots(
            Err(DiskstatsError::Malformed),
            Err(DiskstatsError::PermissionDenied),
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(mixed.capability, IoCapability::Failed);
        assert_eq!(mixed.issues.start_error, Some(DiskstatsError::Malformed));
        assert_eq!(
            mixed.issues.end_error,
            Some(DiskstatsError::PermissionDenied)
        );
    }

    #[test]
    fn parses_process_io_and_requires_read_write_byte_fields() {
        let parsed = parse_process_io(PROCESS_IO).unwrap();
        assert_eq!(parsed.read_bytes, 30);
        assert_eq!(parsed.cancelled_write_bytes, Some(1));
        assert_eq!(parsed.rchar, Some(100));
        for invalid in [
            "read_bytes: 1\n",
            "read_bytes: 1\nwrite_bytes: x\n",
            "read_bytes: 1\nread_bytes: 2\nwrite_bytes: 3\n",
        ] {
            assert_eq!(parse_process_io(invalid), Err(DiskstatsError::Malformed));
        }
    }

    #[test]
    fn torn_counter_width_disables_process_io_attribution() {
        let issues = ProcessIoCollectionIssues {
            counter_width_unsupported: true,
            ..Default::default()
        };
        assert_eq!(
            process_io_capability(&issues, false),
            IoCapability::Unsupported
        );
    }

    #[test]
    fn process_interval_retains_other_fields_when_one_counter_regresses_and_detects_reuse() {
        let process = key(7, 10);
        let start = process_snapshot(vec![(
            process,
            ProcessIoRaw {
                read_bytes: 10,
                write_bytes: 20,
                cancelled_write_bytes: Some(1),
                rchar: Some(30),
                wchar: Some(40),
            },
        )]);
        let end = process_snapshot(vec![
            (
                process,
                ProcessIoRaw {
                    read_bytes: 15,
                    write_bytes: 19,
                    cancelled_write_bytes: Some(3),
                    rchar: Some(35),
                    wchar: Some(45),
                },
            ),
            (
                key(8, 20),
                ProcessIoRaw {
                    read_bytes: 0,
                    write_bytes: 0,
                    cancelled_write_bytes: None,
                    rchar: None,
                    wchar: None,
                },
            ),
        ]);
        let observed =
            process_io_interval_from_snapshots(start, end, Duration::from_secs(1)).unwrap();
        assert_eq!(observed.processes[0].read_bytes, Some(5));
        assert_eq!(observed.processes[0].write_bytes, None);
        assert_eq!(observed.processes[0].cancelled_write_bytes, Some(2));
        assert_eq!(observed.processes[0].rchar, Some(5));
        assert_eq!(observed.regressed[0].counter, ProcessIoCounter::WriteBytes);
        assert_eq!(observed.issues.appeared, 1);
        assert_eq!(observed.capability, IoCapability::Partial);
    }

    #[test]
    fn injected_proc_root_collects_only_stat_io_stat_stable_identities() {
        let root = std::env::temp_dir().join(format!(
            "bottleneck-io-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let process = root.join("123");
        fs::create_dir_all(&process).unwrap();
        fs::write(
            process.join("stat"),
            "123 (test process) R 1 2 3 4 5 6 7 8 9 10 42 7 13 14 15 16 17 18 987 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40\n",
        )
        .unwrap();
        fs::write(process.join("io"), PROCESS_IO).unwrap();
        let snapshot = read_process_io_snapshot_at(&root);
        assert_eq!(snapshot.processes.len(), 1);
        assert!(snapshot.issues == ProcessIoCollectionIssues::default());
        fs::remove_file(process.join("io")).unwrap();
        let missing_io = read_process_io_snapshot_at(&root);
        assert_eq!(missing_io.issues.unsupported, 1);
        fs::remove_file(process.join("stat")).unwrap();
        fs::remove_dir(&process).unwrap();
        fs::remove_dir(&root).unwrap();
    }

    #[test]
    fn diskstats_reader_rejects_input_beyond_the_byte_budget() {
        let root = std::env::temp_dir().join(format!(
            "bottleneck-diskstats-budget-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        fs::write(
            root.join("diskstats"),
            vec![b'x'; MAX_DISKSTATS_BYTES as usize + 1],
        )
        .unwrap();
        assert_eq!(read_diskstats_at(&root), Err(DiskstatsError::Malformed));
        fs::remove_file(root.join("diskstats")).unwrap();
        fs::remove_dir(root).unwrap();
    }
}
