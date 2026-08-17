//! Versioned normalized-observation recordings (ADR-0007).
//!
//! Recordings are not hunt JSON. They store analyzer input so `replay` can
//! re-run the current inference path. Pre-1.0 schema versions are rejected
//! rather than partially interpreted.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::cgroup::{
    CgroupCollectionIssues, CgroupCpuInterval, CgroupError, CgroupFileState, CgroupInterval,
    CgroupIoDevice, CgroupIoRaw, CgroupMemoryEventsRaw, CgroupMemoryStatRaw, CgroupObservation,
    CgroupProcessMember, CgroupPsiInterval, CgroupPsiIntervalState, CgroupResource,
};
use crate::cpu::{CpuError, CpuProcessObservation};
use crate::io::{DiskstatsError, DiskstatsObservation, ProcessIoObservation};
use crate::memory::{MemoryContextError, MemoryContextObservation};
use crate::observe::{
    CgroupHuntObservation, HuntObservation, IoHuntObservation, MemoryHuntObservation,
};
use crate::psi::{
    CpuPsiError, CpuPsiObservation, IoPsiError, IoPsiObservation, MemoryPsiError,
    MemoryPsiObservation,
};

pub const RECORDING_KIND: &str = "bottleneck.recording";
pub const RECORDING_SCHEMA_VERSION: u32 = 1;
pub const MAX_RECORDING_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Redaction {
    None,
    Identifiers,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Collected<T, E> {
    Observed { value: T },
    Unavailable { error: E },
}

impl<T, E> Collected<T, E> {
    fn from_result(result: Result<T, E>) -> Self {
        match result {
            Ok(value) => Self::Observed { value },
            Err(error) => Self::Unavailable { error },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Recording {
    pub kind: String,
    pub schema_version: u32,
    pub tool_version: String,
    pub recorded_at_unix_ms: Option<u64>,
    pub redaction: Redaction,
    pub requested_duration_ms: u64,
    pub observation: RecordedHunt,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordedHunt {
    pub cpu_psi: Collected<CpuPsiObservation, CpuPsiError>,
    pub cpu: Collected<CpuProcessObservation, CpuError>,
    pub memory: Option<RecordedMemoryHunt>,
    pub io: Option<RecordedIoHunt>,
    pub cgroup: Option<Collected<RecordedCgroup, CgroupError>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordedMemoryHunt {
    pub psi: Collected<MemoryPsiObservation, MemoryPsiError>,
    pub context: Collected<RecordedMemoryContext, MemoryContextError>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedMemoryContext {
    pub elapsed_us: u64,
    pub observation: MemoryContextObservation,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordedIoHunt {
    pub psi: Collected<IoPsiObservation, IoPsiError>,
    pub diskstats: Collected<RecordedDiskstats, DiskstatsError>,
    pub processes: Collected<RecordedProcessIo, DiskstatsError>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedDiskstats {
    pub elapsed_us: u64,
    pub observation: DiskstatsObservation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedProcessIo {
    pub elapsed_us: u64,
    pub observation: ProcessIoObservation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedCgroup {
    pub elapsed_us: u64,
    pub groups: Vec<RecordedCgroupInterval>,
    pub members: Vec<CgroupProcessMember>,
    pub issues: CgroupCollectionIssues,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedCgroupInterval {
    pub path: String,
    pub cpu: CgroupResource<CgroupCpuInterval>,
    pub memory_current_end: CgroupResource<u64>,
    pub memory_events: CgroupResource<CgroupMemoryEventsRaw>,
    #[serde(default = "missing_cgroup_memory_stat")]
    pub memory_stat: CgroupResource<CgroupMemoryStatRaw>,
    pub io: CgroupResource<BTreeMap<CgroupIoDevice, CgroupIoRaw>>,
    pub cpu_pressure: CgroupResource<RecordedCgroupPsi>,
    pub memory_pressure: CgroupResource<RecordedCgroupPsi>,
    pub io_pressure: CgroupResource<RecordedCgroupPsi>,
    pub systemd_unit_candidate: Option<String>,
}

fn missing_cgroup_memory_stat() -> CgroupResource<CgroupMemoryStatRaw> {
    CgroupResource {
        state: CgroupFileState::Missing,
        value: None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedCgroupPsi {
    pub elapsed_us: Option<u64>,
    pub some_total_usec: Option<u64>,
    pub full_total_usec: Option<u64>,
    pub state: CgroupPsiIntervalState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordError {
    message: String,
}

impl RecordError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for RecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.message.fmt(formatter)
    }
}

impl std::error::Error for RecordError {}

impl From<io::Error> for RecordError {
    fn from(error: io::Error) -> Self {
        Self::new(error.to_string())
    }
}

impl From<serde_json::Error> for RecordError {
    fn from(error: serde_json::Error) -> Self {
        Self::new(format!("recording JSON is invalid: {error}"))
    }
}

pub fn recording_from_observation(
    observation: &HuntObservation,
    requested_duration_ms: u64,
    redaction: Redaction,
) -> Result<Recording, RecordError> {
    let mut recording = Recording {
        kind: RECORDING_KIND.to_owned(),
        schema_version: RECORDING_SCHEMA_VERSION,
        tool_version: env!("CARGO_PKG_VERSION").to_owned(),
        recorded_at_unix_ms: unix_now_ms(),
        redaction: Redaction::None,
        requested_duration_ms,
        observation: RecordedHunt {
            cpu_psi: Collected::from_result(observation.psi),
            cpu: Collected::from_result(observation.cpu.clone()),
            memory: observation.memory.as_ref().map(record_memory),
            io: observation.io.as_ref().map(record_io),
            cgroup: observation.cgroup.as_ref().map(record_cgroup),
        },
    };
    if redaction == Redaction::Identifiers {
        redact_recording(&mut recording);
    }
    Ok(recording)
}

pub fn observation_from_recording(recording: &Recording) -> Result<HuntObservation, RecordError> {
    validate_header(recording)?;
    Ok(HuntObservation {
        psi: result_from_collected(&recording.observation.cpu_psi),
        cpu: result_from_collected(&recording.observation.cpu),
        memory: recording
            .observation
            .memory
            .as_ref()
            .map(memory_from_recorded),
        io: recording.observation.io.as_ref().map(io_from_recorded),
        cgroup: recording
            .observation
            .cgroup
            .as_ref()
            .map(cgroup_from_recorded),
    })
}

pub fn encode_recording(recording: &Recording) -> Result<String, RecordError> {
    validate_header(recording)?;
    serde_json::to_string_pretty(recording)
        .map(|json| format!("{json}\n"))
        .map_err(RecordError::from)
}

pub fn decode_recording(input: &str) -> Result<Recording, RecordError> {
    if input.len() as u64 > MAX_RECORDING_BYTES {
        return Err(RecordError::new(format!(
            "recording exceeds the {MAX_RECORDING_BYTES} byte decode limit"
        )));
    }
    let recording: Recording = serde_json::from_str(input)?;
    validate_header(&recording)?;
    Ok(recording)
}

pub fn write_recording(
    path: &Path,
    recording: &Recording,
    overwrite: bool,
) -> Result<(), RecordError> {
    let encoded = encode_recording(recording)?;
    let mut options = OpenOptions::new();
    options.write(true);
    if overwrite {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            RecordError::new(format!(
                "recording '{}' already exists; pass --force to overwrite",
                path.display()
            ))
        } else {
            RecordError::from(error)
        }
    })?;
    file.write_all(encoded.as_bytes())?;
    Ok(())
}

pub fn read_recording(path: &Path) -> Result<Recording, RecordError> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_RECORDING_BYTES {
        return Err(RecordError::new(format!(
            "recording '{}' exceeds the {MAX_RECORDING_BYTES} byte decode limit",
            path.display()
        )));
    }
    let file = fs::File::open(path)?;
    let mut input = String::new();
    file.take(MAX_RECORDING_BYTES + 1)
        .read_to_string(&mut input)?;
    if input.len() as u64 > MAX_RECORDING_BYTES {
        return Err(RecordError::new(format!(
            "recording '{}' exceeds the {MAX_RECORDING_BYTES} byte decode limit",
            path.display()
        )));
    }
    decode_recording(&input)
}

pub fn redact_recording(recording: &mut Recording) {
    recording.redaction = Redaction::Identifiers;
    let mut paths = PathRedactor::default();
    if let Collected::Observed { value } = &mut recording.observation.cpu {
        for process in &mut value.processes {
            process.name = process_placeholder(process.key.pid);
        }
        for candidate in &mut value.scheduler_delay_candidates {
            candidate.name = process_placeholder(candidate.key.pid);
        }
    }
    if let Some(io) = recording.observation.io.as_mut()
        && let Collected::Observed { value } = &mut io.diskstats
    {
        for device in &mut value.observation.devices {
            device.name = device_placeholder(device.key.major, device.key.minor);
        }
    }
    if let Some(io) = recording.observation.io.as_mut()
        && let Collected::Observed { value } = &mut io.processes
    {
        for process in &mut value.observation.processes {
            process.name = process_placeholder(process.key.pid);
        }
    }
    if let Some(Collected::Observed { value }) = recording.observation.cgroup.as_mut() {
        for group in &mut value.groups {
            group.path = paths.path(&group.path);
            group.systemd_unit_candidate = group
                .systemd_unit_candidate
                .as_deref()
                .and_then(redacted_unit);
        }
        for member in &mut value.members {
            member.name = process_placeholder(member.key.pid);
            member.cgroup_path = paths.path(&member.cgroup_path);
        }
    }
}

fn validate_header(recording: &Recording) -> Result<(), RecordError> {
    if recording.kind != RECORDING_KIND {
        return Err(RecordError::new(format!(
            "unsupported recording kind '{}'; expected '{RECORDING_KIND}'",
            recording.kind
        )));
    }
    if recording.schema_version != RECORDING_SCHEMA_VERSION {
        return Err(RecordError::new(format!(
            "unsupported recording schema_version {}; this tool reads version {RECORDING_SCHEMA_VERSION}",
            recording.schema_version
        )));
    }
    Ok(())
}

fn record_memory(memory: &MemoryHuntObservation) -> RecordedMemoryHunt {
    RecordedMemoryHunt {
        psi: Collected::from_result(memory.psi),
        context: match &memory.context {
            Ok(context) => Collected::Observed {
                value: RecordedMemoryContext {
                    elapsed_us: duration_us(context.elapsed),
                    observation: context.clone(),
                },
            },
            Err(error) => Collected::Unavailable { error: *error },
        },
    }
}

fn record_io(io: &IoHuntObservation) -> RecordedIoHunt {
    RecordedIoHunt {
        psi: Collected::from_result(io.psi),
        diskstats: match &io.diskstats {
            Ok(observation) => Collected::Observed {
                value: RecordedDiskstats {
                    elapsed_us: duration_us(observation.elapsed),
                    observation: observation.clone(),
                },
            },
            Err(error) => Collected::Unavailable { error: *error },
        },
        processes: match &io.processes {
            Ok(observation) => Collected::Observed {
                value: RecordedProcessIo {
                    elapsed_us: duration_us(observation.elapsed),
                    observation: observation.clone(),
                },
            },
            Err(error) => Collected::Unavailable { error: *error },
        },
    }
}

fn record_cgroup(cgroup: &CgroupHuntObservation) -> Collected<RecordedCgroup, CgroupError> {
    match &cgroup.observation {
        Ok(observation) => Collected::Observed {
            value: RecordedCgroup {
                elapsed_us: duration_us(observation.elapsed),
                groups: observation
                    .groups
                    .iter()
                    .map(record_cgroup_interval)
                    .collect(),
                members: observation.members.clone(),
                issues: observation.issues.clone(),
            },
        },
        Err(error) => Collected::Unavailable { error: *error },
    }
}

fn record_cgroup_interval(group: &CgroupInterval) -> RecordedCgroupInterval {
    RecordedCgroupInterval {
        path: group.path.clone(),
        cpu: group.cpu.clone(),
        memory_current_end: group.memory_current_end.clone(),
        memory_events: group.memory_events.clone(),
        memory_stat: group.memory_stat.clone(),
        io: group.io.clone(),
        cpu_pressure: map_resource(&group.cpu_pressure, record_cgroup_psi),
        memory_pressure: map_resource(&group.memory_pressure, record_cgroup_psi),
        io_pressure: map_resource(&group.io_pressure, record_cgroup_psi),
        systemd_unit_candidate: group.systemd_unit_candidate.clone(),
    }
}

fn record_cgroup_psi(interval: &CgroupPsiInterval) -> RecordedCgroupPsi {
    RecordedCgroupPsi {
        elapsed_us: interval.elapsed.map(duration_us),
        some_total_usec: interval.some_total_usec,
        full_total_usec: interval.full_total_usec,
        state: interval.state,
    }
}

fn memory_from_recorded(memory: &RecordedMemoryHunt) -> MemoryHuntObservation {
    MemoryHuntObservation {
        psi: result_from_collected(&memory.psi),
        context: match &memory.context {
            Collected::Observed { value } => {
                let mut observation = value.observation.clone();
                observation.elapsed = Duration::from_micros(value.elapsed_us);
                Ok(observation)
            }
            Collected::Unavailable { error } => Err(*error),
        },
    }
}

fn io_from_recorded(io: &RecordedIoHunt) -> IoHuntObservation {
    IoHuntObservation {
        psi: result_from_collected(&io.psi),
        diskstats: match &io.diskstats {
            Collected::Observed { value } => {
                let mut observation = value.observation.clone();
                observation.elapsed = Duration::from_micros(value.elapsed_us);
                Ok(observation)
            }
            Collected::Unavailable { error } => Err(*error),
        },
        processes: match &io.processes {
            Collected::Observed { value } => {
                let mut observation = value.observation.clone();
                observation.elapsed = Duration::from_micros(value.elapsed_us);
                Ok(observation)
            }
            Collected::Unavailable { error } => Err(*error),
        },
    }
}

fn cgroup_from_recorded(cgroup: &Collected<RecordedCgroup, CgroupError>) -> CgroupHuntObservation {
    CgroupHuntObservation {
        observation: match cgroup {
            Collected::Observed { value } => Ok(CgroupObservation {
                elapsed: Duration::from_micros(value.elapsed_us),
                groups: value
                    .groups
                    .iter()
                    .map(cgroup_interval_from_recorded)
                    .collect(),
                members: value.members.clone(),
                issues: value.issues.clone(),
            }),
            Collected::Unavailable { error } => Err(*error),
        },
    }
}

fn cgroup_interval_from_recorded(group: &RecordedCgroupInterval) -> CgroupInterval {
    CgroupInterval {
        path: group.path.clone(),
        cpu: group.cpu.clone(),
        memory_current_end: group.memory_current_end.clone(),
        memory_events: group.memory_events.clone(),
        memory_stat: group.memory_stat.clone(),
        io: group.io.clone(),
        cpu_pressure: map_resource(&group.cpu_pressure, cgroup_psi_from_recorded),
        memory_pressure: map_resource(&group.memory_pressure, cgroup_psi_from_recorded),
        io_pressure: map_resource(&group.io_pressure, cgroup_psi_from_recorded),
        systemd_unit_candidate: group.systemd_unit_candidate.clone(),
    }
}

fn cgroup_psi_from_recorded(interval: &RecordedCgroupPsi) -> CgroupPsiInterval {
    CgroupPsiInterval {
        elapsed: interval.elapsed_us.map(Duration::from_micros),
        some_total_usec: interval.some_total_usec,
        full_total_usec: interval.full_total_usec,
        state: interval.state,
    }
}

fn map_resource<T, U>(resource: &CgroupResource<T>, map: impl Fn(&T) -> U) -> CgroupResource<U> {
    CgroupResource {
        state: resource.state,
        value: resource.value.as_ref().map(map),
    }
}

fn result_from_collected<T: Clone, E: Copy>(collected: &Collected<T, E>) -> Result<T, E> {
    match collected {
        Collected::Observed { value } => Ok(value.clone()),
        Collected::Unavailable { error } => Err(*error),
    }
}

fn duration_us(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

fn unix_now_ms() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
}

fn process_placeholder(pid: u32) -> String {
    format!("pid-{pid}")
}

fn device_placeholder(major: u32, minor: u32) -> String {
    format!("dev-{major}-{minor}")
}

fn redacted_unit(candidate: &str) -> Option<String> {
    let suffix = candidate.rsplit_once('.')?.1;
    matches!(suffix, "service" | "scope" | "slice").then(|| format!("redacted.{suffix}"))
}

#[derive(Default)]
struct PathRedactor {
    components: BTreeMap<String, String>,
}

impl PathRedactor {
    fn path(&mut self, path: &str) -> String {
        if path == "/" {
            return "/".to_owned();
        }
        let mut redacted = String::new();
        for component in path.split('/').filter(|component| !component.is_empty()) {
            let next = self.components.len();
            let token = self
                .components
                .entry(component.to_owned())
                .or_insert_with(|| format!("c{next}"));
            redacted.push('/');
            redacted.push_str(token);
        }
        if redacted.is_empty() {
            "/".to_owned()
        } else {
            redacted
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{self, AssessmentKind};
    use crate::cgroup::{CgroupFileState, CgroupPsiIntervalState};
    use crate::cpu::{
        HostCpuInterval, LoadAverageAvailability, LoadAverageRaw, ProcessCollectionIssues,
        ProcessCpuInterval, ProcessKey, SchedstatCapability,
    };
    use crate::io::{
        BlockDeviceKey, DiskstatsInterval, DiskstatsIntervalIssues, IoCapability,
        ProcessIoCollectionIssues, ProcessIoInterval,
    };
    use crate::memory::{MeminfoRaw, MemoryContextCapability, VmstatCounter, VmstatIntervalIssues};
    use crate::psi::{
        CpuPsiInterval, CpuPsiRaw, IoPsiFullInterval, IoPsiInterval, IoPsiLine, IoPsiLineInterval,
        IoPsiRaw, MemoryPsiFullInterval, MemoryPsiInterval, MemoryPsiLine, MemoryPsiLineInterval,
        MemoryPsiRaw,
    };

    fn sample_observation() -> HuntObservation {
        let elapsed = Duration::from_secs(10);
        HuntObservation {
            psi: Ok(CpuPsiObservation {
                requested: elapsed,
                interval: CpuPsiInterval {
                    elapsed,
                    total_delta_us: 2_000_000,
                    some_fraction: 0.2,
                },
                start: CpuPsiRaw {
                    avg10_percent: 0.0,
                    avg60_percent: 0.0,
                    avg300_percent: 0.0,
                    total_us: 0,
                },
                end: CpuPsiRaw {
                    avg10_percent: 20.0,
                    avg60_percent: 5.0,
                    avg300_percent: 1.0,
                    total_us: 2_000_000,
                },
            }),
            cpu: Ok(CpuProcessObservation {
                elapsed,
                clock_ticks_per_second: 100,
                host: HostCpuInterval {
                    total_ticks: 1_000,
                    busy_ticks: 800,
                    idle_ticks: 200,
                    utilization_fraction: 0.8,
                    cpu_count: 4,
                },
                load: Some(LoadAverageRaw {
                    avg1: 2.0,
                    avg5: 1.0,
                    avg15: 0.5,
                    runnable_tasks: 6,
                    total_tasks: 80,
                    last_pid: 99,
                }),
                load_availability: LoadAverageAvailability::Available,
                processes: vec![ProcessCpuInterval {
                    key: ProcessKey {
                        pid: 42,
                        start_time_ticks: 7,
                    },
                    name: "secret-worker".into(),
                    state: 'R',
                    cpu_ticks: 50,
                    cpu_fraction_of_one: 0.5,
                }],
                collection_issues: ProcessCollectionIssues::default(),
                scheduler_delay_candidates: Vec::new(),
                schedstat_collection_issues: crate::cpu::SchedstatCollectionIssues::default(),
                schedstat_capability: SchedstatCapability::Unsupported,
            }),
            memory: Some(MemoryHuntObservation {
                psi: Ok(MemoryPsiObservation {
                    requested: elapsed,
                    interval: MemoryPsiInterval {
                        elapsed,
                        some: MemoryPsiLineInterval {
                            total_delta_us: 0,
                            fraction: 0.0,
                        },
                        full: MemoryPsiFullInterval::Missing,
                    },
                    start: MemoryPsiRaw {
                        some: MemoryPsiLine {
                            avg10_percent: 0.0,
                            avg60_percent: 0.0,
                            avg300_percent: 0.0,
                            total_us: 0,
                        },
                        full: None,
                    },
                    end: MemoryPsiRaw {
                        some: MemoryPsiLine {
                            avg10_percent: 0.0,
                            avg60_percent: 0.0,
                            avg300_percent: 0.0,
                            total_us: 0,
                        },
                        full: None,
                    },
                }),
                context: Ok(MemoryContextObservation {
                    elapsed,
                    end_meminfo: Some(MeminfoRaw {
                        mem_total_bytes: 8_000_000,
                        mem_available_bytes: 4_000_000,
                        swap_total_bytes: 0,
                        swap_free_bytes: 0,
                        cached_bytes: None,
                        sreclaimable_bytes: None,
                        anon_pages_bytes: None,
                    }),
                    meminfo_capability: MemoryContextCapability::Available,
                    vmstat_capability: MemoryContextCapability::Available,
                    vmstat_deltas: VmstatCounter::ALL
                        .into_iter()
                        .map(|counter| (counter, 0))
                        .collect(),
                    vmstat_issues: VmstatIntervalIssues::default(),
                }),
            }),
            io: Some(IoHuntObservation {
                psi: Ok(IoPsiObservation {
                    requested: elapsed,
                    interval: IoPsiInterval {
                        elapsed,
                        some: IoPsiLineInterval {
                            total_delta_us: 1_500_000,
                            fraction: 0.15,
                        },
                        full: IoPsiFullInterval::Available(IoPsiLineInterval {
                            total_delta_us: 100_000,
                            fraction: 0.01,
                        }),
                    },
                    start: IoPsiRaw {
                        some: IoPsiLine {
                            avg10_percent: 0.0,
                            avg60_percent: 0.0,
                            avg300_percent: 0.0,
                            total_us: 0,
                        },
                        full: Some(IoPsiLine {
                            avg10_percent: 0.0,
                            avg60_percent: 0.0,
                            avg300_percent: 0.0,
                            total_us: 0,
                        }),
                    },
                    end: IoPsiRaw {
                        some: IoPsiLine {
                            avg10_percent: 0.0,
                            avg60_percent: 0.0,
                            avg300_percent: 0.0,
                            total_us: 1_500_000,
                        },
                        full: Some(IoPsiLine {
                            avg10_percent: 0.0,
                            avg60_percent: 0.0,
                            avg300_percent: 0.0,
                            total_us: 100_000,
                        }),
                    },
                }),
                diskstats: Ok(DiskstatsObservation {
                    elapsed,
                    capability: IoCapability::Available,
                    devices: vec![DiskstatsInterval {
                        key: BlockDeviceKey { major: 8, minor: 0 },
                        name: "sda".into(),
                        reads_completed: Some(10),
                        sectors_read_512: Some(8_192),
                        writes_completed: Some(20),
                        sectors_written_512: Some(16_384),
                        io_ticks_ms: Some(400),
                        weighted_io_ticks_ms: Some(500),
                        end_in_flight: 1,
                    }],
                    issues: DiskstatsIntervalIssues::default(),
                }),
                processes: Ok(ProcessIoObservation {
                    elapsed,
                    capability: IoCapability::Available,
                    processes: vec![ProcessIoInterval {
                        key: ProcessKey {
                            pid: 7,
                            start_time_ticks: 3,
                        },
                        name: "restic".into(),
                        read_bytes: Some(100),
                        write_bytes: Some(200),
                        cancelled_write_bytes: None,
                        rchar: None,
                        wchar: None,
                    }],
                    issues: ProcessIoCollectionIssues::default(),
                    regressed: vec![],
                }),
            }),
            cgroup: Some(CgroupHuntObservation {
                observation: Ok(CgroupObservation {
                    elapsed,
                    members: vec![CgroupProcessMember {
                        key: ProcessKey {
                            pid: 42,
                            start_time_ticks: 7,
                        },
                        name: "secret-worker".into(),
                        cgroup_path: "/user.slice/app.service".into(),
                    }],
                    issues: CgroupCollectionIssues::default(),
                    groups: vec![CgroupInterval {
                        path: "/user.slice/app.service".into(),
                        cpu: CgroupResource {
                            state: CgroupFileState::Missing,
                            value: None,
                        },
                        memory_current_end: CgroupResource {
                            state: CgroupFileState::Missing,
                            value: None,
                        },
                        memory_events: CgroupResource {
                            state: CgroupFileState::Missing,
                            value: None,
                        },
                        memory_stat: CgroupResource {
                            state: CgroupFileState::Missing,
                            value: None,
                        },
                        io: CgroupResource {
                            state: CgroupFileState::Missing,
                            value: None,
                        },
                        cpu_pressure: CgroupResource {
                            state: CgroupFileState::Available,
                            value: Some(CgroupPsiInterval {
                                elapsed: Some(elapsed),
                                some_total_usec: Some(2_000_000),
                                full_total_usec: None,
                                state: CgroupPsiIntervalState::Available,
                            }),
                        },
                        memory_pressure: CgroupResource {
                            state: CgroupFileState::Missing,
                            value: None,
                        },
                        io_pressure: CgroupResource {
                            state: CgroupFileState::Missing,
                            value: None,
                        },
                        systemd_unit_candidate: Some("app.service".into()),
                    }],
                }),
            }),
        }
    }

    #[test]
    fn round_trip_preserves_analysis() {
        let original = sample_observation();
        let recording =
            recording_from_observation(&original, 10_000, Redaction::None).expect("encode");
        let restored = observation_from_recording(&recording).expect("decode");
        let original_cpu =
            analysis::analyze_cpu(original.psi.as_ref().ok(), original.cpu.as_ref().ok());
        let restored_cpu =
            analysis::analyze_cpu(restored.psi.as_ref().ok(), restored.cpu.as_ref().ok());
        assert_eq!(original_cpu.findings[0].kind, AssessmentKind::CpuContention);
        assert_eq!(original_cpu.findings, restored_cpu.findings);
        assert_eq!(
            restored.cpu.as_ref().unwrap().processes[0].name,
            "secret-worker"
        );
        assert_eq!(
            restored
                .cgroup
                .as_ref()
                .unwrap()
                .observation
                .as_ref()
                .unwrap()
                .groups[0]
                .cpu_pressure
                .value
                .as_ref()
                .unwrap()
                .elapsed,
            Some(Duration::from_secs(10))
        );
        assert_eq!(
            restored
                .memory
                .as_ref()
                .unwrap()
                .context
                .as_ref()
                .unwrap()
                .elapsed,
            Duration::from_secs(10)
        );
    }

    #[test]
    fn redaction_replaces_identifiers_without_changing_verdicts() {
        let original = sample_observation();
        let recording =
            recording_from_observation(&original, 10_000, Redaction::Identifiers).expect("encode");
        let restored = observation_from_recording(&recording).expect("decode");
        let original_cpu =
            &analysis::analyze_cpu(original.psi.as_ref().ok(), original.cpu.as_ref().ok()).findings
                [0];
        let restored_cpu =
            &analysis::analyze_cpu(restored.psi.as_ref().ok(), restored.cpu.as_ref().ok()).findings
                [0];
        assert_eq!(recording.redaction, Redaction::Identifiers);
        assert_eq!(original_cpu.kind, restored_cpu.kind);
        assert_eq!(original_cpu.severity, restored_cpu.severity);
        assert_eq!(restored.cpu.as_ref().unwrap().processes[0].name, "pid-42");
        assert_eq!(
            restored
                .io
                .as_ref()
                .unwrap()
                .diskstats
                .as_ref()
                .unwrap()
                .devices[0]
                .name,
            "dev-8-0"
        );
        let cgroup = restored
            .cgroup
            .as_ref()
            .unwrap()
            .observation
            .as_ref()
            .unwrap();
        assert_eq!(cgroup.groups[0].path, "/c0/c1");
        assert_eq!(cgroup.members[0].cgroup_path, "/c0/c1");
        assert_eq!(
            cgroup.groups[0].systemd_unit_candidate.as_deref(),
            Some("redacted.service")
        );
        assert!(
            !encode_recording(&recording)
                .expect("json")
                .contains("secret-worker")
        );
    }

    #[test]
    fn unknown_schema_is_rejected() {
        let mut recording =
            recording_from_observation(&sample_observation(), 10_000, Redaction::None)
                .expect("encode");
        recording.schema_version = 99;
        let json = serde_json::to_string(&recording).expect("json");
        let error = decode_recording(&json).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unsupported recording schema_version")
        );
    }

    #[test]
    fn hunt_json_is_not_a_recording() {
        let error =
            decode_recording("{\"schema_version\":1,\"status\":\"observed\"}\n").unwrap_err();
        assert!(error.to_string().contains("recording JSON is invalid"));
    }
}
