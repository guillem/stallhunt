//! Bounded cgroup v2 telemetry.  This module deliberately collects only
//! cgroups which contain selected processes and their ancestors; walking an
//! arbitrary cgroup hierarchy can be unexpectedly expensive on a busy host.

use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::cpu::{ProcessKey, ProcessRaw, parse_process_stat, sanitized_process_name};

pub const MAX_CGROUP_PROCESSES: usize = 512;
pub const MAX_CGROUPS: usize = 512;
pub const MAX_CGROUP_DEPTH: usize = 64;
pub const MAX_CGROUP_PATH_BYTES: usize = 4_096;
pub const MAX_CGROUP_FILE_BYTES: u64 = 64 * 1024;
pub const MAX_CGROUP_SNAPSHOT_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_CGROUP_READ_ATTEMPTS: u32 = 4_096;
const MAX_PROC_INPUT_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Cgroup2Mount {
    /// Root of the cgroup hierarchy exposed by this mount, in cgroup-path
    /// notation (not a host filesystem path).
    pub root: String,
    pub mount_point: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CgroupError {
    Unsupported,
    PermissionDenied,
    Unreadable,
    Malformed,
    AmbiguousMount,
    EmptyInterval,
    MountChanged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CgroupFileState {
    Available,
    /// One endpoint was readable but the other was not, so no delta exists.
    Partial,
    Missing,
    PermissionDenied,
    Unreadable,
    Malformed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgroupResource<T> {
    pub state: CgroupFileState,
    pub value: Option<T>,
}

impl<T> CgroupResource<T> {
    fn available(value: T) -> Self {
        Self {
            state: CgroupFileState::Available,
            value: Some(value),
        }
    }
    fn failed(state: CgroupFileState) -> Self {
        Self { state, value: None }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgroupCpuRaw {
    pub usage_usec: u64,
    pub user_usec: Option<u64>,
    pub system_usec: Option<u64>,
    pub nr_periods: Option<u64>,
    pub nr_throttled: Option<u64>,
    pub throttled_usec: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgroupMemoryEventsRaw {
    pub low: Option<u64>,
    pub high: Option<u64>,
    pub max: Option<u64>,
    pub oom: Option<u64>,
    pub oom_kill: Option<u64>,
    pub oom_group_kill: Option<u64>,
}

/// Selected cgroup `memory.stat` counters. Unknown kernel keys are ignored.
/// Direct scan/steal and swap-in/out are the scoped analogue of host vmstat
/// mechanism counters; background kswapd aggregates are not collected here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CgroupMemoryStatRaw {
    pub pgscan_direct: Option<u64>,
    pub pgsteal_direct: Option<u64>,
    pub pswpin: Option<u64>,
    pub pswpout: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CgroupIoDevice {
    pub major: u32,
    pub minor: u32,
}

impl Serialize for CgroupIoDevice {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{}:{}", self.major, self.minor))
    }
}

impl<'de> Deserialize<'de> for CgroupIoDevice {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let text = String::deserialize(deserializer)?;
        let (major, minor) = text.split_once(':').ok_or_else(|| {
            serde::de::Error::custom("cgroup I/O device identity must be major:minor")
        })?;
        Ok(Self {
            major: major.parse().map_err(serde::de::Error::custom)?,
            minor: minor.parse().map_err(serde::de::Error::custom)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgroupIoRaw {
    pub rbytes: Option<u64>,
    pub wbytes: Option<u64>,
    pub rios: Option<u64>,
    pub wios: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CgroupPsiRaw {
    pub some_total_usec: u64,
    pub full_total_usec: Option<u64>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CgroupPsiIntervalState {
    Available,
    Partial,
    SomeRegressed,
    SomeExceedsElapsed,
    FullExceedsSome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CgroupRaw {
    pub path: String,
    pub cpu: CgroupResource<CgroupCpuRaw>,
    pub memory_current: CgroupResource<u64>,
    pub memory_events: CgroupResource<CgroupMemoryEventsRaw>,
    pub memory_stat: CgroupResource<CgroupMemoryStatRaw>,
    pub io: CgroupResource<BTreeMap<CgroupIoDevice, CgroupIoRaw>>,
    pub cpu_pressure: CgroupResource<CgroupPsiRaw>,
    pub memory_pressure: CgroupResource<CgroupPsiRaw>,
    pub io_pressure: CgroupResource<CgroupPsiRaw>,
    #[serde(skip)]
    pub cpu_pressure_at: Option<Instant>,
    #[serde(skip)]
    pub memory_pressure_at: Option<Instant>,
    #[serde(skip)]
    pub io_pressure_at: Option<Instant>,
    /// Conservative presentation-only inference from the final path component.
    pub systemd_unit_candidate: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgroupProcessMember {
    pub key: ProcessKey,
    pub name: String,
    pub cgroup_path: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgroupCollectionIssues {
    pub process_enumeration_failed: bool,
    pub process_enumeration_errors: u32,
    pub process_disappeared: u32,
    pub process_identity_changed: u32,
    pub process_permission_denied: u32,
    pub process_malformed: u32,
    pub process_limit_reached: bool,
    pub cgroup_limit_reached: bool,
    pub path_rejected: u32,
    pub cgroup_disappeared: u32,
    pub cgroup_permission_denied: u32,
    pub cgroup_unreadable: u32,
    pub cgroup_malformed: u32,
    pub budget_exhausted: bool,
    pub read_attempts: u32,
    pub bytes_read: u64,
    pub members_appeared: u32,
    pub members_exited: u32,
    pub members_reused: u32,
    pub members_moved: u32,
}
#[derive(Default)]
struct SnapshotBudget {
    reads: u32,
    bytes: u64,
    exhausted: bool,
}
impl SnapshotBudget {
    fn permit(&mut self) -> bool {
        if self.reads >= MAX_CGROUP_READ_ATTEMPTS
            || self.bytes.saturating_add(MAX_CGROUP_FILE_BYTES) > MAX_CGROUP_SNAPSHOT_BYTES
        {
            self.exhausted = true;
            false
        } else {
            self.reads += 1;
            true
        }
    }
    fn add_bytes(&mut self, bytes: usize) {
        self.bytes = self.bytes.saturating_add(bytes as u64);
        if self.bytes > MAX_CGROUP_SNAPSHOT_BYTES {
            self.exhausted = true;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CgroupCapability {
    Available,
    Partial,
    Unsupported,
    PermissionDenied,
    Failed,
}
impl CgroupCapability {
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

/// The capability summary is derived from collected cgroup data rather than
/// merely from whether an outer snapshot/interval was constructed.  That
/// keeps `capabilities` and `hunt` honest when budgets, permissions, or
/// optional controller files make otherwise usable context incomplete.
pub fn cgroup_capability_from_snapshot(snapshot: &CgroupSnapshot) -> CgroupCapability {
    if snapshot.members.is_empty()
        || snapshot.groups.is_empty()
        || collection_is_partial(&snapshot.issues)
        || snapshot
            .groups
            .values()
            .any(|group| !all_group_resources_available(group))
    {
        CgroupCapability::Partial
    } else {
        CgroupCapability::Available
    }
}

pub fn cgroup_capability_from_observation(observation: &CgroupObservation) -> CgroupCapability {
    if observation.groups.is_empty()
        || collection_is_partial(&observation.issues)
        || observation.groups.iter().any(|group| {
            ![
                group.cpu.state,
                group.memory_current_end.state,
                group.memory_events.state,
                group.memory_stat.state,
                group.io.state,
                group.cpu_pressure.state,
                group.memory_pressure.state,
                group.io_pressure.state,
            ]
            .into_iter()
            .all(|state| state == CgroupFileState::Available)
        })
    {
        CgroupCapability::Partial
    } else {
        CgroupCapability::Available
    }
}

fn collection_is_partial(issues: &CgroupCollectionIssues) -> bool {
    issues.process_enumeration_failed
        || issues.process_enumeration_errors != 0
        || issues.process_disappeared != 0
        || issues.process_identity_changed != 0
        || issues.process_permission_denied != 0
        || issues.process_malformed != 0
        || issues.process_limit_reached
        || issues.cgroup_limit_reached
        || issues.path_rejected != 0
        || issues.cgroup_disappeared != 0
        || issues.cgroup_permission_denied != 0
        || issues.cgroup_unreadable != 0
        || issues.cgroup_malformed != 0
        || issues.budget_exhausted
        || issues.members_appeared != 0
        || issues.members_exited != 0
        || issues.members_reused != 0
        || issues.members_moved != 0
}

pub fn probe_cgroup_v2() -> CgroupCapability {
    match read_cgroup_snapshot_at(Path::new("/proc")) {
        Ok(snapshot) => cgroup_capability_from_snapshot(&snapshot),
        Err(CgroupError::Unsupported) => CgroupCapability::Unsupported,
        Err(CgroupError::PermissionDenied) => CgroupCapability::PermissionDenied,
        Err(_) => CgroupCapability::Failed,
    }
}
fn all_group_resources_available(group: &CgroupRaw) -> bool {
    [
        group.cpu.state,
        group.memory_current.state,
        group.memory_events.state,
        group.memory_stat.state,
        group.io.state,
        group.cpu_pressure.state,
        group.memory_pressure.state,
        group.io_pressure.state,
    ]
    .into_iter()
    .all(|state| state == CgroupFileState::Available)
}
pub const fn cgroup_capability_explanation(capability: CgroupCapability) -> &'static str {
    match capability {
        CgroupCapability::Available => {
            "cgroup v2 membership and bounded active-cgroup context are readable."
        }
        CgroupCapability::Partial => {
            "cgroup v2 context is only partially readable or was bounded during collection."
        }
        CgroupCapability::Unsupported => "no usable cgroup v2 mount was discovered.",
        CgroupCapability::PermissionDenied => {
            "cgroup v2 discovery is denied by current permissions."
        }
        CgroupCapability::Failed => "cgroup v2 discovery or collection failed.",
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CgroupSnapshot {
    pub mount: Cgroup2Mount,
    pub members: BTreeMap<ProcessKey, CgroupProcessMember>,
    pub groups: BTreeMap<String, CgroupRaw>,
    pub issues: CgroupCollectionIssues,
}

fn discover_cgroup2_with_budget_at(
    proc_root: &Path,
    budget: &mut SnapshotBudget,
) -> Result<Cgroup2Mount, CgroupError> {
    if !budget.permit() {
        return Err(CgroupError::Unreadable);
    }
    let input =
        read_proc_limited(proc_root.join("self/mountinfo"), budget).map_err(classify_error)?;
    parse_cgroup2_mountinfo(&input)
}

pub fn parse_cgroup2_mountinfo(input: &str) -> Result<Cgroup2Mount, CgroupError> {
    let mut found = Vec::new();
    for line in input.lines().filter(|line| !line.is_empty()) {
        let (left, right) = line.split_once(" - ").ok_or(CgroupError::Malformed)?;
        let mut pre = left.split_ascii_whitespace();
        let _id = pre.next().ok_or(CgroupError::Malformed)?;
        let _parent = pre.next().ok_or(CgroupError::Malformed)?;
        let _major_minor = pre.next().ok_or(CgroupError::Malformed)?;
        let root = decode_mountinfo_path(pre.next().ok_or(CgroupError::Malformed)?)?;
        let mount_point = decode_mountinfo_path(pre.next().ok_or(CgroupError::Malformed)?)?;
        let _options = pre.next().ok_or(CgroupError::Malformed)?;
        let mut post = right.split_ascii_whitespace();
        if post.next() != Some("cgroup2") {
            continue;
        }
        if post.next().is_none() || post.next().is_none() {
            return Err(CgroupError::Malformed);
        }
        found.push(Cgroup2Mount {
            root,
            mount_point: PathBuf::from(mount_point),
        });
    }
    match found.len() {
        0 => Err(CgroupError::Unsupported),
        1 => Ok(found.remove(0)),
        _ => Err(CgroupError::AmbiguousMount),
    }
}

/// Parse the unified record.  A cgroup-v1 record or multiple unified records
/// is rejected rather than guessed.
pub fn parse_unified_cgroup(input: &str) -> Result<String, CgroupError> {
    let mut result = None;
    for line in input.lines().filter(|line| !line.is_empty()) {
        let mut parts = line.splitn(3, ':');
        let hierarchy = parts.next().ok_or(CgroupError::Malformed)?;
        let controllers = parts.next().ok_or(CgroupError::Malformed)?;
        let path = parts.next().ok_or(CgroupError::Malformed)?;
        if hierarchy == "0"
            && controllers.is_empty()
            && result.replace(normalize_cgroup_path(path)?).is_some()
        {
            return Err(CgroupError::Malformed);
        }
    }
    result.ok_or(CgroupError::Unsupported)
}

pub fn read_cgroup_snapshot_at(proc_root: &Path) -> Result<CgroupSnapshot, CgroupError> {
    let mut budget = SnapshotBudget::default();
    let mount = discover_cgroup2_with_budget_at(proc_root, &mut budget)?;
    read_cgroup_snapshot_with_mount_and_budget_at(proc_root, mount, budget)
}

/// Fixture-friendly collection entry point. `mount.mount_point` may point at a
/// synthetic cgroup tree while process records still come from `proc_root`.
#[cfg(test)]
pub fn read_cgroup_snapshot_with_mount_at(
    proc_root: &Path,
    mount: Cgroup2Mount,
) -> Result<CgroupSnapshot, CgroupError> {
    read_cgroup_snapshot_with_mount_and_budget_at(proc_root, mount, SnapshotBudget::default())
}
fn read_cgroup_snapshot_with_mount_and_budget_at(
    proc_root: &Path,
    mount: Cgroup2Mount,
    mut budget: SnapshotBudget,
) -> Result<CgroupSnapshot, CgroupError> {
    let mut issues = CgroupCollectionIssues::default();
    let pids = select_pids(proc_root, &mut issues);
    let mut members = BTreeMap::new();
    for pid in pids {
        let base = proc_root.join(pid.to_string());
        if !budget.permit() {
            issues.budget_exhausted = true;
            break;
        }
        let first = match read_stat(&base, &mut budget) {
            Ok(value) => value,
            Err(kind) => {
                note_process_error(&mut issues, kind);
                continue;
            }
        };
        if !budget.permit() {
            issues.budget_exhausted = true;
            break;
        }
        let path = match read_proc_limited(base.join("cgroup"), &mut budget) {
            Ok(value) => match parse_unified_cgroup(&value) {
                Ok(value) => value,
                Err(_) => {
                    issues.process_malformed = issues.process_malformed.saturating_add(1);
                    continue;
                }
            },
            Err(error) => {
                note_process_error(&mut issues, classify_proc_error(&error));
                continue;
            }
        };
        if !budget.permit() {
            issues.budget_exhausted = true;
            break;
        }
        match read_stat(&base, &mut budget) {
            Ok(second) if second.key == first.key => {
                members.insert(
                    second.key,
                    CgroupProcessMember {
                        key: second.key,
                        name: sanitized_process_name(&second.comm),
                        cgroup_path: path,
                    },
                );
            }
            Ok(_) => {
                issues.process_identity_changed = issues.process_identity_changed.saturating_add(1)
            }
            Err(kind) => note_process_error(&mut issues, kind),
        }
    }
    let paths = active_paths(
        &mount,
        members.values().map(|member| member.cgroup_path.as_str()),
        &mut issues,
    );
    let mut groups = BTreeMap::new();
    for path in paths {
        let directory = match cgroup_directory(&mount, &path) {
            Ok(value) => value,
            Err(_) => {
                issues.path_rejected = issues.path_rejected.saturating_add(1);
                continue;
            }
        };
        if budget.exhausted {
            issues.budget_exhausted = true;
            break;
        }
        match read_group(&directory, &path, &mut budget) {
            Ok(group) => {
                groups.insert(path, group);
            }
            Err(CgroupFileState::Missing) => {
                issues.cgroup_disappeared = issues.cgroup_disappeared.saturating_add(1)
            }
            Err(CgroupFileState::PermissionDenied) => {
                issues.cgroup_permission_denied = issues.cgroup_permission_denied.saturating_add(1)
            }
            Err(CgroupFileState::Unreadable) => {
                issues.cgroup_unreadable = issues.cgroup_unreadable.saturating_add(1)
            }
            Err(
                CgroupFileState::Malformed | CgroupFileState::Partial | CgroupFileState::Available,
            ) => issues.cgroup_malformed = issues.cgroup_malformed.saturating_add(1),
        }
    }
    issues.read_attempts = budget.reads;
    issues.bytes_read = budget.bytes;
    issues.budget_exhausted |= budget.exhausted;
    Ok(CgroupSnapshot {
        mount,
        members,
        groups,
        issues,
    })
}

fn active_paths<'a>(
    mount: &Cgroup2Mount,
    paths: impl Iterator<Item = &'a str>,
    issues: &mut CgroupCollectionIssues,
) -> BTreeSet<String> {
    let mut result = BTreeSet::new();
    let mut leaves = BTreeSet::new();
    for path in paths {
        if !is_below_mount_root(path, &mount.root) {
            issues.path_rejected = issues.path_rejected.saturating_add(1);
            continue;
        }
        leaves.insert(path.to_owned());
    }
    for leaf in &leaves {
        result.insert(leaf.clone());
    }
    if result.len() > MAX_CGROUPS {
        issues.cgroup_limit_reached = true;
        return result.into_iter().take(MAX_CGROUPS).collect();
    }
    for path in leaves {
        let mut current = path.to_owned();
        loop {
            if result.len() < MAX_CGROUPS || result.contains(&current) {
                result.insert(current.clone());
            } else {
                issues.cgroup_limit_reached = true;
                break;
            }
            if current == mount.root {
                break;
            }
            current = parent_cgroup_path(&current).expect("normalized non-root path has parent");
        }
    }
    result
}

fn cgroup_directory(mount: &Cgroup2Mount, path: &str) -> Result<PathBuf, CgroupError> {
    if !is_below_mount_root(path, &mount.root) {
        return Err(CgroupError::Malformed);
    }
    let relative = path
        .strip_prefix(&mount.root)
        .unwrap_or("")
        .trim_start_matches('/');
    Ok(if relative.is_empty() {
        mount.mount_point.clone()
    } else {
        mount.mount_point.join(relative)
    })
}

fn read_group(
    directory: &Path,
    path: &str,
    budget: &mut SnapshotBudget,
) -> Result<CgroupRaw, CgroupFileState> {
    match fs::metadata(directory) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => return Err(CgroupFileState::Missing),
        Err(error) => return Err(classify_file_error(&error)),
    }
    let (cpu_pressure, cpu_pressure_at) = read_psi_resource(directory, "cpu.pressure", budget);
    let (memory_pressure, memory_pressure_at) =
        read_psi_resource(directory, "memory.pressure", budget);
    let (io_pressure, io_pressure_at) = read_psi_resource(directory, "io.pressure", budget);
    Ok(CgroupRaw {
        path: path.to_owned(),
        cpu: read_resource(directory, "cpu.stat", parse_cpu_stat, budget),
        memory_current: read_resource(directory, "memory.current", parse_single_counter, budget),
        memory_events: read_resource(directory, "memory.events", parse_memory_events, budget),
        memory_stat: read_resource(directory, "memory.stat", parse_memory_stat, budget),
        io: read_resource(directory, "io.stat", parse_io_stat, budget),
        cpu_pressure,
        memory_pressure,
        io_pressure,
        cpu_pressure_at,
        memory_pressure_at,
        io_pressure_at,
        systemd_unit_candidate: systemd_unit_candidate(path),
    })
}
fn read_psi_resource(
    directory: &Path,
    name: &str,
    budget: &mut SnapshotBudget,
) -> (CgroupResource<CgroupPsiRaw>, Option<Instant>) {
    let resource = read_resource(directory, name, parse_cgroup_psi, budget);
    let timestamp = resource.value.is_some().then(Instant::now);
    (resource, timestamp)
}

fn read_resource<T>(
    directory: &Path,
    name: &str,
    parse: fn(&str) -> Result<T, CgroupError>,
    budget: &mut SnapshotBudget,
) -> CgroupResource<T> {
    if !budget.permit() {
        return CgroupResource::failed(CgroupFileState::Partial);
    }
    match read_limited(directory.join(name), budget) {
        Ok(input) => match parse(&input) {
            Ok(value) => CgroupResource::available(value),
            Err(_) => CgroupResource::failed(CgroupFileState::Malformed),
        },
        Err(state) => CgroupResource::failed(state),
    }
}

fn read_limited(path: PathBuf, budget: &mut SnapshotBudget) -> Result<String, CgroupFileState> {
    let file = File::open(path).map_err(|error| classify_file_error(&error))?;
    let mut text = String::new();
    file.take(MAX_CGROUP_FILE_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|_| CgroupFileState::Unreadable)?;
    if text.len() as u64 > MAX_CGROUP_FILE_BYTES {
        return Err(CgroupFileState::Malformed);
    }
    budget.add_bytes(text.len());
    Ok(text)
}

pub fn parse_cpu_stat(input: &str) -> Result<CgroupCpuRaw, CgroupError> {
    let values = parse_key_values(input)?;
    Ok(CgroupCpuRaw {
        usage_usec: required(&values, "usage_usec")?,
        user_usec: values.get("user_usec").copied(),
        system_usec: values.get("system_usec").copied(),
        nr_periods: values.get("nr_periods").copied(),
        nr_throttled: values.get("nr_throttled").copied(),
        throttled_usec: values.get("throttled_usec").copied(),
    })
}
fn parse_single_counter(input: &str) -> Result<u64, CgroupError> {
    input.trim().parse().map_err(|_| CgroupError::Malformed)
}
pub fn parse_memory_events(input: &str) -> Result<CgroupMemoryEventsRaw, CgroupError> {
    let v = parse_key_values(input)?;
    Ok(CgroupMemoryEventsRaw {
        low: v.get("low").copied(),
        high: v.get("high").copied(),
        max: v.get("max").copied(),
        oom: v.get("oom").copied(),
        oom_kill: v.get("oom_kill").copied(),
        oom_group_kill: v.get("oom_group_kill").copied(),
    })
}
pub fn parse_memory_stat(input: &str) -> Result<CgroupMemoryStatRaw, CgroupError> {
    let v = parse_key_values(input)?;
    Ok(CgroupMemoryStatRaw {
        pgscan_direct: v.get("pgscan_direct").copied(),
        pgsteal_direct: v.get("pgsteal_direct").copied(),
        pswpin: v.get("pswpin").copied(),
        pswpout: v.get("pswpout").copied(),
    })
}
pub fn parse_io_stat(input: &str) -> Result<BTreeMap<CgroupIoDevice, CgroupIoRaw>, CgroupError> {
    let mut output = BTreeMap::new();
    for line in input.lines().filter(|line| !line.trim().is_empty()) {
        let mut fields = line.split_ascii_whitespace();
        let device = fields.next().ok_or(CgroupError::Malformed)?;
        let (major, minor) = device.split_once(':').ok_or(CgroupError::Malformed)?;
        let key = CgroupIoDevice {
            major: major.parse().map_err(|_| CgroupError::Malformed)?,
            minor: minor.parse().map_err(|_| CgroupError::Malformed)?,
        };
        if output.contains_key(&key) {
            return Err(CgroupError::Malformed);
        }
        let values = parse_assignment_fields(fields)?;
        output.insert(
            key,
            CgroupIoRaw {
                rbytes: values.get("rbytes").copied(),
                wbytes: values.get("wbytes").copied(),
                rios: values.get("rios").copied(),
                wios: values.get("wios").copied(),
            },
        );
    }
    Ok(output)
}
pub fn parse_cgroup_psi(input: &str) -> Result<CgroupPsiRaw, CgroupError> {
    let mut some = None;
    let mut full = None;
    for line in input.lines().filter(|line| !line.trim().is_empty()) {
        let mut fields = line.split_ascii_whitespace();
        let kind = fields.next().ok_or(CgroupError::Malformed)?;
        let mut total = None;
        for field in fields {
            let (key, value) = field.split_once('=').ok_or(CgroupError::Malformed)?;
            if key == "total"
                && total
                    .replace(value.parse().map_err(|_| CgroupError::Malformed)?)
                    .is_some()
            {
                return Err(CgroupError::Malformed);
            }
        }
        let total = total.ok_or(CgroupError::Malformed)?;
        match kind {
            "some" => {
                if some.replace(total).is_some() {
                    return Err(CgroupError::Malformed);
                }
            }
            "full" => {
                if full.replace(total).is_some() {
                    return Err(CgroupError::Malformed);
                }
            }
            _ => return Err(CgroupError::Malformed),
        }
    }
    let some = some.ok_or(CgroupError::Malformed)?;
    if full.is_some_and(|full| full > some) {
        return Err(CgroupError::Malformed);
    }
    Ok(CgroupPsiRaw {
        some_total_usec: some,
        full_total_usec: full,
    })
}

fn parse_key_values(input: &str) -> Result<BTreeMap<&str, u64>, CgroupError> {
    let mut result = BTreeMap::new();
    for line in input.lines().filter(|line| !line.trim().is_empty()) {
        let mut fields = line.split_ascii_whitespace();
        let key = fields.next().ok_or(CgroupError::Malformed)?;
        let value = fields.next().ok_or(CgroupError::Malformed)?;
        if fields.next().is_some()
            || result
                .insert(key, value.parse().map_err(|_| CgroupError::Malformed)?)
                .is_some()
        {
            return Err(CgroupError::Malformed);
        }
    }
    Ok(result)
}
fn parse_assignment_fields<'a>(
    fields: impl Iterator<Item = &'a str>,
) -> Result<BTreeMap<&'a str, u64>, CgroupError> {
    let mut result = BTreeMap::new();
    for field in fields {
        let (key, value) = field.split_once('=').ok_or(CgroupError::Malformed)?;
        if key.is_empty()
            || result
                .insert(key, value.parse().map_err(|_| CgroupError::Malformed)?)
                .is_some()
        {
            return Err(CgroupError::Malformed);
        }
    }
    Ok(result)
}
fn required(values: &BTreeMap<&str, u64>, key: &str) -> Result<u64, CgroupError> {
    values.get(key).copied().ok_or(CgroupError::Malformed)
}

fn select_pids(proc_root: &Path, issues: &mut CgroupCollectionIssues) -> Vec<u32> {
    let entries = match fs::read_dir(proc_root) {
        Ok(value) => value,
        Err(_) => {
            issues.process_enumeration_failed = true;
            return Vec::new();
        }
    };
    let mut heap = BinaryHeap::new();
    for entry in entries {
        match entry {
            Ok(entry) => {
                if let Some(pid) = entry
                    .file_name()
                    .to_str()
                    .and_then(|name| name.parse::<u32>().ok())
                {
                    if heap.len() < MAX_CGROUP_PROCESSES {
                        heap.push(pid);
                    } else if heap.peek().is_some_and(|largest| pid < *largest) {
                        heap.pop();
                        heap.push(pid);
                        issues.process_limit_reached = true;
                    } else {
                        issues.process_limit_reached = true;
                    }
                }
            }
            Err(_) => {
                issues.process_enumeration_errors =
                    issues.process_enumeration_errors.saturating_add(1)
            }
        }
    }
    let mut result = heap.into_vec();
    result.sort_unstable();
    result
}
#[derive(Clone, Copy)]
enum ProcError {
    Disappeared,
    PermissionDenied,
    Other,
}
fn read_stat(base: &Path, budget: &mut SnapshotBudget) -> Result<ProcessRaw, ProcError> {
    read_proc_limited(base.join("stat"), budget)
        .map_err(|error| classify_proc_error(&error))
        .and_then(|text| parse_process_stat(&text).map_err(|_| ProcError::Other))
}
fn read_proc_limited(path: PathBuf, budget: &mut SnapshotBudget) -> io::Result<String> {
    let file = File::open(path)?;
    let mut text = String::new();
    file.take(MAX_PROC_INPUT_BYTES + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > MAX_PROC_INPUT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proc input exceeds bound",
        ));
    }
    budget.add_bytes(text.len());
    Ok(text)
}
fn classify_proc_error(error: &io::Error) -> ProcError {
    match error.kind() {
        io::ErrorKind::NotFound => ProcError::Disappeared,
        io::ErrorKind::PermissionDenied => ProcError::PermissionDenied,
        _ => ProcError::Other,
    }
}
fn note_process_error(issues: &mut CgroupCollectionIssues, error: ProcError) {
    match error {
        ProcError::Disappeared => {
            issues.process_disappeared = issues.process_disappeared.saturating_add(1)
        }
        ProcError::PermissionDenied => {
            issues.process_permission_denied = issues.process_permission_denied.saturating_add(1)
        }
        ProcError::Other => issues.process_malformed = issues.process_malformed.saturating_add(1),
    }
}
fn classify_error(error: io::Error) -> CgroupError {
    match error.kind() {
        io::ErrorKind::NotFound => CgroupError::Unsupported,
        io::ErrorKind::PermissionDenied => CgroupError::PermissionDenied,
        _ => CgroupError::Unreadable,
    }
}
fn classify_file_error(error: &io::Error) -> CgroupFileState {
    match error.kind() {
        io::ErrorKind::NotFound => CgroupFileState::Missing,
        io::ErrorKind::PermissionDenied => CgroupFileState::PermissionDenied,
        _ => CgroupFileState::Unreadable,
    }
}

fn decode_mountinfo_path(value: &str) -> Result<String, CgroupError> {
    let mut output = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'\\' {
            output.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 3 >= bytes.len() {
            return Err(CgroupError::Malformed);
        }
        let decoded = match &bytes[index + 1..index + 4] {
            b"040" => b' ',
            b"011" => b'\t',
            b"012" => b'\n',
            b"134" => b'\\',
            _ => return Err(CgroupError::Malformed),
        };
        output.push(decoded);
        index += 4;
    }
    normalize_cgroup_path(&String::from_utf8(output).map_err(|_| CgroupError::Malformed)?)
}
fn normalize_cgroup_path(value: &str) -> Result<String, CgroupError> {
    if !value.starts_with('/') || value.len() > MAX_CGROUP_PATH_BYTES || value.contains('\0') {
        return Err(CgroupError::Malformed);
    }
    let mut components = Vec::new();
    for component in value.split('/') {
        if component.is_empty() {
            continue;
        }
        if component == "." || component == ".." {
            return Err(CgroupError::Malformed);
        }
        components.push(component);
        if components.len() > MAX_CGROUP_DEPTH {
            return Err(CgroupError::Malformed);
        }
    }
    Ok(if components.is_empty() {
        "/".to_owned()
    } else {
        format!("/{}", components.join("/"))
    })
}
fn is_below_mount_root(path: &str, root: &str) -> bool {
    path == root
        || (root == "/" && path.starts_with('/'))
        || path
            .strip_prefix(root)
            .is_some_and(|rest| rest.starts_with('/'))
}
fn parent_cgroup_path(path: &str) -> Option<String> {
    path.rsplit_once('/').map(|(parent, _)| {
        if parent.is_empty() {
            "/".to_owned()
        } else {
            parent.to_owned()
        }
    })
}
fn systemd_unit_candidate(path: &str) -> Option<String> {
    let component = path.rsplit('/').next()?;
    matches!(
        component.rsplit_once('.').map(|(_, suffix)| suffix),
        Some("service" | "scope" | "slice")
    )
    .then(|| component.to_owned())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgroupCpuInterval {
    pub usage_usec: Option<u64>,
    pub user_usec: Option<u64>,
    pub system_usec: Option<u64>,
    pub nr_periods: Option<u64>,
    pub nr_throttled: Option<u64>,
    pub throttled_usec: Option<u64>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgroupPsiInterval {
    #[serde(skip)]
    pub elapsed: Option<Duration>,
    pub some_total_usec: Option<u64>,
    pub full_total_usec: Option<u64>,
    pub state: CgroupPsiIntervalState,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgroupInterval {
    pub path: String,
    pub cpu: CgroupResource<CgroupCpuInterval>,
    pub memory_current_end: CgroupResource<u64>,
    pub memory_events: CgroupResource<CgroupMemoryEventsRaw>,
    pub memory_stat: CgroupResource<CgroupMemoryStatRaw>,
    pub io: CgroupResource<BTreeMap<CgroupIoDevice, CgroupIoRaw>>,
    pub cpu_pressure: CgroupResource<CgroupPsiInterval>,
    pub memory_pressure: CgroupResource<CgroupPsiInterval>,
    pub io_pressure: CgroupResource<CgroupPsiInterval>,
    pub systemd_unit_candidate: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgroupObservation {
    #[serde(skip)]
    pub elapsed: Duration,
    pub groups: Vec<CgroupInterval>,
    pub members: Vec<CgroupProcessMember>,
    pub issues: CgroupCollectionIssues,
}

/// Normalize only stable path identities. A deleted/recreated path has no
/// kernel generation counter, so an equal path cannot prove it was the same
/// cgroup lifetime; callers must retain this limitation as a qualifier.
pub fn cgroup_interval_from_snapshots(
    start: CgroupSnapshot,
    end: CgroupSnapshot,
    elapsed: Duration,
) -> Result<CgroupObservation, CgroupError> {
    if elapsed.is_zero() {
        return Err(CgroupError::EmptyInterval);
    }
    if start.mount != end.mount {
        return Err(CgroupError::MountChanged);
    }
    let mut issues = merge_issues(start.issues, end.issues);
    issues.members_appeared = u32::try_from(
        end.members
            .keys()
            .filter(|key| !start.members.contains_key(key))
            .count(),
    )
    .unwrap_or(u32::MAX);
    issues.members_exited = u32::try_from(
        start
            .members
            .keys()
            .filter(|key| !end.members.contains_key(key))
            .count(),
    )
    .unwrap_or(u32::MAX);
    issues.members_reused = u32::try_from(
        end.members
            .keys()
            .filter(|end_key| {
                start
                    .members
                    .keys()
                    .any(|start_key| start_key.pid == end_key.pid && start_key != *end_key)
            })
            .count(),
    )
    .unwrap_or(u32::MAX);
    let mut members = Vec::new();
    for (key, finish) in &end.members {
        if let Some(begin) = start.members.get(key) {
            if begin.cgroup_path == finish.cgroup_path {
                members.push(finish.clone());
            } else {
                issues.members_moved = issues.members_moved.saturating_add(1);
            }
        }
    }
    let mut groups = Vec::new();
    for (path, finish) in &end.groups {
        let Some(begin) = start.groups.get(path) else {
            continue;
        };
        groups.push(CgroupInterval {
            path: path.clone(),
            cpu: interval_cpu(&begin.cpu, &finish.cpu),
            memory_current_end: finish.memory_current.clone(),
            memory_events: interval_events(&begin.memory_events, &finish.memory_events),
            memory_stat: interval_memory_stat(&begin.memory_stat, &finish.memory_stat),
            io: interval_io(&begin.io, &finish.io),
            cpu_pressure: interval_psi(
                &begin.cpu_pressure,
                &finish.cpu_pressure,
                begin.cpu_pressure_at,
                finish.cpu_pressure_at,
            ),
            memory_pressure: interval_psi(
                &begin.memory_pressure,
                &finish.memory_pressure,
                begin.memory_pressure_at,
                finish.memory_pressure_at,
            ),
            io_pressure: interval_psi(
                &begin.io_pressure,
                &finish.io_pressure,
                begin.io_pressure_at,
                finish.io_pressure_at,
            ),
            systemd_unit_candidate: finish.systemd_unit_candidate.clone(),
        });
    }
    Ok(CgroupObservation {
        elapsed,
        groups,
        members,
        issues,
    })
}
fn interval_cpu(
    start: &CgroupResource<CgroupCpuRaw>,
    end: &CgroupResource<CgroupCpuRaw>,
) -> CgroupResource<CgroupCpuInterval> {
    match (&start.value, &end.value) {
        (Some(a), Some(b)) => CgroupResource::available(CgroupCpuInterval {
            usage_usec: b.usage_usec.checked_sub(a.usage_usec),
            user_usec: opt_delta(a.user_usec, b.user_usec),
            system_usec: opt_delta(a.system_usec, b.system_usec),
            nr_periods: opt_delta(a.nr_periods, b.nr_periods),
            nr_throttled: opt_delta(a.nr_throttled, b.nr_throttled),
            throttled_usec: opt_delta(a.throttled_usec, b.throttled_usec),
        }),
        _ => CgroupResource::failed(interval_missing_state(start, end)),
    }
}
fn interval_events(
    start: &CgroupResource<CgroupMemoryEventsRaw>,
    end: &CgroupResource<CgroupMemoryEventsRaw>,
) -> CgroupResource<CgroupMemoryEventsRaw> {
    match (&start.value, &end.value) {
        (Some(a), Some(b)) => CgroupResource::available(CgroupMemoryEventsRaw {
            low: opt_delta(a.low, b.low),
            high: opt_delta(a.high, b.high),
            max: opt_delta(a.max, b.max),
            oom: opt_delta(a.oom, b.oom),
            oom_kill: opt_delta(a.oom_kill, b.oom_kill),
            oom_group_kill: opt_delta(a.oom_group_kill, b.oom_group_kill),
        }),
        _ => CgroupResource::failed(interval_missing_state(start, end)),
    }
}
fn interval_memory_stat(
    start: &CgroupResource<CgroupMemoryStatRaw>,
    end: &CgroupResource<CgroupMemoryStatRaw>,
) -> CgroupResource<CgroupMemoryStatRaw> {
    match (&start.value, &end.value) {
        (Some(a), Some(b)) => CgroupResource::available(CgroupMemoryStatRaw {
            pgscan_direct: opt_delta(a.pgscan_direct, b.pgscan_direct),
            pgsteal_direct: opt_delta(a.pgsteal_direct, b.pgsteal_direct),
            pswpin: opt_delta(a.pswpin, b.pswpin),
            pswpout: opt_delta(a.pswpout, b.pswpout),
        }),
        _ => CgroupResource::failed(interval_missing_state(start, end)),
    }
}
fn interval_io(
    start: &CgroupResource<BTreeMap<CgroupIoDevice, CgroupIoRaw>>,
    end: &CgroupResource<BTreeMap<CgroupIoDevice, CgroupIoRaw>>,
) -> CgroupResource<BTreeMap<CgroupIoDevice, CgroupIoRaw>> {
    match (&start.value, &end.value) {
        (Some(a), Some(b)) => {
            let mut result = BTreeMap::new();
            for (key, last) in b {
                if let Some(first) = a.get(key) {
                    result.insert(
                        key.clone(),
                        CgroupIoRaw {
                            rbytes: opt_delta(first.rbytes, last.rbytes),
                            wbytes: opt_delta(first.wbytes, last.wbytes),
                            rios: opt_delta(first.rios, last.rios),
                            wios: opt_delta(first.wios, last.wios),
                        },
                    );
                }
            }
            CgroupResource::available(result)
        }
        _ => CgroupResource::failed(interval_missing_state(start, end)),
    }
}
fn interval_psi(
    start: &CgroupResource<CgroupPsiRaw>,
    end: &CgroupResource<CgroupPsiRaw>,
    start_at: Option<Instant>,
    end_at: Option<Instant>,
) -> CgroupResource<CgroupPsiInterval> {
    match (&start.value, &end.value) {
        (Some(a), Some(b)) => {
            let some = b.some_total_usec.checked_sub(a.some_total_usec);
            if some.is_none() {
                return CgroupResource::available(CgroupPsiInterval {
                    elapsed: None,
                    some_total_usec: None,
                    full_total_usec: None,
                    state: CgroupPsiIntervalState::SomeRegressed,
                });
            }
            let some = some.expect("checked above");
            let elapsed = start_at
                .zip(end_at)
                .and_then(|(start, end)| end.checked_duration_since(start));
            let Some(elapsed) = elapsed else {
                return CgroupResource::failed(CgroupFileState::Partial);
            };
            let elapsed_usec = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
            if some > elapsed_usec {
                return CgroupResource::available(CgroupPsiInterval {
                    elapsed: Some(elapsed),
                    some_total_usec: None,
                    full_total_usec: None,
                    state: CgroupPsiIntervalState::SomeExceedsElapsed,
                });
            }
            let full = opt_delta(a.full_total_usec, b.full_total_usec);
            let state =
                if a.full_total_usec.is_some() && b.full_total_usec.is_some() && full.is_none() {
                    CgroupPsiIntervalState::Partial
                } else if full.is_some_and(|full| full > some) {
                    CgroupPsiIntervalState::FullExceedsSome
                } else {
                    CgroupPsiIntervalState::Available
                };
            CgroupResource::available(CgroupPsiInterval {
                elapsed: Some(elapsed),
                some_total_usec: Some(some),
                full_total_usec: if state == CgroupPsiIntervalState::FullExceedsSome {
                    None
                } else {
                    full
                },
                state,
            })
        }
        _ => CgroupResource::failed(interval_missing_state(start, end)),
    }
}
fn interval_missing_state<T>(
    start: &CgroupResource<T>,
    end: &CgroupResource<T>,
) -> CgroupFileState {
    if start.value.is_some() || end.value.is_some() {
        CgroupFileState::Partial
    } else {
        end.state
    }
}
fn opt_delta(start: Option<u64>, end: Option<u64>) -> Option<u64> {
    match (start, end) {
        (Some(a), Some(b)) => b.checked_sub(a),
        _ => None,
    }
}
fn merge_issues(
    mut start: CgroupCollectionIssues,
    end: CgroupCollectionIssues,
) -> CgroupCollectionIssues {
    start.process_enumeration_failed |= end.process_enumeration_failed;
    start.process_enumeration_errors = start
        .process_enumeration_errors
        .saturating_add(end.process_enumeration_errors);
    start.process_disappeared = start
        .process_disappeared
        .saturating_add(end.process_disappeared);
    start.process_identity_changed = start
        .process_identity_changed
        .saturating_add(end.process_identity_changed);
    start.process_permission_denied = start
        .process_permission_denied
        .saturating_add(end.process_permission_denied);
    start.process_malformed = start
        .process_malformed
        .saturating_add(end.process_malformed);
    start.process_limit_reached |= end.process_limit_reached;
    start.cgroup_limit_reached |= end.cgroup_limit_reached;
    start.path_rejected = start.path_rejected.saturating_add(end.path_rejected);
    start.cgroup_disappeared = start
        .cgroup_disappeared
        .saturating_add(end.cgroup_disappeared);
    start.cgroup_permission_denied = start
        .cgroup_permission_denied
        .saturating_add(end.cgroup_permission_denied);
    start.cgroup_unreadable = start
        .cgroup_unreadable
        .saturating_add(end.cgroup_unreadable);
    start.cgroup_malformed = start.cgroup_malformed.saturating_add(end.cgroup_malformed);
    start.budget_exhausted |= end.budget_exhausted;
    start.read_attempts = start.read_attempts.saturating_add(end.read_attempts);
    start.bytes_read = start.bytes_read.saturating_add(end.bytes_read);
    start
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
    struct TempTree(PathBuf);
    impl TempTree {
        fn new() -> Self {
            for _ in 0..100 {
                let path = std::env::temp_dir().join(format!(
                    "cgroup-fixture-{}-{}",
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_nanos(),
                    TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
                ));
                if fs::create_dir(&path).is_ok() {
                    return Self(path);
                }
            }
            panic!("could not create unique cgroup fixture directory");
        }
    }
    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn mount(name: &str) -> Cgroup2Mount {
        Cgroup2Mount {
            root: "/".into(),
            mount_point: PathBuf::from(name),
        }
    }
    fn member(pid: u32, start: u64, path: &str) -> CgroupProcessMember {
        CgroupProcessMember {
            key: ProcessKey {
                pid,
                start_time_ticks: start,
            },
            name: "task".into(),
            cgroup_path: path.into(),
        }
    }
    fn raw(path: &str, psi: Option<CgroupPsiRaw>) -> CgroupRaw {
        CgroupRaw {
            path: path.into(),
            cpu: CgroupResource::failed(CgroupFileState::Missing),
            memory_current: CgroupResource::failed(CgroupFileState::Missing),
            memory_events: CgroupResource::failed(CgroupFileState::Missing),
            memory_stat: CgroupResource::failed(CgroupFileState::Missing),
            io: CgroupResource::failed(CgroupFileState::Missing),
            cpu_pressure: psi
                .clone()
                .map(CgroupResource::available)
                .unwrap_or_else(|| CgroupResource::failed(CgroupFileState::Missing)),
            memory_pressure: CgroupResource::failed(CgroupFileState::Missing),
            io_pressure: CgroupResource::failed(CgroupFileState::Missing),
            cpu_pressure_at: psi
                .is_some()
                .then(|| Instant::now() - Duration::from_secs(1)),
            memory_pressure_at: None,
            io_pressure_at: None,
            systemd_unit_candidate: None,
        }
    }
    fn snapshot(
        mount: Cgroup2Mount,
        members: Vec<CgroupProcessMember>,
        psi: Option<CgroupPsiRaw>,
    ) -> CgroupSnapshot {
        CgroupSnapshot {
            mount,
            members: members
                .into_iter()
                .map(|member| (member.key, member))
                .collect(),
            groups: BTreeMap::from([("/x".into(), raw("/x", psi))]),
            issues: CgroupCollectionIssues::default(),
        }
    }
    #[test]
    fn mountinfo_decodes_and_rejects_unsafe_paths() {
        let mount = parse_cgroup2_mountinfo(
            "29 23 0:26 /my\\040root /sys/fs/cgroup rw - cgroup2 cgroup rw\n",
        )
        .unwrap();
        assert_eq!(mount.root, "/my root");
        assert_eq!(mount.mount_point, PathBuf::from("/sys/fs/cgroup"));
        assert_eq!(
            parse_cgroup2_mountinfo(
                "1 0 0:1 / /x rw - cgroup2 cgroup rw\n2 0 0:2 / /y rw - cgroup2 cgroup rw\n"
            ),
            Err(CgroupError::AmbiguousMount)
        );
        assert!(parse_cgroup2_mountinfo("1 0 0:1 /../x /x rw - cgroup2 cgroup rw\n").is_err());
        assert!(parse_cgroup2_mountinfo("1 0 0:1 /bad\\999 /x rw - cgroup2 cgroup rw\n").is_err());
    }
    #[test]
    fn unified_path_is_strict() {
        assert_eq!(
            parse_unified_cgroup("0::/system.slice/a.service\n").unwrap(),
            "/system.slice/a.service"
        );
        assert!(parse_unified_cgroup("0::/a/../b\n").is_err());
        assert!(parse_unified_cgroup("1:cpu:/x\n").is_err());
    }
    #[test]
    fn parsers_preserve_optional_counters() {
        let cpu = parse_cpu_stat(include_str!("../tests/fixtures/cgroup-cpu-stat-valid")).unwrap();
        assert_eq!(cpu.usage_usec, 100);
        assert_eq!(cpu.system_usec, Some(30));
        let io = parse_io_stat(include_str!("../tests/fixtures/cgroup-io-stat-valid")).unwrap();
        assert_eq!(
            io[&CgroupIoDevice { major: 8, minor: 0 }].rbytes,
            Some(1024)
        );
        assert_eq!(
            io[&CgroupIoDevice { major: 8, minor: 0 }].wbytes,
            Some(2048)
        );
        assert_eq!(
            parse_cgroup_psi(include_str!("../tests/fixtures/cgroup-pressure-valid"))
                .unwrap()
                .some_total_usec,
            123
        );
        assert_eq!(
            parse_memory_events(include_str!("../tests/fixtures/cgroup-memory-events-valid"))
                .unwrap()
                .high,
            Some(2)
        );
        let stat =
            parse_memory_stat(include_str!("../tests/fixtures/cgroup-memory-stat-valid")).unwrap();
        assert_eq!(stat.pgscan_direct, Some(12));
        assert_eq!(stat.pgsteal_direct, Some(8));
        assert_eq!(stat.pswpin, Some(3));
        assert_eq!(stat.pswpout, Some(4));
    }
    #[test]
    fn paths_collect_ancestors_and_bound_count() {
        let mount = Cgroup2Mount {
            root: "/".into(),
            mount_point: "/x".into(),
        };
        let mut issues = CgroupCollectionIssues::default();
        let got = active_paths(&mount, ["/a/b/c"].into_iter(), &mut issues);
        assert!(got.contains("/"));
        assert!(got.contains("/a/b"));
        let mut too_many = String::from("/");
        for n in 0..65 {
            too_many.push_str(&format!("a{n}/"));
        }
        assert!(normalize_cgroup_path(&too_many).is_err());
    }
    #[test]
    fn interval_omits_regression_and_pid_move_is_not_matched() {
        let mount = Cgroup2Mount {
            root: "/".into(),
            mount_point: "/x".into(),
        };
        let raw = |usage| CgroupRaw {
            path: "/x".into(),
            cpu: CgroupResource::available(CgroupCpuRaw {
                usage_usec: usage,
                user_usec: None,
                system_usec: None,
                nr_periods: None,
                nr_throttled: None,
                throttled_usec: None,
            }),
            memory_current: CgroupResource::failed(CgroupFileState::Missing),
            memory_events: CgroupResource::failed(CgroupFileState::Missing),
            memory_stat: CgroupResource::failed(CgroupFileState::Missing),
            io: CgroupResource::failed(CgroupFileState::Missing),
            cpu_pressure: CgroupResource::failed(CgroupFileState::Missing),
            memory_pressure: CgroupResource::failed(CgroupFileState::Missing),
            io_pressure: CgroupResource::failed(CgroupFileState::Missing),
            cpu_pressure_at: None,
            memory_pressure_at: None,
            io_pressure_at: None,
            systemd_unit_candidate: None,
        };
        let start = CgroupSnapshot {
            mount: mount.clone(),
            members: BTreeMap::new(),
            groups: BTreeMap::from([("/x".into(), raw(9))]),
            issues: CgroupCollectionIssues::default(),
        };
        let end = CgroupSnapshot {
            mount,
            members: BTreeMap::new(),
            groups: BTreeMap::from([("/x".into(), raw(3))]),
            issues: CgroupCollectionIssues::default(),
        };
        let observation =
            cgroup_interval_from_snapshots(start, end, Duration::from_secs(1)).unwrap();
        assert_eq!(
            observation.groups[0].cpu.value.as_ref().unwrap().usage_usec,
            None
        );
    }
    #[test]
    fn membership_interval_retains_stable_path_and_excludes_moves_and_reuse() {
        let stable = member(1, 10, "/x");
        let observed = cgroup_interval_from_snapshots(
            snapshot(mount("/cg"), vec![stable.clone()], None),
            snapshot(mount("/cg"), vec![stable.clone()], None),
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(observed.members, vec![stable.clone()]);
        let moved = member(1, 10, "/y");
        let observed = cgroup_interval_from_snapshots(
            snapshot(mount("/cg"), vec![stable], None),
            snapshot(mount("/cg"), vec![moved], None),
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(observed.members.is_empty());
        assert_eq!(observed.issues.members_moved, 1);
        let observed = cgroup_interval_from_snapshots(
            snapshot(mount("/cg"), vec![member(1, 10, "/x")], None),
            snapshot(mount("/cg"), vec![member(1, 11, "/x")], None),
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(observed.members.is_empty());
        assert_eq!(observed.issues.members_reused, 1);
        assert_eq!(observed.issues.members_appeared, 1);
        assert_eq!(observed.issues.members_exited, 1);
    }
    #[test]
    fn rejects_mount_change_before_normalization() {
        assert_eq!(
            cgroup_interval_from_snapshots(
                snapshot(mount("/one"), vec![], None),
                snapshot(mount("/two"), vec![], None),
                Duration::from_secs(1)
            ),
            Err(CgroupError::MountChanged)
        );
    }
    #[test]
    fn psi_interval_preserves_valid_some_and_qualifies_full_anomalies() {
        let interval = |start, end| {
            let instant = Instant::now();
            interval_psi(
                &CgroupResource::available(start),
                &CgroupResource::available(end),
                Some(instant),
                Some(instant + Duration::from_secs(1)),
            )
        };
        let some_regressed = interval(
            CgroupPsiRaw {
                some_total_usec: 10,
                full_total_usec: Some(1),
            },
            CgroupPsiRaw {
                some_total_usec: 9,
                full_total_usec: Some(2),
            },
        );
        assert_eq!(
            some_regressed.value.unwrap().state,
            CgroupPsiIntervalState::SomeRegressed
        );
        let full_regressed = interval(
            CgroupPsiRaw {
                some_total_usec: 10,
                full_total_usec: Some(5),
            },
            CgroupPsiRaw {
                some_total_usec: 20,
                full_total_usec: Some(4),
            },
        )
        .value
        .unwrap();
        assert_eq!(full_regressed.some_total_usec, Some(10));
        assert_eq!(full_regressed.full_total_usec, None);
        assert_eq!(full_regressed.state, CgroupPsiIntervalState::Partial);
        let exceeds = interval(
            CgroupPsiRaw {
                some_total_usec: 10,
                full_total_usec: Some(1),
            },
            CgroupPsiRaw {
                some_total_usec: 12,
                full_total_usec: Some(5),
            },
        )
        .value
        .unwrap();
        assert_eq!(exceeds.some_total_usec, Some(2));
        assert_eq!(exceeds.full_total_usec, None);
        assert_eq!(exceeds.state, CgroupPsiIntervalState::FullExceedsSome);
        assert_eq!(
            parse_cgroup_psi("some total=4\nfull total=5\n"),
            Err(CgroupError::Malformed)
        );
    }
    #[test]
    fn psi_some_delta_must_fit_the_measured_interval() {
        let observe = |end_total| {
            let instant = Instant::now();
            interval_psi(
                &CgroupResource::available(CgroupPsiRaw {
                    some_total_usec: 0,
                    full_total_usec: Some(0),
                }),
                &CgroupResource::available(CgroupPsiRaw {
                    some_total_usec: end_total,
                    full_total_usec: Some(0),
                }),
                Some(instant),
                Some(instant + Duration::from_micros(10)),
            )
            .value
            .unwrap()
        };
        let exact = observe(10);
        assert_eq!(exact.some_total_usec, Some(10));
        assert_eq!(exact.state, CgroupPsiIntervalState::Available);
        let excessive = observe(11);
        assert_eq!(excessive.some_total_usec, None);
        assert_eq!(excessive.full_total_usec, None);
        assert_eq!(excessive.state, CgroupPsiIntervalState::SomeExceedsElapsed);
    }
    #[test]
    fn interval_missing_endpoint_is_never_marked_available() {
        let missing_cpu = CgroupResource::failed(CgroupFileState::Missing);
        let cpu = CgroupResource::available(CgroupCpuRaw {
            usage_usec: 1,
            user_usec: None,
            system_usec: None,
            nr_periods: None,
            nr_throttled: None,
            throttled_usec: None,
        });
        assert_eq!(
            interval_cpu(&missing_cpu, &cpu).state,
            CgroupFileState::Partial
        );
        assert_eq!(
            interval_cpu(&cpu, &missing_cpu).state,
            CgroupFileState::Partial
        );
        let missing_events = CgroupResource::failed(CgroupFileState::Missing);
        let events = CgroupResource::available(CgroupMemoryEventsRaw {
            low: None,
            high: None,
            max: None,
            oom: None,
            oom_kill: None,
            oom_group_kill: None,
        });
        assert_eq!(
            interval_events(&missing_events, &events).state,
            CgroupFileState::Partial
        );
        assert_eq!(
            interval_events(&events, &missing_events).state,
            CgroupFileState::Partial
        );
        let missing_stat = CgroupResource::failed(CgroupFileState::Missing);
        let stat = CgroupResource::available(CgroupMemoryStatRaw {
            pgscan_direct: Some(1),
            pgsteal_direct: Some(1),
            pswpin: Some(0),
            pswpout: Some(0),
        });
        assert_eq!(
            interval_memory_stat(&missing_stat, &stat).state,
            CgroupFileState::Partial
        );
        assert_eq!(
            interval_memory_stat(&stat, &missing_stat).state,
            CgroupFileState::Partial
        );
        let missing_io = CgroupResource::failed(CgroupFileState::Missing);
        let io = CgroupResource::available(BTreeMap::<CgroupIoDevice, CgroupIoRaw>::new());
        assert_eq!(
            interval_io(&missing_io, &io).state,
            CgroupFileState::Partial
        );
        assert_eq!(
            interval_io(&io, &missing_io).state,
            CgroupFileState::Partial
        );
        let missing_psi = CgroupResource::failed(CgroupFileState::Missing);
        let psi = CgroupResource::available(CgroupPsiRaw {
            some_total_usec: 1,
            full_total_usec: None,
        });
        assert_eq!(
            interval_psi(&missing_psi, &psi, None, Some(Instant::now())).state,
            CgroupFileState::Partial
        );
        assert_eq!(
            interval_psi(&psi, &missing_psi, Some(Instant::now()), None).state,
            CgroupFileState::Partial
        );
    }
    #[test]
    fn active_path_cap_keeps_every_leaf_before_ancestors() {
        let leaves: Vec<String> = (0..MAX_CGROUPS)
            .map(|index| format!("/leaf-{index}/child"))
            .collect();
        let mut issues = CgroupCollectionIssues::default();
        let result = active_paths(
            &mount("/cg"),
            leaves.iter().map(String::as_str),
            &mut issues,
        );
        assert!(issues.cgroup_limit_reached);
        assert_eq!(result.len(), MAX_CGROUPS);
        assert!(leaves.iter().all(|leaf| result.contains(leaf)));
    }
    #[test]
    fn systemd_candidates_are_conservative() {
        assert_eq!(
            systemd_unit_candidate("/a/foo.service"),
            Some("foo.service".into())
        );
        assert_eq!(systemd_unit_candidate("/a/foo.socket"), None);
    }
    #[test]
    fn fixture_tree_collects_stable_members_and_active_ancestors() {
        let root = TempTree::new();
        let proc_root = root.0.join("proc");
        let cg_root = root.0.join("cg");
        fs::create_dir_all(proc_root.join("123")).unwrap();
        fs::create_dir_all(cg_root.join("system.slice/example.service")).unwrap();
        let stat = include_str!("../tests/fixtures/proc-pid-stat-unusual-name");
        fs::write(proc_root.join("123/stat"), stat).unwrap();
        fs::write(
            proc_root.join("123/cgroup"),
            include_str!("../tests/fixtures/proc-pid-cgroup-unified"),
        )
        .unwrap();
        let group = cg_root.join("system.slice/example.service");
        fs::write(
            group.join("cpu.stat"),
            include_str!("../tests/fixtures/cgroup-cpu-stat-valid"),
        )
        .unwrap();
        fs::write(group.join("memory.current"), "7\n").unwrap();
        let snapshot = read_cgroup_snapshot_with_mount_at(
            &proc_root,
            Cgroup2Mount {
                root: "/".into(),
                mount_point: cg_root,
            },
        )
        .unwrap();
        assert_eq!(snapshot.members.len(), 1);
        assert!(
            snapshot
                .groups
                .contains_key("/system.slice/example.service")
        );
        assert!(snapshot.groups.contains_key("/system.slice"));
    }

    #[test]
    fn completeness_assessment_marks_limits_permissions_and_missing_resources_partial() {
        let base = CgroupCollectionIssues::default();
        assert!(!collection_is_partial(&base));

        for mutate in [
            |issues: &mut CgroupCollectionIssues| issues.process_limit_reached = true,
            |issues: &mut CgroupCollectionIssues| issues.cgroup_limit_reached = true,
            |issues: &mut CgroupCollectionIssues| issues.budget_exhausted = true,
            |issues: &mut CgroupCollectionIssues| issues.process_permission_denied = 1,
            |issues: &mut CgroupCollectionIssues| issues.cgroup_permission_denied = 1,
            |issues: &mut CgroupCollectionIssues| issues.cgroup_unreadable = 1,
            |issues: &mut CgroupCollectionIssues| issues.members_moved = 1,
        ] {
            let mut issues = CgroupCollectionIssues::default();
            mutate(&mut issues);
            assert!(collection_is_partial(&issues));
        }

        let snapshot = CgroupSnapshot {
            mount: mount("/cg"),
            members: BTreeMap::new(),
            groups: BTreeMap::from([("/x".into(), raw("/x", None))]),
            issues: CgroupCollectionIssues::default(),
        };
        assert_eq!(
            cgroup_capability_from_snapshot(&snapshot),
            CgroupCapability::Partial
        );
    }

    #[test]
    fn issue_merge_includes_both_endpoint_costs_and_budget_exhaustion() {
        let start = CgroupCollectionIssues {
            budget_exhausted: false,
            read_attempts: 4,
            bytes_read: 10,
            ..CgroupCollectionIssues::default()
        };
        let end = CgroupCollectionIssues {
            budget_exhausted: true,
            read_attempts: 7,
            bytes_read: 20,
            ..CgroupCollectionIssues::default()
        };
        let merged = merge_issues(start, end);
        assert!(merged.budget_exhausted);
        assert_eq!(merged.read_attempts, 11);
        assert_eq!(merged.bytes_read, 30);

        let merged = merge_issues(
            CgroupCollectionIssues {
                read_attempts: u32::MAX,
                bytes_read: u64::MAX,
                ..CgroupCollectionIssues::default()
            },
            CgroupCollectionIssues {
                read_attempts: 1,
                bytes_read: 1,
                ..CgroupCollectionIssues::default()
            },
        );
        assert_eq!(merged.read_attempts, u32::MAX);
        assert_eq!(merged.bytes_read, u64::MAX);
    }
}
