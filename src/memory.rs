//! Bounded host-memory context collected from procfs.
//!
//! This module intentionally keeps memory gauges and VM counters separate from
//! memory-pressure inference.  In particular, neither occupancy nor a counter
//! rate is itself a memory-bottleneck verdict.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;
use std::time::Duration;

use serde::Serialize;

const MEMINFO_PATH: &str = "meminfo";
const VMSTAT_PATH: &str = "vmstat";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MeminfoRaw {
    pub mem_total_bytes: u64,
    pub mem_available_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_free_bytes: u64,
    /// Page-cache context only; it is not a claim of reclaimability.
    pub cached_bytes: Option<u64>,
    /// Reclaimable slab context only; it is not a claim of reclaimability.
    pub sreclaimable_bytes: Option<u64>,
    /// Anonymous-memory context only; it is not a process RSS measurement.
    pub anon_pages_bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VmstatCounter {
    PageFaults,
    MajorPageFaults,
    SwapIn,
    SwapOut,
    ScanKswapd,
    ScanDirect,
    StealKswapd,
    StealDirect,
}

impl VmstatCounter {
    pub const ALL: [Self; 8] = [
        Self::PageFaults,
        Self::MajorPageFaults,
        Self::SwapIn,
        Self::SwapOut,
        Self::ScanKswapd,
        Self::ScanDirect,
        Self::StealKswapd,
        Self::StealDirect,
    ];

    fn from_proc_name(name: &str) -> Option<Self> {
        match name {
            "pgfault" => Some(Self::PageFaults),
            "pgmajfault" => Some(Self::MajorPageFaults),
            "pswpin" => Some(Self::SwapIn),
            "pswpout" => Some(Self::SwapOut),
            "pgscan_kswapd" => Some(Self::ScanKswapd),
            "pgscan_direct" => Some(Self::ScanDirect),
            "pgsteal_kswapd" => Some(Self::StealKswapd),
            "pgsteal_direct" => Some(Self::StealDirect),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct VmstatRaw {
    /// Raw kernel page/event counters.  Page counts deliberately remain pages,
    /// rather than being presented as bytes without a page-size contract.
    pub counters: BTreeMap<VmstatCounter, u64>,
    pub missing: Vec<VmstatCounter>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryContextCapability {
    Available,
    Partial,
    Unsupported,
    PermissionDenied,
    Failed,
}

impl MemoryContextCapability {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryContextError {
    Unsupported,
    PermissionDenied,
    Unreadable,
    Malformed,
    EmptyInterval,
}

impl MemoryContextError {
    const fn capability(self) -> MemoryContextCapability {
        match self {
            Self::Unsupported => MemoryContextCapability::Unsupported,
            Self::PermissionDenied => MemoryContextCapability::PermissionDenied,
            Self::Unreadable | Self::Malformed | Self::EmptyInterval => {
                MemoryContextCapability::Failed
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryContextSnapshot {
    pub meminfo: Result<MeminfoRaw, MemoryContextError>,
    pub vmstat: Result<VmstatRaw, MemoryContextError>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MemoryContextCapabilities {
    pub meminfo: MemoryContextCapability,
    pub vmstat: MemoryContextCapability,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct VmstatIntervalIssues {
    pub missing: Vec<VmstatCounter>,
    pub regressed: Vec<VmstatCounter>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MemoryContextObservation {
    /// The exact time between the two snapshots supplied by the caller.
    #[serde(skip)]
    pub elapsed: Duration,
    /// The end gauge is retained whenever the second meminfo read succeeded.
    pub end_meminfo: Option<MeminfoRaw>,
    pub meminfo_capability: MemoryContextCapability,
    pub vmstat_capability: MemoryContextCapability,
    /// Available counter deltas only. Missing or regressed counters are never
    /// synthesized as zero.
    pub vmstat_deltas: BTreeMap<VmstatCounter, u64>,
    pub vmstat_issues: VmstatIntervalIssues,
}

pub fn probe_memory_context() -> MemoryContextCapabilities {
    probe_memory_context_at(Path::new("/proc"))
}

pub fn probe_memory_context_at(proc_root: &Path) -> MemoryContextCapabilities {
    let snapshot = read_memory_context_snapshot_at(proc_root);
    MemoryContextCapabilities {
        meminfo: snapshot_capability(&snapshot.meminfo),
        vmstat: vmstat_snapshot_capability(&snapshot.vmstat),
    }
}

pub fn read_memory_context_snapshot() -> MemoryContextSnapshot {
    read_memory_context_snapshot_at(Path::new("/proc"))
}

pub fn read_memory_context_snapshot_at(proc_root: &Path) -> MemoryContextSnapshot {
    MemoryContextSnapshot {
        meminfo: read_meminfo_at(proc_root),
        vmstat: read_vmstat_at(proc_root),
    }
}

pub fn read_meminfo_at(proc_root: &Path) -> Result<MeminfoRaw, MemoryContextError> {
    fs::read_to_string(proc_root.join(MEMINFO_PATH))
        .map_err(classify_read_error)
        .and_then(|contents| parse_meminfo(&contents))
}

pub fn read_vmstat_at(proc_root: &Path) -> Result<VmstatRaw, MemoryContextError> {
    fs::read_to_string(proc_root.join(VMSTAT_PATH))
        .map_err(classify_read_error)
        .and_then(|contents| parse_vmstat(&contents))
}

pub fn parse_meminfo(input: &str) -> Result<MeminfoRaw, MemoryContextError> {
    let mut values = BTreeMap::new();
    for line in input.lines().filter(|line| !line.trim().is_empty()) {
        let (name, rest) = line.split_once(':').ok_or(MemoryContextError::Malformed)?;
        if !matches!(
            name,
            "MemTotal"
                | "MemAvailable"
                | "SwapTotal"
                | "SwapFree"
                | "Cached"
                | "SReclaimable"
                | "AnonPages"
        ) {
            continue;
        }
        if values.contains_key(name) {
            return Err(MemoryContextError::Malformed);
        }
        let fields: Vec<_> = rest.split_ascii_whitespace().collect();
        if fields.len() != 2 || fields[1] != "kB" {
            return Err(MemoryContextError::Malformed);
        }
        let kib: u64 = fields[0]
            .parse()
            .map_err(|_| MemoryContextError::Malformed)?;
        let bytes = kib.checked_mul(1024).ok_or(MemoryContextError::Malformed)?;
        values.insert(name, bytes);
    }

    let required = |name| {
        values
            .get(name)
            .copied()
            .ok_or(MemoryContextError::Malformed)
    };
    let mem_total_bytes = required("MemTotal")?;
    let mem_available_bytes = required("MemAvailable")?;
    let swap_total_bytes = required("SwapTotal")?;
    let swap_free_bytes = required("SwapFree")?;
    if mem_total_bytes == 0
        || mem_available_bytes > mem_total_bytes
        || swap_free_bytes > swap_total_bytes
    {
        return Err(MemoryContextError::Malformed);
    }
    Ok(MeminfoRaw {
        mem_total_bytes,
        mem_available_bytes,
        swap_total_bytes,
        swap_free_bytes,
        cached_bytes: values.get("Cached").copied(),
        sreclaimable_bytes: values.get("SReclaimable").copied(),
        anon_pages_bytes: values.get("AnonPages").copied(),
    })
}

pub fn parse_vmstat(input: &str) -> Result<VmstatRaw, MemoryContextError> {
    let mut counters = BTreeMap::new();
    for line in input.lines().filter(|line| !line.trim().is_empty()) {
        let mut fields = line.split_ascii_whitespace();
        let Some(name) = fields.next() else { continue };
        let Some(counter) = VmstatCounter::from_proc_name(name) else {
            continue;
        };
        let value = fields.next().ok_or(MemoryContextError::Malformed)?;
        if fields.next().is_some() || counters.contains_key(&counter) {
            return Err(MemoryContextError::Malformed);
        }
        counters.insert(
            counter,
            value.parse().map_err(|_| MemoryContextError::Malformed)?,
        );
    }
    let missing = VmstatCounter::ALL
        .into_iter()
        .filter(|counter| !counters.contains_key(counter))
        .collect();
    Ok(VmstatRaw { counters, missing })
}

pub fn interval_from_snapshots(
    start: MemoryContextSnapshot,
    end: MemoryContextSnapshot,
    elapsed: Duration,
) -> Result<MemoryContextObservation, MemoryContextError> {
    if elapsed.is_zero() {
        return Err(MemoryContextError::EmptyInterval);
    }

    let end_meminfo = end.meminfo.as_ref().ok().cloned();
    let meminfo_capability = interval_capability(&start.meminfo, &end.meminfo, false);
    let mut vmstat_deltas = BTreeMap::new();
    let mut vmstat_issues = VmstatIntervalIssues::default();

    if let (Ok(start_raw), Ok(end_raw)) = (&start.vmstat, &end.vmstat) {
        for counter in VmstatCounter::ALL {
            match (
                start_raw.counters.get(&counter),
                end_raw.counters.get(&counter),
            ) {
                (Some(start_value), Some(end_value)) => match end_value.checked_sub(*start_value) {
                    Some(delta) => {
                        vmstat_deltas.insert(counter, delta);
                    }
                    None => vmstat_issues.regressed.push(counter),
                },
                _ => vmstat_issues.missing.push(counter),
            }
        }
    } else {
        vmstat_issues.missing.extend(VmstatCounter::ALL);
    }
    let vmstat_capability = interval_capability(
        &start.vmstat,
        &end.vmstat,
        !vmstat_issues.missing.is_empty() || !vmstat_issues.regressed.is_empty(),
    );

    Ok(MemoryContextObservation {
        elapsed,
        end_meminfo,
        meminfo_capability,
        vmstat_capability,
        vmstat_deltas,
        vmstat_issues,
    })
}

fn classify_read_error(error: io::Error) -> MemoryContextError {
    match error.kind() {
        io::ErrorKind::NotFound => MemoryContextError::Unsupported,
        io::ErrorKind::PermissionDenied => MemoryContextError::PermissionDenied,
        _ => MemoryContextError::Unreadable,
    }
}

fn snapshot_capability<T>(result: &Result<T, MemoryContextError>) -> MemoryContextCapability {
    result.as_ref().map_or_else(
        |error| error.capability(),
        |_| MemoryContextCapability::Available,
    )
}

fn vmstat_snapshot_capability(
    result: &Result<VmstatRaw, MemoryContextError>,
) -> MemoryContextCapability {
    match result {
        Ok(raw) if raw.missing.is_empty() => MemoryContextCapability::Available,
        Ok(_) => MemoryContextCapability::Partial,
        Err(error) => error.capability(),
    }
}

fn interval_capability<T>(
    start: &Result<T, MemoryContextError>,
    end: &Result<T, MemoryContextError>,
    partial: bool,
) -> MemoryContextCapability {
    match (start, end) {
        (Ok(_), Ok(_)) if !partial => MemoryContextCapability::Available,
        (Ok(_), _) | (_, Ok(_)) => MemoryContextCapability::Partial,
        (Err(start_error), Err(end_error)) if start_error == end_error => start_error.capability(),
        (Err(_), Err(_)) => MemoryContextCapability::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    const MEMINFO: &str = include_str!("../tests/fixtures/proc-meminfo-valid");
    const VMSTAT: &str = include_str!("../tests/fixtures/proc-vmstat-valid");

    fn snapshot(
        meminfo: Result<MeminfoRaw, MemoryContextError>,
        vmstat: Result<VmstatRaw, MemoryContextError>,
    ) -> MemoryContextSnapshot {
        MemoryContextSnapshot { meminfo, vmstat }
    }

    #[test]
    fn parses_meminfo_fixture_with_checked_kibibytes() {
        let parsed = parse_meminfo(MEMINFO).unwrap();
        assert_eq!(parsed.mem_total_bytes, 16_384 * 1024);
        assert_eq!(parsed.mem_available_bytes, 4_096 * 1024);
        assert_eq!(parsed.cached_bytes, Some(512 * 1024));
    }

    #[test]
    fn meminfo_rejects_missing_duplicate_bad_units_overflow_and_inconsistent_gauges() {
        for invalid in [
            "MemTotal: 1 kB\nMemAvailable: 1 kB\nSwapTotal: 1 kB\n",
            "MemTotal: 1 kB\nMemTotal: 1 kB\nMemAvailable: 1 kB\nSwapTotal: 1 kB\nSwapFree: 1 kB\n",
            "MemTotal: 1 MB\nMemAvailable: 1 kB\nSwapTotal: 1 kB\nSwapFree: 1 kB\n",
            "MemTotal: 18446744073709551615 kB\nMemAvailable: 1 kB\nSwapTotal: 1 kB\nSwapFree: 1 kB\n",
            "MemTotal: 1 kB\nMemAvailable: 2 kB\nSwapTotal: 1 kB\nSwapFree: 1 kB\n",
            "MemTotal: 1 kB\nMemAvailable: 1 kB\nSwapTotal: 1 kB\nSwapFree: 2 kB\n",
            "MemTotal: 0 kB\nMemAvailable: 0 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n",
        ] {
            assert_eq!(parse_meminfo(invalid), Err(MemoryContextError::Malformed));
        }
    }

    #[test]
    fn vmstat_retains_missing_counters_and_rejects_bad_selected_lines() {
        let parsed = parse_vmstat("pgfault 7\npswpout 9\nunknown nonsense\n").unwrap();
        assert_eq!(parsed.counters[&VmstatCounter::PageFaults], 7);
        assert!(parsed.missing.contains(&VmstatCounter::MajorPageFaults));
        for invalid in [
            "pgfault not-a-number\n",
            "pgfault 1\npgfault 2\n",
            "pgfault 1 extra\n",
        ] {
            assert_eq!(parse_vmstat(invalid), Err(MemoryContextError::Malformed));
        }
    }

    #[test]
    fn normalizes_each_vm_counter_independently_and_marks_regressions() {
        let start_vm = parse_vmstat(VMSTAT).unwrap();
        let mut end_vm = start_vm.clone();
        end_vm.counters.insert(VmstatCounter::PageFaults, 110);
        end_vm.counters.insert(VmstatCounter::MajorPageFaults, 3);
        let observation = interval_from_snapshots(
            snapshot(Ok(parse_meminfo(MEMINFO).unwrap()), Ok(start_vm)),
            snapshot(Ok(parse_meminfo(MEMINFO).unwrap()), Ok(end_vm)),
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(observation.vmstat_deltas[&VmstatCounter::PageFaults], 10);
        assert!(
            !observation
                .vmstat_deltas
                .contains_key(&VmstatCounter::MajorPageFaults)
        );
        assert_eq!(
            observation.vmstat_issues.regressed,
            vec![VmstatCounter::MajorPageFaults]
        );
        assert_eq!(
            observation.vmstat_capability,
            MemoryContextCapability::Partial
        );
    }

    #[test]
    fn end_gauge_survives_a_missing_start_and_capability_is_partial() {
        let observation = interval_from_snapshots(
            snapshot(
                Err(MemoryContextError::Unsupported),
                Ok(parse_vmstat(VMSTAT).unwrap()),
            ),
            snapshot(
                Ok(parse_meminfo(MEMINFO).unwrap()),
                Ok(parse_vmstat(VMSTAT).unwrap()),
            ),
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(observation.end_meminfo.is_some());
        assert_eq!(
            observation.meminfo_capability,
            MemoryContextCapability::Partial
        );
    }

    #[test]
    fn interval_capabilities_preserve_terminal_errors_and_mixed_failures() {
        let vmstat = Ok(parse_vmstat(VMSTAT).unwrap());
        let unsupported = interval_from_snapshots(
            snapshot(Err(MemoryContextError::Unsupported), vmstat.clone()),
            snapshot(Err(MemoryContextError::Unsupported), vmstat.clone()),
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(
            unsupported.meminfo_capability,
            MemoryContextCapability::Unsupported
        );

        let denied = interval_from_snapshots(
            snapshot(Err(MemoryContextError::PermissionDenied), vmstat.clone()),
            snapshot(Err(MemoryContextError::PermissionDenied), vmstat.clone()),
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(
            denied.meminfo_capability,
            MemoryContextCapability::PermissionDenied
        );

        let mixed = interval_from_snapshots(
            snapshot(Err(MemoryContextError::Unsupported), vmstat.clone()),
            snapshot(Err(MemoryContextError::Malformed), vmstat),
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(mixed.meminfo_capability, MemoryContextCapability::Failed);
    }

    #[test]
    fn injected_proc_root_supports_reads_and_capability_probes() {
        let root = std::env::temp_dir().join(format!(
            "bottleneck-memory-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        fs::write(root.join(MEMINFO_PATH), MEMINFO).unwrap();
        fs::write(root.join(VMSTAT_PATH), VMSTAT).unwrap();
        let snapshot = read_memory_context_snapshot_at(&root);
        assert!(snapshot.meminfo.is_ok());
        assert!(snapshot.vmstat.is_ok());
        assert_eq!(
            probe_memory_context_at(&root).meminfo,
            MemoryContextCapability::Available
        );
        assert_eq!(
            probe_memory_context_at(&root).vmstat,
            MemoryContextCapability::Available
        );
        fs::remove_file(root.join(VMSTAT_PATH)).unwrap();
        assert_eq!(
            probe_memory_context_at(&root).vmstat,
            MemoryContextCapability::Unsupported
        );
        fs::remove_file(root.join(MEMINFO_PATH)).unwrap();
        fs::remove_dir(&root).unwrap();
    }
}
