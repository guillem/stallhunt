//! Bounded multi-resource observation orchestration.
//!
//! Resource collectors retain their own completed-snapshot intervals. The
//! reads are sequential and therefore only share coarse same-window context;
//! no stronger atomicity or causal relationship is implied.
//!
//! Watch reuses an endpoint snapshot as the next window's start so rolling
//! windows stay contiguous and do not double-collect.

use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use crate::cgroup::{self, CgroupError, CgroupObservation, CgroupSnapshot};
use crate::cpu::{self, CpuError, CpuProcessObservation, CpuSnapshot};
use crate::io::{
    self as block_io, DiskstatsError, DiskstatsObservation, DiskstatsSnapshot,
    ProcessIoObservation, ProcessIoSnapshot,
};
use crate::memory::{self, MemoryContextError, MemoryContextObservation, MemoryContextSnapshot};
use crate::psi::{
    self, CpuPsiError, CpuPsiObservation, CpuPsiRaw, IoPsiError, IoPsiObservation, IoPsiRaw,
    MemoryPsiError, MemoryPsiObservation, MemoryPsiRaw,
};

#[derive(Debug, Clone)]
pub struct MemoryHuntObservation {
    pub psi: Result<MemoryPsiObservation, MemoryPsiError>,
    pub context: Result<MemoryContextObservation, MemoryContextError>,
}

#[derive(Debug, Clone)]
pub struct IoHuntObservation {
    pub psi: Result<IoPsiObservation, IoPsiError>,
    pub diskstats: Result<DiskstatsObservation, DiskstatsError>,
    pub processes: Result<ProcessIoObservation, DiskstatsError>,
}
#[derive(Debug, Clone)]
pub struct CgroupHuntObservation {
    pub observation: Result<CgroupObservation, CgroupError>,
}

#[derive(Debug, Clone)]
pub struct HuntObservation {
    pub psi: Result<CpuPsiObservation, CpuPsiError>,
    pub cpu: Result<CpuProcessObservation, CpuError>,
    /// `None` is reserved for injected CPU-only fixtures. Live hunts always
    /// populate the memory observation independently of CPU availability.
    pub memory: Option<MemoryHuntObservation>,
    /// `None` is reserved for injected pre-M3 fixtures. Live hunts always
    /// populate I/O observation independently of other resource availability.
    pub io: Option<IoHuntObservation>,
    /// `None` is reserved for injected pre-M4 fixtures. Live hunts always
    /// collect bounded cgroup-v2 context independently of host resources.
    pub cgroup: Option<CgroupHuntObservation>,
}

/// One completed multi-resource read, timestamped per collector.
///
/// Hunt uses a start-order first endpoint and an end-order second endpoint.
/// Watch reuses the previous end-order endpoint as the next window start.
#[derive(Debug, Clone)]
pub struct HuntEndpoint {
    cpu_psi: Sample<Result<CpuPsiRaw, CpuPsiError>>,
    memory_psi: Sample<Result<MemoryPsiRaw, MemoryPsiError>>,
    io_psi: Sample<Result<IoPsiRaw, IoPsiError>>,
    cpu: Sample<Result<CpuSnapshot, CpuError>>,
    memory: Sample<MemoryContextSnapshot>,
    diskstats: Sample<Result<DiskstatsSnapshot, DiskstatsError>>,
    process_io: Sample<ProcessIoSnapshot>,
    cgroup: Sample<Result<CgroupSnapshot, CgroupError>>,
}

#[derive(Debug, Clone)]
struct Sample<T> {
    value: T,
    at: Instant,
}

pub fn observe_hunt(requested: Duration) -> HuntObservation {
    if requested.is_zero() {
        return empty_interval_observation();
    }

    let start = read_start_endpoint();
    thread::sleep(requested);
    let end = read_end_endpoint();
    observation_from_endpoints(&start, &end, requested)
}

pub fn empty_interval_observation() -> HuntObservation {
    HuntObservation {
        psi: Err(CpuPsiError::EmptyInterval),
        cpu: Err(CpuError::EmptyInterval),
        memory: Some(MemoryHuntObservation {
            psi: Err(MemoryPsiError::EmptyInterval),
            context: Err(MemoryContextError::EmptyInterval),
        }),
        io: Some(IoHuntObservation {
            psi: Err(IoPsiError::EmptyInterval),
            diskstats: Err(DiskstatsError::EmptyInterval),
            processes: Err(DiskstatsError::EmptyInterval),
        }),
        cgroup: Some(CgroupHuntObservation {
            observation: Err(CgroupError::EmptyInterval),
        }),
    }
}

pub fn read_start_endpoint() -> HuntEndpoint {
    let cpu_psi = sample(psi::read_cpu_psi());
    let memory_psi = sample(psi::read_memory_psi());
    let io_psi = sample(psi::read_io_psi());
    let cpu = sample(cpu::read_snapshot(Path::new("/proc")));
    let memory = sample(memory::read_memory_context_snapshot());
    let diskstats = sample(block_io::read_diskstats_at(Path::new("/proc")));
    let process_io = sample(block_io::read_process_io_snapshot_at(Path::new("/proc")));
    let cgroup = sample(cgroup::read_cgroup_snapshot_at(Path::new("/proc")));
    HuntEndpoint {
        cpu_psi,
        memory_psi,
        io_psi,
        cpu,
        memory,
        diskstats,
        process_io,
        cgroup,
    }
}

pub fn read_end_endpoint() -> HuntEndpoint {
    // End-order sandwich is preserved from the original hunt collector so the
    // first watch window matches a hunt of the same requested duration.
    let process_io = sample(block_io::read_process_io_snapshot_at(Path::new("/proc")));
    let diskstats = sample(block_io::read_diskstats_at(Path::new("/proc")));
    let memory = sample(memory::read_memory_context_snapshot());
    let cpu = sample(cpu::read_snapshot(Path::new("/proc")));
    let memory_psi = sample(psi::read_memory_psi());
    let io_psi = sample(psi::read_io_psi());
    let cpu_psi = sample(psi::read_cpu_psi());
    let cgroup = sample(cgroup::read_cgroup_snapshot_at(Path::new("/proc")));
    HuntEndpoint {
        cpu_psi,
        memory_psi,
        io_psi,
        cpu,
        memory,
        diskstats,
        process_io,
        cgroup,
    }
}

pub fn observation_from_endpoints(
    start: &HuntEndpoint,
    end: &HuntEndpoint,
    requested: Duration,
) -> HuntObservation {
    let psi = match (start.cpu_psi.value, end.cpu_psi.value) {
        (Ok(start_raw), Ok(end_raw)) => psi::interval_from_raw(
            start_raw,
            end_raw,
            end.cpu_psi.at.duration_since(start.cpu_psi.at),
        )
        .map(|interval| CpuPsiObservation {
            requested,
            interval,
            start: start_raw,
            end: end_raw,
        }),
        (Err(error), _) | (_, Err(error)) => Err(error),
    };
    let cpu = match (&start.cpu.value, &end.cpu.value) {
        (Ok(start_cpu), Ok(end_cpu)) => cpu::interval_from_snapshots(
            start_cpu.clone(),
            end_cpu.clone(),
            end.cpu.at.duration_since(start.cpu.at),
        ),
        (Err(error), _) | (_, Err(error)) => Err(*error),
    };
    let memory_psi = match (start.memory_psi.value, end.memory_psi.value) {
        (Ok(start_raw), Ok(end_raw)) => psi::memory_interval_from_raw(
            start_raw,
            end_raw,
            end.memory_psi.at.duration_since(start.memory_psi.at),
        )
        .map(|interval| MemoryPsiObservation {
            requested,
            interval,
            start: start_raw,
            end: end_raw,
        }),
        (Err(error), _) | (_, Err(error)) => Err(error),
    };
    let memory_context = memory::interval_from_snapshots(
        start.memory.value.clone(),
        end.memory.value.clone(),
        end.memory.at.duration_since(start.memory.at),
    );
    let io_psi = match (start.io_psi.value, end.io_psi.value) {
        (Ok(start_raw), Ok(end_raw)) => psi::io_interval_from_raw(
            start_raw,
            end_raw,
            end.io_psi.at.duration_since(start.io_psi.at),
        )
        .map(|interval| IoPsiObservation {
            requested,
            interval,
            start: start_raw,
            end: end_raw,
        }),
        (Err(error), _) | (_, Err(error)) => Err(error),
    };
    let diskstats = block_io::diskstats_interval_from_snapshots(
        start.diskstats.value.clone(),
        end.diskstats.value.clone(),
        end.diskstats.at.duration_since(start.diskstats.at),
    );
    let processes = block_io::process_io_interval_from_snapshots(
        start.process_io.value.clone(),
        end.process_io.value.clone(),
        end.process_io.at.duration_since(start.process_io.at),
    );
    let cgroup = match (&start.cgroup.value, &end.cgroup.value) {
        (Ok(start_cgroup), Ok(end_cgroup)) => cgroup::cgroup_interval_from_snapshots(
            start_cgroup.clone(),
            end_cgroup.clone(),
            end.cgroup.at.duration_since(start.cgroup.at),
        ),
        (Err(error), _) | (_, Err(error)) => Err(*error),
    };

    HuntObservation {
        psi,
        cpu,
        memory: Some(MemoryHuntObservation {
            psi: memory_psi,
            context: memory_context,
        }),
        io: Some(IoHuntObservation {
            psi: io_psi,
            diskstats,
            processes,
        }),
        cgroup: Some(CgroupHuntObservation {
            observation: cgroup,
        }),
    }
}

fn sample<T>(value: T) -> Sample<T> {
    Sample {
        value,
        at: Instant::now(),
    }
}
