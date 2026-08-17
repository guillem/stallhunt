//! Bounded multi-resource observation orchestration.
//!
//! Resource collectors retain their own completed-snapshot intervals. The
//! reads are sequential and therefore only share coarse same-window context;
//! no stronger atomicity or causal relationship is implied.

use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use crate::cpu::{self, CpuError, CpuProcessObservation};
use crate::memory::{self, MemoryContextError, MemoryContextObservation};
use crate::psi::{self, CpuPsiError, CpuPsiObservation, MemoryPsiError, MemoryPsiObservation};

#[derive(Debug)]
pub struct MemoryHuntObservation {
    pub psi: Result<MemoryPsiObservation, MemoryPsiError>,
    pub context: Result<MemoryContextObservation, MemoryContextError>,
}

#[derive(Debug)]
pub struct HuntObservation {
    pub psi: Result<CpuPsiObservation, CpuPsiError>,
    pub cpu: Result<CpuProcessObservation, CpuError>,
    /// `None` is reserved for injected CPU-only fixtures. Live hunts always
    /// populate the memory observation independently of CPU availability.
    pub memory: Option<MemoryHuntObservation>,
}

pub fn observe_hunt(requested: Duration) -> HuntObservation {
    if requested.is_zero() {
        return HuntObservation {
            psi: Err(CpuPsiError::EmptyInterval),
            cpu: Err(CpuError::EmptyInterval),
            memory: Some(MemoryHuntObservation {
                psi: Err(MemoryPsiError::EmptyInterval),
                context: Err(MemoryContextError::EmptyInterval),
            }),
        };
    }

    let cpu_psi_start = psi::read_cpu_psi();
    let cpu_psi_started_at = Instant::now();
    let memory_psi_start = psi::read_memory_psi();
    let memory_psi_started_at = Instant::now();
    let cpu_start = cpu::read_snapshot(Path::new("/proc"));
    let cpu_started_at = Instant::now();
    let memory_start = memory::read_memory_context_snapshot();
    let memory_started_at = Instant::now();

    thread::sleep(requested);

    let memory_end = memory::read_memory_context_snapshot();
    let memory_ended_at = Instant::now();
    let cpu_end = cpu::read_snapshot(Path::new("/proc"));
    let cpu_ended_at = Instant::now();
    let memory_psi_end = psi::read_memory_psi();
    let memory_psi_ended_at = Instant::now();
    let cpu_psi_end = psi::read_cpu_psi();
    let cpu_psi_ended_at = Instant::now();

    let psi = match (cpu_psi_start, cpu_psi_end) {
        (Ok(start), Ok(end)) => psi::interval_from_raw(
            start,
            end,
            cpu_psi_ended_at.duration_since(cpu_psi_started_at),
        )
        .map(|interval| CpuPsiObservation {
            requested,
            interval,
            start,
            end,
        }),
        (Err(error), _) | (_, Err(error)) => Err(error),
    };
    let cpu = match (cpu_start, cpu_end) {
        (Ok(start), Ok(end)) => {
            cpu::interval_from_snapshots(start, end, cpu_ended_at.duration_since(cpu_started_at))
        }
        (Err(error), _) | (_, Err(error)) => Err(error),
    };
    let memory_psi = match (memory_psi_start, memory_psi_end) {
        (Ok(start), Ok(end)) => psi::memory_interval_from_raw(
            start,
            end,
            memory_psi_ended_at.duration_since(memory_psi_started_at),
        )
        .map(|interval| MemoryPsiObservation {
            requested,
            interval,
            start,
            end,
        }),
        (Err(error), _) | (_, Err(error)) => Err(error),
    };
    let memory_context = memory::interval_from_snapshots(
        memory_start,
        memory_end,
        memory_ended_at.duration_since(memory_started_at),
    );

    HuntObservation {
        psi,
        cpu,
        memory: Some(MemoryHuntObservation {
            psi: memory_psi,
            context: memory_context,
        }),
    }
}
