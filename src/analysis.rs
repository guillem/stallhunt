//! Conservative inference over normalized observations. This module has no
//! procfs or rendering dependencies so fixtures can exercise it directly.
use std::time::Duration;

use serde::Serialize;

use crate::cgroup::{
    CgroupCpuInterval, CgroupFileState, CgroupIoDevice, CgroupIoRaw, CgroupMemoryEventsRaw,
    CgroupMemoryStatRaw, CgroupObservation, CgroupPsiInterval, CgroupPsiIntervalState,
    CgroupResource,
};
use crate::cpu::{
    self, CpuProcessObservation, ProcessKey, ProcessResourceInterval,
    ProcessSchedulerDelayInterval, SchedstatCapability,
};
use crate::io::{BlockDeviceKey, DiskstatsObservation, IoCapability, ProcessIoObservation};
use crate::memory::{MemoryContextCapability, MemoryContextObservation, VmstatCounter};
use crate::psi::{
    CpuPsiObservation, IoPsiFullInterval, IoPsiObservation, MemoryPsiFullInterval,
    MemoryPsiObservation,
};
use crate::taskstats::{DelayAccountingState, TaskstatsCapability};
use std::collections::{BTreeMap, BTreeSet};

pub const MIN_DIAGNOSIS_WINDOW: Duration = Duration::from_secs(1);
pub const CPU_SEVERITY_THRESHOLDS: [f64; 4] = [0.01, 0.05, 0.15, 0.30];
pub const MEMORY_SEVERITY_THRESHOLDS: [f64; 4] = [0.01, 0.05, 0.15, 0.30];
pub const IO_SEVERITY_THRESHOLDS: [f64; 4] = [0.01, 0.05, 0.15, 0.30];
/// Same-cgroup chains are bounded independently of the 64 displayed cgroup
/// findings. Extra matching paths are dropped after severity-then-path order.
const MAX_CGROUP_EVIDENCE_CHAINS: usize = 16;
/// Provisional lower bound for calling VM churn material enough to support a
/// possible-thrashing heuristic. These counters are pages, not bytes.
const THRASHING_MIN_PAGE_RATE_PER_SEC: u64 = 1_024;
const SUSPECT_MIN_FRACTION: f64 = 0.25;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CgroupResourceKind {
    Cpu,
    Memory,
    Io,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CgroupAssessmentKind {
    NoMeaningfulPressure,
    Pressure,
    InsufficientObservation,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CgroupMechanism {
    Reclaim,
    Swap,
    PossibleThrashing,
    CpuQuotaThrottle,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CgroupEvidence {
    pub psi_some_fraction: Option<f64>,
    pub psi_some_total_delta_us: Option<u64>,
    pub psi_full_fraction: Option<f64>,
    pub psi_full_total_delta_us: Option<u64>,
    pub psi_window_us: u128,
    pub psi_state: CgroupFileState,
    /// Controller values are scoped context only. They do not create the PSI
    /// verdict or establish a causal relationship with another cgroup.
    pub cpu: CgroupResource<CgroupCpuInterval>,
    pub memory_current_end: CgroupResource<u64>,
    pub memory_events: CgroupResource<CgroupMemoryEventsRaw>,
    pub memory_stat: CgroupResource<CgroupMemoryStatRaw>,
    pub io: CgroupResource<BTreeMap<CgroupIoDevice, CgroupIoRaw>>,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CgroupFinding {
    pub path: String,
    pub resource: CgroupResourceKind,
    pub kind: CgroupAssessmentKind,
    pub severity: Severity,
    pub resource_confidence: Confidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mechanism: Option<CgroupMechanism>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mechanism_confidence: Option<Confidence>,
    pub summary: String,
    pub evidence: CgroupEvidence,
    pub systemd_unit_candidate: Option<String>,
    pub members: Vec<CgroupMember>,
    pub qualifiers: Vec<Qualifier>,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CgroupMember {
    pub key: ProcessKey,
    pub name: String,
    pub label: &'static str,
}
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct CgroupAnalysisResult {
    pub findings: Vec<CgroupFinding>,
    pub qualifiers: Vec<Qualifier>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    None,
    Low,
    Moderate,
    High,
    Severe,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

/// Scope-owned, bounded process attribution.  These are candidates, never a
/// proof that one process caused another to stall.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "scope", rename_all = "snake_case")]
pub enum ProcessScopeKind {
    Host,
    #[allow(dead_code)] // constructed by the following cgroup attribution slice
    Cgroup {
        path: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessRole {
    CpuVictim,
    CpuSuspect,
    MemoryVictim,
    MemorySuspect,
    IoVictim,
    IoSuspect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessCandidateAvailability {
    Available,
    UnavailableOrIncomplete,
    NotAssessed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessRoleCompleteness {
    Complete,
    Partial,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProcessCandidateEvidence {
    RunnableDelay {
        runnable_wait_ns: u64,
        runnable_delay_fraction: f64,
        stable_task_count: u32,
        taskstats_cpu_delay_ns: Option<u64>,
    },
    CpuConsumption {
        cpu_fraction_of_one: f64,
        cpu_ticks: u64,
    },
    TaskstatsCpuDelay {
        cpu_delay_ns: u64,
    },
    MemoryDelay {
        largest_component: &'static str,
        largest_delay_ns: u64,
        swapin_delay_ns: Option<u64>,
        reclaim_delay_ns: Option<u64>,
        thrashing_delay_ns: Option<u64>,
        compaction_delay_ns: Option<u64>,
        write_protect_copy_delay_ns: Option<u64>,
    },
    MajorFaults {
        major_faults: u64,
    },
    RssGrowth {
        rss_growth_bytes: u64,
    },
    BlockIoDelay {
        block_io_delay_ns: Option<u64>,
        procfs_block_io_delay_ticks: Option<u64>,
    },
    IoActivity {
        read_bytes: Option<u64>,
        write_bytes: Option<u64>,
        cancelled_write_bytes: Option<u64>,
        known_accounted_bytes: u128,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProcessCandidate {
    pub role: ProcessRole,
    pub key: ProcessKey,
    pub name: String,
    pub confidence: Confidence,
    pub label: &'static str,
    pub evidence: ProcessCandidateEvidence,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProcessRoleList {
    pub role: ProcessRole,
    pub availability: ProcessCandidateAvailability,
    pub completeness: ProcessRoleCompleteness,
    /// Lifecycle retention marks copied role lists stale explicitly; consumers
    /// must not infer freshness from the resource row alone.
    #[serde(default)]
    pub stale: bool,
    pub candidates: Vec<ProcessCandidate>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProcessScope {
    pub scope: ProcessScopeKind,
    pub roles: Vec<ProcessRoleList>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentKind {
    #[serde(rename = "cpu_scheduling_contention")]
    CpuContention,
    CpuNoMeaningfulContention,
    InsufficientObservation,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Resource {
    Cpu,
    Memory,
    Io,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CpuFinding {
    pub resource: Resource,
    pub kind: AssessmentKind,
    pub severity: Severity,
    pub resource_confidence: Confidence,
    pub summary: String,
    pub evidence: CpuEvidence,
    pub victims: Vec<Victim>,
    pub suspects: Vec<Suspect>,
    pub qualifiers: Vec<Qualifier>,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CpuEvidence {
    pub psi_some_fraction: f64,
    pub psi_total_delta_us: u64,
    pub psi_window_us: u128,
    pub host_utilization_fraction: Option<f64>,
    pub logical_cpu_count: Option<u32>,
    pub runnable_tasks: Option<u64>,
    pub loadavg1: Option<f64>,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Victim {
    pub key: ProcessKey,
    pub name: String,
    pub runnable_wait_ns: u64,
    pub runnable_delay_fraction: f64,
    pub stable_task_count: u32,
    pub confidence: Confidence,
    pub label: &'static str,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Suspect {
    pub key: ProcessKey,
    pub name: String,
    pub cpu_fraction_of_one: f64,
    pub cpu_ticks: u64,
    pub confidence: Confidence,
    pub label: &'static str,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Qualifier {
    pub kind: &'static str,
    pub message: &'static str,
}
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct AnalysisResult {
    pub findings: Vec<CpuFinding>,
    pub qualifiers: Vec<Qualifier>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum MemoryAssessmentKind {
    #[serde(rename = "memory_no_harmful_pressure")]
    NoHarmfulPressure,
    #[serde(rename = "memory_pressure")]
    Pressure,
    #[serde(rename = "memory_reclaim_pressure")]
    ReclaimPressure,
    #[serde(rename = "memory_swap_pressure")]
    SwapPressure,
    #[serde(rename = "memory_possible_thrashing")]
    PossibleThrashing,
    #[serde(rename = "memory_insufficient_observation")]
    InsufficientObservation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryFullEvidenceState {
    Available,
    Missing,
    CounterRegressed,
    DeltaExceedsElapsed,
    ExceedsSome,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MemoryEvidence {
    pub psi_some_fraction: f64,
    pub psi_some_total_delta_us: u64,
    pub psi_full_fraction: Option<f64>,
    pub psi_full_total_delta_us: Option<u64>,
    pub psi_full_state: MemoryFullEvidenceState,
    pub psi_window_us: u128,
    /// Exact interval for the independently sampled meminfo/vmstat context.
    pub memory_context_window_us: Option<u128>,
    pub memory_total_bytes: Option<u64>,
    pub memory_available_bytes: Option<u64>,
    pub memory_occupancy_fraction: Option<f64>,
    pub swap_total_bytes: Option<u64>,
    pub swap_free_bytes: Option<u64>,
    pub swap_used_bytes: Option<u64>,
    pub page_faults: Option<u64>,
    pub major_page_faults: Option<u64>,
    pub swap_in_pages: Option<u64>,
    pub swap_out_pages: Option<u64>,
    pub scan_kswapd_pages: Option<u64>,
    pub scan_direct_pages: Option<u64>,
    pub steal_kswapd_pages: Option<u64>,
    pub steal_direct_pages: Option<u64>,
    pub meminfo_capability: Option<MemoryContextCapability>,
    pub vmstat_capability: Option<MemoryContextCapability>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MemoryFinding {
    pub resource: Resource,
    pub kind: MemoryAssessmentKind,
    pub severity: Severity,
    /// Confidence in the PSI-backed pressure verdict.
    pub resource_confidence: Confidence,
    /// Confidence in a VM-counter-backed mechanism label. Host-wide counters
    /// are same-window correlation, so this is intentionally never high.
    pub mechanism_confidence: Option<Confidence>,
    pub summary: String,
    pub evidence: MemoryEvidence,
    pub qualifiers: Vec<Qualifier>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct MemoryAnalysisResult {
    pub findings: Vec<MemoryFinding>,
    pub qualifiers: Vec<Qualifier>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Finding {
    Cpu(CpuFinding),
    Memory(MemoryFinding),
    Io(IoFinding),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainKind {
    MemoryMechanismConsistentWithIo,
    CgroupMemoryConsistentWithIo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainRelation {
    ConsistentWith,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "resource", rename_all = "snake_case")]
pub enum ChainEndpoint {
    Memory {
        kind: MemoryAssessmentKind,
    },
    Io {
        kind: IoAssessmentKind,
    },
    CgroupMemory {
        path: String,
        kind: CgroupAssessmentKind,
    },
    CgroupIo {
        path: String,
        kind: CgroupAssessmentKind,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ChainEvidence {
    pub memory_psi_some_fraction: f64,
    pub io_psi_some_fraction: f64,
    pub swap_in_pages: Option<u64>,
    pub swap_out_pages: Option<u64>,
    pub scan_direct_pages: Option<u64>,
    pub steal_direct_pages: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub high_events: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_events: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EvidenceChain {
    pub kind: ChainKind,
    pub relation: ChainRelation,
    pub confidence: Confidence,
    pub summary: String,
    pub from: ChainEndpoint,
    pub to: ChainEndpoint,
    pub evidence: ChainEvidence,
    pub qualifiers: Vec<Qualifier>,
}

/// Relates already-produced findings only when independent evidence supports a
/// path. Coincident PSI without a memory mechanism is not a chain. Host and
/// cgroup findings are never linked to each other, and a chain never claims
/// that one resource caused the other.
pub fn analyze_evidence_chains(
    memory: Option<&MemoryFinding>,
    io: Option<&IoFinding>,
    cgroup_findings: &[CgroupFinding],
) -> Vec<EvidenceChain> {
    let mut chains = analyze_host_memory_io_chain(memory, io);
    chains.extend(analyze_cgroup_memory_io_chains(cgroup_findings));
    chains
}

fn analyze_host_memory_io_chain(
    memory: Option<&MemoryFinding>,
    io: Option<&IoFinding>,
) -> Vec<EvidenceChain> {
    let Some(memory) = memory else {
        return Vec::new();
    };
    let Some(io) = io else {
        return Vec::new();
    };
    if io.kind != IoAssessmentKind::Pressure {
        return Vec::new();
    }
    let (confidence, summary) = match memory.kind {
        MemoryAssessmentKind::ReclaimPressure => (
            Confidence::Low,
            "Memory reclaim pressure is consistent with block-I/O pressure in the same window.",
        ),
        MemoryAssessmentKind::SwapPressure => (
            Confidence::Low,
            "Memory swap pressure is consistent with block-I/O pressure in the same window.",
        ),
        MemoryAssessmentKind::PossibleThrashing => (
            Confidence::Medium,
            "Possible thrashing is consistent with block-I/O pressure in the same window.",
        ),
        MemoryAssessmentKind::NoHarmfulPressure
        | MemoryAssessmentKind::Pressure
        | MemoryAssessmentKind::InsufficientObservation => return Vec::new(),
    };
    vec![EvidenceChain {
        kind: ChainKind::MemoryMechanismConsistentWithIo,
        relation: ChainRelation::ConsistentWith,
        confidence,
        summary: summary.into(),
        from: ChainEndpoint::Memory { kind: memory.kind },
        to: ChainEndpoint::Io { kind: io.kind },
        evidence: ChainEvidence {
            memory_psi_some_fraction: memory.evidence.psi_some_fraction,
            io_psi_some_fraction: io.evidence.psi_some_fraction,
            swap_in_pages: memory.evidence.swap_in_pages,
            swap_out_pages: memory.evidence.swap_out_pages,
            scan_direct_pages: memory.evidence.scan_direct_pages,
            steal_direct_pages: memory.evidence.steal_direct_pages,
            path: None,
            high_events: None,
            max_events: None,
        },
        qualifiers: vec![
            Qualifier {
                kind: "chain_not_causal",
                message: "Independent same-window PSI and VM-counter evidence can support a related path; it does not prove that memory reclaim or swap caused the I/O stalls.",
            },
            Qualifier {
                kind: "no_process_device_mapping",
                message: "The chain does not map processes to devices or identify which I/O was reclaim or swap traffic.",
            },
        ],
    }]
}

fn analyze_cgroup_memory_io_chains(findings: &[CgroupFinding]) -> Vec<EvidenceChain> {
    let mut memory_by_path = BTreeMap::new();
    let mut io_by_path = BTreeMap::new();
    for finding in findings {
        if finding.kind != CgroupAssessmentKind::Pressure {
            continue;
        }
        match finding.resource {
            CgroupResourceKind::Memory => {
                memory_by_path.insert(finding.path.as_str(), finding);
            }
            CgroupResourceKind::Io => {
                io_by_path.insert(finding.path.as_str(), finding);
            }
            CgroupResourceKind::Cpu => {}
        }
    }
    let mut candidates = Vec::new();
    for (path, memory) in &memory_by_path {
        let Some(io) = io_by_path.get(path) else {
            continue;
        };
        if let Some(chain) = cgroup_memory_io_chain(memory, io) {
            candidates.push(chain);
        }
    }
    candidates.sort_by(|left, right| {
        cgroup_chain_rank(right)
            .cmp(&cgroup_chain_rank(left))
            .then_with(|| left.evidence.path.cmp(&right.evidence.path))
    });
    candidates.truncate(MAX_CGROUP_EVIDENCE_CHAINS);
    candidates
}

fn cgroup_chain_rank(chain: &EvidenceChain) -> (u8, u8) {
    (
        psi_fraction_rank(chain.evidence.memory_psi_some_fraction)
            .max(psi_fraction_rank(chain.evidence.io_psi_some_fraction)),
        confidence_rank(chain.confidence),
    )
}

fn psi_fraction_rank(fraction: f64) -> u8 {
    severity_rank(severity_for_psi(fraction))
}

fn cgroup_memory_io_chain(memory: &CgroupFinding, io: &CgroupFinding) -> Option<EvidenceChain> {
    if memory.path != io.path {
        return None;
    }
    let events = memory.evidence.memory_events.value.as_ref();
    let high_events = events
        .and_then(|events| events.high)
        .filter(|value| *value > 0);
    let max_events = events
        .and_then(|events| events.max)
        .filter(|value| *value > 0);
    let stat = memory.evidence.memory_stat.value.as_ref();
    let scan_direct_pages = stat
        .and_then(|stat| stat.pgscan_direct)
        .filter(|value| *value > 0);
    let steal_direct_pages = stat
        .and_then(|stat| stat.pgsteal_direct)
        .filter(|value| *value > 0);
    let swap_in_pages = stat.and_then(|stat| stat.pswpin).filter(|value| *value > 0);
    let swap_out_pages = stat
        .and_then(|stat| stat.pswpout)
        .filter(|value| *value > 0);
    let limit_reclaim = high_events.is_some() || max_events.is_some();
    let direct_reclaim = scan_direct_pages.is_some() && steal_direct_pages.is_some();
    if !limit_reclaim && !direct_reclaim && swap_in_pages.is_none() {
        return None;
    }
    let memory_psi_some_fraction = memory.evidence.psi_some_fraction?;
    let io_psi_some_fraction = io.evidence.psi_some_fraction?;
    Some(EvidenceChain {
        kind: ChainKind::CgroupMemoryConsistentWithIo,
        relation: ChainRelation::ConsistentWith,
        confidence: Confidence::Low,
        summary: format!(
            "Scoped memory pressure in {} is consistent with scoped I/O pressure in the same cgroup.",
            memory.path
        ),
        from: ChainEndpoint::CgroupMemory {
            path: memory.path.clone(),
            kind: memory.kind,
        },
        to: ChainEndpoint::CgroupIo {
            path: io.path.clone(),
            kind: io.kind,
        },
        evidence: ChainEvidence {
            memory_psi_some_fraction,
            io_psi_some_fraction,
            swap_in_pages,
            swap_out_pages,
            scan_direct_pages,
            steal_direct_pages,
            path: Some(memory.path.clone()),
            high_events,
            max_events,
        },
        qualifiers: vec![
            Qualifier {
                kind: "chain_not_causal",
                message: "Independent same-cgroup PSI plus memory.events or memory.stat evidence can support a related path; it does not prove that memory reclaim in this cgroup caused its I/O stalls.",
            },
            Qualifier {
                kind: "same_cgroup_scope_only",
                message: "The relation is limited to one cgroup path. It does not link host findings to cgroup findings or one cgroup to another, including ancestors and children.",
            },
            Qualifier {
                kind: "cgroup_memory_mechanism_scoped",
                message: "memory.events high/max and memory.stat direct-reclaim or swap-in deltas are cgroup-scoped signals, not host vmstat proof, and may include descendant activity.",
            },
            Qualifier {
                kind: "no_process_device_mapping",
                message: "The chain does not map processes to devices or identify which I/O was reclaim or swap traffic.",
            },
        ],
    })
}

/// Combines all currently normalized resource findings.
pub fn ranked_findings_with_io(
    cpu: AnalysisResult,
    memory: MemoryAnalysisResult,
    io: IoAnalysisResult,
) -> Vec<Finding> {
    let mut findings =
        Vec::with_capacity(cpu.findings.len() + memory.findings.len() + io.findings.len());
    findings.extend(cpu.findings.into_iter().map(Finding::Cpu));
    findings.extend(memory.findings.into_iter().map(Finding::Memory));
    findings.extend(io.findings.into_iter().map(Finding::Io));
    findings.sort_by(|left, right| {
        finding_rank(right)
            .cmp(&finding_rank(left))
            .then_with(|| finding_resource_rank(left).cmp(&finding_resource_rank(right)))
    });
    findings
}

fn finding_rank(finding: &Finding) -> (u8, u8) {
    let (severity, confidence) = match finding {
        Finding::Cpu(finding) => (finding.severity, finding.resource_confidence),
        Finding::Memory(finding) => (finding.severity, finding.resource_confidence),
        Finding::Io(finding) => (finding.severity, finding.resource_confidence),
    };
    (severity_rank(severity), confidence_rank(confidence))
}

fn finding_resource_rank(finding: &Finding) -> u8 {
    match finding {
        Finding::Cpu(_) => 0,
        Finding::Memory(_) => 1,
        Finding::Io(_) => 2,
    }
}

const fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::None => 0,
        Severity::Low => 1,
        Severity::Moderate => 2,
        Severity::High => 3,
        Severity::Severe => 4,
    }
}

const fn confidence_rank(confidence: Confidence) -> u8 {
    match confidence {
        Confidence::Low => 0,
        Confidence::Medium => 1,
        Confidence::High => 2,
    }
}

pub fn severity_for_psi(some_fraction: f64) -> Severity {
    if some_fraction < CPU_SEVERITY_THRESHOLDS[0] {
        Severity::None
    } else if some_fraction < CPU_SEVERITY_THRESHOLDS[1] {
        Severity::Low
    } else if some_fraction < CPU_SEVERITY_THRESHOLDS[2] {
        Severity::Moderate
    } else if some_fraction < CPU_SEVERITY_THRESHOLDS[3] {
        Severity::High
    } else {
        Severity::Severe
    }
}

pub fn severity_for_memory_psi(some_fraction: f64) -> Severity {
    if some_fraction < MEMORY_SEVERITY_THRESHOLDS[0] {
        Severity::None
    } else if some_fraction < MEMORY_SEVERITY_THRESHOLDS[1] {
        Severity::Low
    } else if some_fraction < MEMORY_SEVERITY_THRESHOLDS[2] {
        Severity::Moderate
    } else if some_fraction < MEMORY_SEVERITY_THRESHOLDS[3] {
        Severity::High
    } else {
        Severity::Severe
    }
}

pub fn analyze_memory(
    psi: Option<&MemoryPsiObservation>,
    context: Option<&MemoryContextObservation>,
) -> MemoryAnalysisResult {
    let Some(psi) = psi else {
        return MemoryAnalysisResult {
            findings: vec![],
            qualifiers: vec![Qualifier {
                kind: "memory_assessment_unavailable",
                message: "Memory PSI is unavailable, so no memory pressure assessment was produced.",
            }],
        };
    };
    let effective_window = psi.requested.min(psi.interval.elapsed);
    if effective_window < MIN_DIAGNOSIS_WINDOW {
        return MemoryAnalysisResult {
            findings: vec![MemoryFinding {
                resource: Resource::Memory,
                kind: MemoryAssessmentKind::InsufficientObservation,
                severity: Severity::None,
                resource_confidence: Confidence::Low,
                mechanism_confidence: None,
                summary: "Memory observation is shorter than 1s; no healthy or pressure conclusion was made.".into(),
                evidence: memory_evidence(psi, context),
                qualifiers: vec![
                    Qualifier {
                        kind: "insufficient_observation",
                        message: "A requested and measured memory PSI interval of at least 1s is required for a diagnosis.",
                    },
                    no_memory_attribution_qualifier(),
                ],
            }],
            qualifiers: vec![],
        };
    }

    let severity = severity_for_memory_psi(psi.interval.some.fraction);
    let resource_confidence = if psi.requested >= Duration::from_secs(5)
        && psi.interval.elapsed >= Duration::from_secs(5)
    {
        Confidence::High
    } else {
        Confidence::Medium
    };
    let evidence = memory_evidence(psi, context);
    let mut qualifiers = memory_qualifiers(&evidence, context);
    let direct_reclaim = evidence.scan_direct_pages.is_some_and(|value| value > 0)
        && evidence.steal_direct_pages.is_some_and(|value| value > 0);
    let swap_in = evidence.swap_in_pages.is_some_and(|value| value > 0);
    let full_fraction = evidence.psi_full_fraction.unwrap_or(0.0);
    let material_thrashing_churn = context.is_some_and(|context| {
        !context.elapsed.is_zero()
            && page_rate_at_least(
                evidence.scan_direct_pages,
                context.elapsed,
                THRASHING_MIN_PAGE_RATE_PER_SEC,
            )
            && page_rate_at_least(
                evidence.steal_direct_pages,
                context.elapsed,
                THRASHING_MIN_PAGE_RATE_PER_SEC,
            )
            && page_rate_at_least(
                evidence.swap_in_pages,
                context.elapsed,
                THRASHING_MIN_PAGE_RATE_PER_SEC,
            )
            && page_rate_at_least(
                evidence.swap_out_pages,
                context.elapsed,
                THRASHING_MIN_PAGE_RATE_PER_SEC,
            )
    });
    let kind = if severity == Severity::None {
        MemoryAssessmentKind::NoHarmfulPressure
    } else if matches!(severity, Severity::High | Severity::Severe)
        && effective_window >= Duration::from_secs(5)
        && full_fraction >= 0.01
        && material_thrashing_churn
    {
        MemoryAssessmentKind::PossibleThrashing
    } else if swap_in {
        MemoryAssessmentKind::SwapPressure
    } else if direct_reclaim {
        MemoryAssessmentKind::ReclaimPressure
    } else {
        MemoryAssessmentKind::Pressure
    };
    let mechanism_confidence = match kind {
        MemoryAssessmentKind::ReclaimPressure | MemoryAssessmentKind::SwapPressure => {
            Some(Confidence::Low)
        }
        MemoryAssessmentKind::PossibleThrashing => Some(Confidence::Medium),
        _ => None,
    };

    if mechanism_confidence.is_some() {
        qualifiers.push(Qualifier {
            kind: "memory_mechanism_same_window_correlation",
            message: "Host-wide VM counter changes occurred in the same window as PSI pressure; they support the mechanism label but do not prove causality.",
        });
    }
    if kind == MemoryAssessmentKind::PossibleThrashing {
        qualifiers.push(Qualifier {
            kind: "possible_thrashing_heuristic",
            message: "Possible thrashing requires sustained high `some`, non-trivial `full`, and material direct-reclaim plus bidirectional swap churn; it remains a heuristic.",
        });
    }

    if severity == Severity::None {
        qualifiers.push(Qualifier {
            kind: "memory_no_harmful_pressure",
            message: "No harmful memory pressure was observed from exact-interval memory PSI; occupancy and VM counters do not override that verdict.",
        });
    }
    let summary = match kind {
        MemoryAssessmentKind::NoHarmfulPressure
            if evidence
                .memory_occupancy_fraction
                .is_some_and(|fraction| fraction >= 0.90) =>
        {
            "No harmful memory pressure observed despite high memory occupancy.".into()
        }
        MemoryAssessmentKind::NoHarmfulPressure => "No harmful memory pressure observed.".into(),
        MemoryAssessmentKind::Pressure => format!(
            "Active memory pressure observed ({:.2}% memory PSI some); the mechanism is not established.",
            evidence.psi_some_fraction * 100.0
        ),
        MemoryAssessmentKind::ReclaimPressure => format!(
            "Memory pressure observed with correlated direct reclaim activity ({:.2}% memory PSI some).",
            evidence.psi_some_fraction * 100.0
        ),
        MemoryAssessmentKind::SwapPressure => format!(
            "Memory pressure observed with correlated swap-in activity ({:.2}% memory PSI some).",
            evidence.psi_some_fraction * 100.0
        ),
        MemoryAssessmentKind::PossibleThrashing => format!(
            "Memory evidence is consistent with possible thrashing ({:.2}% some, {:.2}% full PSI).",
            evidence.psi_some_fraction * 100.0,
            full_fraction * 100.0
        ),
        MemoryAssessmentKind::InsufficientObservation => unreachable!(),
    };
    MemoryAnalysisResult {
        findings: vec![MemoryFinding {
            resource: Resource::Memory,
            kind,
            severity,
            resource_confidence,
            mechanism_confidence,
            summary,
            evidence,
            qualifiers,
        }],
        qualifiers: vec![],
    }
}

fn page_rate_at_least(pages: Option<u64>, elapsed: Duration, minimum_per_second: u64) -> bool {
    let elapsed_nanos = elapsed.as_nanos();
    elapsed_nanos != 0
        && pages.is_some_and(|pages| {
            u128::from(pages) * 1_000_000_000 >= u128::from(minimum_per_second) * elapsed_nanos
        })
}

fn memory_evidence(
    psi: &MemoryPsiObservation,
    context: Option<&MemoryContextObservation>,
) -> MemoryEvidence {
    let (full_state, full_fraction, full_total_delta_us) = match psi.interval.full {
        MemoryPsiFullInterval::Available(interval) => (
            MemoryFullEvidenceState::Available,
            Some(interval.fraction),
            Some(interval.total_delta_us),
        ),
        MemoryPsiFullInterval::Missing => (MemoryFullEvidenceState::Missing, None, None),
        MemoryPsiFullInterval::CounterRegressed => {
            (MemoryFullEvidenceState::CounterRegressed, None, None)
        }
        MemoryPsiFullInterval::DeltaExceedsElapsed => {
            (MemoryFullEvidenceState::DeltaExceedsElapsed, None, None)
        }
        MemoryPsiFullInterval::ExceedsSome => (MemoryFullEvidenceState::ExceedsSome, None, None),
    };
    let meminfo = context.and_then(|context| context.end_meminfo.as_ref());
    let memory_occupancy_fraction = meminfo.and_then(|meminfo| {
        (meminfo.mem_total_bytes > 0)
            .then(|| 1.0 - meminfo.mem_available_bytes as f64 / meminfo.mem_total_bytes as f64)
    });
    let delta = |counter| context.and_then(|context| context.vmstat_deltas.get(&counter).copied());
    MemoryEvidence {
        psi_some_fraction: psi.interval.some.fraction,
        psi_some_total_delta_us: psi.interval.some.total_delta_us,
        psi_full_fraction: full_fraction,
        psi_full_total_delta_us: full_total_delta_us,
        psi_full_state: full_state,
        psi_window_us: psi.interval.elapsed.as_micros(),
        memory_context_window_us: context.map(|context| context.elapsed.as_micros()),
        memory_total_bytes: meminfo.map(|meminfo| meminfo.mem_total_bytes),
        memory_available_bytes: meminfo.map(|meminfo| meminfo.mem_available_bytes),
        memory_occupancy_fraction,
        swap_total_bytes: meminfo.map(|meminfo| meminfo.swap_total_bytes),
        swap_free_bytes: meminfo.map(|meminfo| meminfo.swap_free_bytes),
        swap_used_bytes: meminfo.and_then(|meminfo| {
            meminfo
                .swap_total_bytes
                .checked_sub(meminfo.swap_free_bytes)
        }),
        page_faults: delta(VmstatCounter::PageFaults),
        major_page_faults: delta(VmstatCounter::MajorPageFaults),
        swap_in_pages: delta(VmstatCounter::SwapIn),
        swap_out_pages: delta(VmstatCounter::SwapOut),
        scan_kswapd_pages: delta(VmstatCounter::ScanKswapd),
        scan_direct_pages: delta(VmstatCounter::ScanDirect),
        steal_kswapd_pages: delta(VmstatCounter::StealKswapd),
        steal_direct_pages: delta(VmstatCounter::StealDirect),
        meminfo_capability: context.map(|context| context.meminfo_capability),
        vmstat_capability: context.map(|context| context.vmstat_capability),
    }
}

fn memory_qualifiers(
    evidence: &MemoryEvidence,
    context: Option<&MemoryContextObservation>,
) -> Vec<Qualifier> {
    let mut qualifiers = vec![no_memory_attribution_qualifier()];
    match evidence.psi_full_state {
        MemoryFullEvidenceState::Available => {}
        MemoryFullEvidenceState::Missing => qualifiers.push(Qualifier {
            kind: "memory_full_unavailable",
            message: "Memory PSI `full` is unavailable; the valid `some` interval still determines the resource verdict.",
        }),
        _ => qualifiers.push(Qualifier {
            kind: "memory_full_interval_invalid",
            message: "Memory PSI `full` was inconsistent; it was excluded while valid `some` evidence was retained.",
        }),
    }
    match context {
        None => qualifiers.push(Qualifier {
            kind: "memory_context_unavailable",
            message: "Meminfo and VM counter context is unavailable; memory PSI alone determines the resource verdict.",
        }),
        Some(context) => {
            if context.meminfo_capability != MemoryContextCapability::Available {
                qualifiers.push(Qualifier {
                    kind: "memory_context_partial",
                    message: "Meminfo context is unavailable or partial; occupancy and swap-allocation context may be incomplete.",
                });
            }
            if context.vmstat_capability != MemoryContextCapability::Available {
                qualifiers.push(Qualifier {
                    kind: "vmstat_partial",
                    message: "VM counter context is unavailable or partial; the pressure mechanism may be unclassified.",
                });
            }
        }
    }
    if evidence
        .memory_occupancy_fraction
        .is_some_and(|fraction| fraction >= 0.90)
    {
        qualifiers.push(Qualifier {
            kind: "high_occupancy_context",
            message: "Memory occupancy was at least 90%; occupancy is context and is not itself evidence of harmful pressure.",
        });
    }
    if evidence.swap_used_bytes.is_some_and(|bytes| bytes > 0) {
        qualifiers.push(Qualifier {
            kind: "swap_allocated_context",
            message: "Swap space was allocated; allocation may be historical and does not establish active swap pressure.",
        });
    }
    if evidence
        .scan_kswapd_pages
        .zip(evidence.steal_kswapd_pages)
        .is_some_and(|(scanned, stolen)| scanned > 0 || stolen > 0)
    {
        qualifiers.push(Qualifier {
            kind: "kswapd_reclaim_context",
            message: "Background reclaim activity was observed; it is supporting context, not proof of synchronous allocation delay.",
        });
    }
    if evidence.swap_out_pages.is_some_and(|pages| pages > 0)
        && !evidence.swap_in_pages.is_some_and(|pages| pages > 0)
    {
        qualifiers.push(Qualifier {
            kind: "swap_out_context",
            message: "Swap-out activity was observed without swap-in; it does not by itself establish active swap pressure.",
        });
    }
    qualifiers
}

const fn no_memory_attribution_qualifier() -> Qualifier {
    Qualifier {
        kind: "no_process_attribution",
        message: "Memory evidence is host-wide; this slice does not identify affected or contributing processes.",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IoAssessmentKind {
    #[serde(rename = "io_no_meaningful_contention")]
    NoMeaningfulContention,
    #[serde(rename = "io_pressure")]
    Pressure,
    #[serde(rename = "io_insufficient_observation")]
    InsufficientObservation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IoFullEvidenceState {
    Available,
    Missing,
    CounterRegressed,
    DeltaExceedsElapsed,
    ExceedsSome,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct IoEvidence {
    pub psi_some_fraction: f64,
    pub psi_some_total_delta_us: u64,
    pub psi_full_fraction: Option<f64>,
    pub psi_full_total_delta_us: Option<u64>,
    pub psi_full_state: IoFullEvidenceState,
    pub psi_window_us: u128,
    pub diskstats_window_us: Option<u128>,
    pub diskstats_capability: Option<IoCapability>,
    pub process_io_window_us: Option<u128>,
    pub process_io_capability: Option<IoCapability>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct IoDeviceCandidate {
    pub key: BlockDeviceKey,
    pub name: String,
    pub read_sectors_512: Option<u64>,
    pub write_sectors_512: Option<u64>,
    pub reads_completed: Option<u64>,
    pub writes_completed: Option<u64>,
    pub io_ticks_ms: Option<u64>,
    pub weighted_io_ticks_ms: Option<u64>,
    pub end_in_flight: u64,
    pub confidence: Confidence,
    pub label: &'static str,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct IoProcessSuspect {
    pub key: ProcessKey,
    pub name: String,
    pub read_bytes: Option<u64>,
    /// Write bytes charged when pages were dirtied, not confirmed writeout.
    pub write_bytes: Option<u64>,
    pub cancelled_write_bytes: Option<u64>,
    /// Sum of independently valid read and charged-write deltas. Cancellation
    /// remains separate because it can apply to another task's dirty pages.
    pub known_accounted_bytes: u128,
    pub confidence: Confidence,
    pub label: &'static str,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct IoFinding {
    pub resource: Resource,
    pub kind: IoAssessmentKind,
    pub severity: Severity,
    pub resource_confidence: Confidence,
    pub summary: String,
    pub evidence: IoEvidence,
    pub device_candidates: Vec<IoDeviceCandidate>,
    pub process_suspects: Vec<IoProcessSuspect>,
    pub qualifiers: Vec<Qualifier>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct IoAnalysisResult {
    pub findings: Vec<IoFinding>,
    pub qualifiers: Vec<Qualifier>,
}

pub fn severity_for_io_psi(some_fraction: f64) -> Severity {
    if some_fraction < IO_SEVERITY_THRESHOLDS[0] {
        Severity::None
    } else if some_fraction < IO_SEVERITY_THRESHOLDS[1] {
        Severity::Low
    } else if some_fraction < IO_SEVERITY_THRESHOLDS[2] {
        Severity::Moderate
    } else if some_fraction < IO_SEVERITY_THRESHOLDS[3] {
        Severity::High
    } else {
        Severity::Severe
    }
}

/// Derives a host-wide block-I/O pressure finding. Exact-interval I/O PSI
/// `some` alone decides pressure; diskstats and `/proc/<pid>/io` only provide
/// same-window activity context and intentionally do not identify victims,
/// backing devices, or a causal process-to-device path.
pub fn analyze_io(
    psi: Option<&IoPsiObservation>,
    diskstats: Option<&DiskstatsObservation>,
    process_io: Option<&ProcessIoObservation>,
) -> IoAnalysisResult {
    let Some(psi) = psi else {
        return IoAnalysisResult {
            findings: vec![],
            qualifiers: vec![Qualifier {
                kind: "io_assessment_unavailable",
                message: "I/O PSI is unavailable, so no block-I/O pressure assessment was produced.",
            }],
        };
    };
    let evidence = io_evidence(psi, diskstats, process_io);
    let effective_window = psi.requested.min(psi.interval.elapsed);
    if effective_window < MIN_DIAGNOSIS_WINDOW {
        return IoAnalysisResult {
            findings: vec![IoFinding {
                resource: Resource::Io,
                kind: IoAssessmentKind::InsufficientObservation,
                severity: Severity::None,
                resource_confidence: Confidence::Low,
                summary: "Block-I/O observation is shorter than 1s; no healthy or pressure conclusion was made.".into(),
                evidence,
                device_candidates: vec![],
                process_suspects: vec![],
                qualifiers: vec![
                    Qualifier { kind: "insufficient_observation", message: "A requested and measured I/O PSI interval of at least 1s is required for a diagnosis." },
                    no_io_victim_attribution_qualifier(),
                ],
            }],
            qualifiers: vec![],
        };
    }

    let severity = severity_for_io_psi(psi.interval.some.fraction);
    let pressure = severity != Severity::None;
    let resource_confidence = if psi.requested >= Duration::from_secs(5)
        && psi.interval.elapsed >= Duration::from_secs(5)
    {
        Confidence::High
    } else {
        Confidence::Medium
    };
    let mut qualifiers = io_qualifiers(&evidence, diskstats, process_io);
    let device_candidates = if pressure {
        io_device_candidates(diskstats, &mut qualifiers)
    } else {
        vec![]
    };
    let process_suspects = if pressure {
        io_process_suspects(process_io, &mut qualifiers)
    } else {
        vec![]
    };
    if !pressure {
        qualifiers.push(Qualifier {
            kind: "io_no_meaningful_contention",
            message: "No meaningful block-I/O pressure was observed from exact-interval I/O PSI; activity counters do not override that verdict.",
        });
    }
    let summary = if pressure {
        format!(
            "Block-I/O pressure observed ({:.2}% I/O PSI some).",
            evidence.psi_some_fraction * 100.0
        )
    } else {
        "No meaningful block-I/O pressure observed.".into()
    };
    IoAnalysisResult {
        findings: vec![IoFinding {
            resource: Resource::Io,
            kind: if pressure {
                IoAssessmentKind::Pressure
            } else {
                IoAssessmentKind::NoMeaningfulContention
            },
            severity,
            resource_confidence,
            summary,
            evidence,
            device_candidates,
            process_suspects,
            qualifiers,
        }],
        qualifiers: vec![],
    }
}

fn io_evidence(
    psi: &IoPsiObservation,
    diskstats: Option<&DiskstatsObservation>,
    process_io: Option<&ProcessIoObservation>,
) -> IoEvidence {
    let (psi_full_state, psi_full_fraction, psi_full_total_delta_us) = match psi.interval.full {
        IoPsiFullInterval::Available(interval) => (
            IoFullEvidenceState::Available,
            Some(interval.fraction),
            Some(interval.total_delta_us),
        ),
        IoPsiFullInterval::Missing => (IoFullEvidenceState::Missing, None, None),
        IoPsiFullInterval::CounterRegressed => (IoFullEvidenceState::CounterRegressed, None, None),
        IoPsiFullInterval::DeltaExceedsElapsed => {
            (IoFullEvidenceState::DeltaExceedsElapsed, None, None)
        }
        IoPsiFullInterval::ExceedsSome => (IoFullEvidenceState::ExceedsSome, None, None),
    };
    IoEvidence {
        psi_some_fraction: psi.interval.some.fraction,
        psi_some_total_delta_us: psi.interval.some.total_delta_us,
        psi_full_fraction,
        psi_full_total_delta_us,
        psi_full_state,
        psi_window_us: psi.interval.elapsed.as_micros(),
        diskstats_window_us: diskstats.map(|observation| observation.elapsed.as_micros()),
        diskstats_capability: diskstats.map(|observation| observation.capability),
        process_io_window_us: process_io.map(|observation| observation.elapsed.as_micros()),
        process_io_capability: process_io.map(|observation| observation.capability),
    }
}

fn io_device_candidates(
    diskstats: Option<&DiskstatsObservation>,
    qualifiers: &mut Vec<Qualifier>,
) -> Vec<IoDeviceCandidate> {
    let Some(diskstats) = diskstats else {
        return vec![];
    };
    let confidence = if diskstats.capability == IoCapability::Available {
        Confidence::Medium
    } else {
        Confidence::Low
    };
    let mut candidates: Vec<_> = diskstats
        .devices
        .iter()
        .filter(|device| {
            device.sectors_read_512.is_some_and(|value| value > 0)
                || device.sectors_written_512.is_some_and(|value| value > 0)
                || device.reads_completed.is_some_and(|value| value > 0)
                || device.writes_completed.is_some_and(|value| value > 0)
                || device.io_ticks_ms.is_some_and(|value| value > 0)
                || device.weighted_io_ticks_ms.is_some_and(|value| value > 0)
                || device.end_in_flight > 0
        })
        .map(|device| IoDeviceCandidate {
            key: device.key,
            name: device.name.clone(),
            read_sectors_512: device.sectors_read_512,
            write_sectors_512: device.sectors_written_512,
            reads_completed: device.reads_completed,
            writes_completed: device.writes_completed,
            io_ticks_ms: device.io_ticks_ms,
            weighted_io_ticks_ms: device.weighted_io_ticks_ms,
            end_in_flight: device.end_in_flight,
            confidence,
            label: "same_window_block_device_activity",
        })
        .collect();
    candidates.sort_by(|left, right| {
        let left_busy = left.io_ticks_ms.unwrap_or(0);
        let right_busy = right.io_ticks_ms.unwrap_or(0);
        let left_weighted = left.weighted_io_ticks_ms.unwrap_or(0);
        let right_weighted = right.weighted_io_ticks_ms.unwrap_or(0);
        let left_activity = u128::from(left.read_sectors_512.unwrap_or(0))
            + u128::from(left.write_sectors_512.unwrap_or(0));
        let right_activity = u128::from(right.read_sectors_512.unwrap_or(0))
            + u128::from(right.write_sectors_512.unwrap_or(0));
        right_busy
            .cmp(&left_busy)
            .then_with(|| right_weighted.cmp(&left_weighted))
            .then_with(|| right.end_in_flight.cmp(&left.end_in_flight))
            .then_with(|| right_activity.cmp(&left_activity))
            .then_with(|| {
                (u128::from(right.reads_completed.unwrap_or(0))
                    + u128::from(right.writes_completed.unwrap_or(0)))
                .cmp(
                    &(u128::from(left.reads_completed.unwrap_or(0))
                        + u128::from(left.writes_completed.unwrap_or(0))),
                )
            })
            .then_with(|| left.key.cmp(&right.key))
    });
    candidates.truncate(5);
    if !candidates.is_empty() {
        qualifiers.push(Qualifier { kind: "device_activity_same_window_correlation", message: "Diskstats activity occurred in the same window as I/O PSI pressure; it does not establish a constrained device or a causal device path." });
    }
    candidates
}

fn io_process_suspects(
    process_io: Option<&ProcessIoObservation>,
    qualifiers: &mut Vec<Qualifier>,
) -> Vec<IoProcessSuspect> {
    let Some(process_io) = process_io else {
        return vec![];
    };
    let confidence = if process_io.capability == IoCapability::Available {
        Confidence::Medium
    } else {
        Confidence::Low
    };
    let mut suspects: Vec<_> = process_io
        .processes
        .iter()
        .filter_map(|process| {
            let known_accounted_bytes = u128::from(process.read_bytes.unwrap_or(0))
                + u128::from(process.write_bytes.unwrap_or(0));
            (known_accounted_bytes > 0).then_some(IoProcessSuspect {
                key: process.key,
                name: process.name.clone(),
                read_bytes: process.read_bytes,
                write_bytes: process.write_bytes,
                cancelled_write_bytes: process.cancelled_write_bytes,
                known_accounted_bytes,
                confidence,
                label: "same_window_process_io_activity",
            })
        })
        .collect();
    suspects.sort_by(|left, right| {
        right
            .known_accounted_bytes
            .cmp(&left.known_accounted_bytes)
            .then_with(|| left.key.cmp(&right.key))
    });
    suspects.truncate(5);
    if !suspects.is_empty() {
        qualifiers.push(Qualifier { kind: "process_io_same_window_correlation", message: "Process read_bytes or charged write_bytes changed in the same window as I/O PSI pressure; cancelled writes remain separate, and this does not map the process to a device or prove causality." });
    }
    suspects
}

fn io_qualifiers(
    evidence: &IoEvidence,
    diskstats: Option<&DiskstatsObservation>,
    process_io: Option<&ProcessIoObservation>,
) -> Vec<Qualifier> {
    let mut qualifiers = vec![
        no_io_victim_attribution_qualifier(),
        Qualifier {
            kind: "layered_device_visibility",
            message: "Diskstats can include layered, virtual, or stacked devices; activity may be represented more than once and is not ownership attribution.",
        },
        Qualifier {
            kind: "page_cache_writeback_visibility",
            message: "Process read_bytes, charged write_bytes, cancelled writes, and diskstats do not reveal page-cache hits, writeback timing, or which storage operation caused a stall.",
        },
        Qualifier {
            kind: "io_full_nonadditive_subset",
            message: "I/O PSI `full` is a subset of `some`; it is retained as context and never added to the pressure fraction or used to establish pressure.",
        },
    ];
    match evidence.psi_full_state {
        IoFullEvidenceState::Available => {}
        IoFullEvidenceState::Missing => qualifiers.push(Qualifier { kind: "io_full_unavailable", message: "I/O PSI `full` is unavailable; valid `some` still determines the resource verdict." }),
        _ => qualifiers.push(Qualifier { kind: "io_full_interval_invalid", message: "I/O PSI `full` was inconsistent; it was excluded while valid `some` evidence was retained." }),
    }
    match diskstats {
        None => qualifiers.push(Qualifier { kind: "diskstats_unavailable", message: "Diskstats context is unavailable; I/O PSI alone determines the resource verdict." }),
        Some(observation) if observation.capability != IoCapability::Available => qualifiers.push(Qualifier { kind: "diskstats_partial", message: "Diskstats context is partial or unavailable; device activity attribution is limited." }),
        Some(_) => {}
    }
    match process_io {
        None => qualifiers.push(Qualifier { kind: "process_io_unavailable", message: "Per-process I/O context is unavailable; no process activity suspects were produced." }),
        Some(observation) if observation.capability != IoCapability::Available => qualifiers.push(Qualifier { kind: "process_io_partial", message: "Per-process I/O context is partial or unavailable; process activity attribution is limited." }),
        Some(_) => {}
    }
    qualifiers
}

const fn no_io_victim_attribution_qualifier() -> Qualifier {
    Qualifier {
        kind: "no_affected_workload_attribution",
        message: "This host-wide I/O slice does not identify affected workloads or claim that any process is a victim.",
    }
}

/// Analyze scoped cgroup PSI independently of host findings.  Cgroup-local
/// pressure is not evidence that the group caused host-wide pressure.
pub fn analyze_cgroups(observation: Option<&CgroupObservation>) -> CgroupAnalysisResult {
    let Some(observation) = observation else {
        return CgroupAnalysisResult::default();
    };
    let mut all_findings = Vec::new();
    for group in &observation.groups {
        for (resource, psi) in [
            (CgroupResourceKind::Cpu, &group.cpu_pressure),
            (CgroupResourceKind::Memory, &group.memory_pressure),
            (CgroupResourceKind::Io, &group.io_pressure),
        ] {
            all_findings.push(cgroup_finding(group, resource, psi, observation));
        }
    }
    all_findings.sort_by(|left, right| {
        severity_rank(right.severity)
            .cmp(&severity_rank(left.severity))
            .then_with(|| {
                confidence_rank(right.resource_confidence)
                    .cmp(&confidence_rank(left.resource_confidence))
            })
            .then_with(|| {
                right
                    .evidence
                    .psi_some_fraction
                    .partial_cmp(&left.evidence.psi_some_fraction)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| left.path.cmp(&right.path))
            .then_with(|| {
                cgroup_resource_rank(left.resource).cmp(&cgroup_resource_rank(right.resource))
            })
    });
    let mut findings: Vec<_> = all_findings
        .iter()
        .filter(|finding| finding.kind == CgroupAssessmentKind::Pressure)
        .cloned()
        .collect();
    findings.truncate(64);
    if findings.is_empty() {
        if let Some(summary) = all_findings.into_iter().next() {
            findings.push(summary);
        }
    }
    CgroupAnalysisResult {
        findings,
        qualifiers: vec![],
    }
}

fn cgroup_resource_rank(resource: CgroupResourceKind) -> u8 {
    match resource {
        CgroupResourceKind::Cpu => 0,
        CgroupResourceKind::Memory => 1,
        CgroupResourceKind::Io => 2,
    }
}

fn cgroup_finding(
    group: &crate::cgroup::CgroupInterval,
    resource: CgroupResourceKind,
    psi: &CgroupResource<CgroupPsiInterval>,
    observation: &CgroupObservation,
) -> CgroupFinding {
    let mut qualifiers = vec![
        Qualifier {
            kind: "cgroup_scoped_evidence",
            message: "This is cgroup-scoped PSI evidence. It does not establish that this cgroup caused host pressure or that host pressure affected this cgroup.",
        },
        Qualifier {
            kind: "cgroup_context_not_causality",
            message: "CPU, memory, I/O counters, gauges, and stable membership are context only; they do not establish a cross-resource or process causal relationship.",
        },
        Qualifier {
            kind: "cgroup_hierarchy_overlaps",
            message: "Ancestor and child cgroup scopes can overlap because parent controller and PSI data may include descendants; findings are not independent and are never summed.",
        },
        Qualifier {
            kind: "cgroup_path_lifetime_uncertain",
            message: "A stable cgroup path has no generation counter, so deletion and recreation at the same path cannot be ruled out.",
        },
    ];
    if group.systemd_unit_candidate.is_some() {
        qualifiers.push(Qualifier { kind: "systemd_unit_candidate", message: "The systemd-looking final path component is a presentation-only candidate, not authoritative unit identity." });
    }
    if observation.issues.members_moved != 0
        || observation.issues.members_reused != 0
        || observation.issues.members_appeared != 0
        || observation.issues.members_exited != 0
    {
        qualifiers.push(Qualifier { kind: "cgroup_membership_changed", message: "Membership changed during the interval; only stable same-path members are retained, so membership context is partial." });
    }
    if observation.issues.process_limit_reached
        || observation.issues.cgroup_limit_reached
        || observation.issues.process_permission_denied != 0
        || observation.issues.cgroup_permission_denied != 0
    {
        qualifiers.push(Qualifier {
            kind: "cgroup_collection_partial",
            message: "Bounded collection or permissions made cgroup context partial.",
        });
    }
    let window = psi.value.as_ref().and_then(|interval| interval.elapsed);
    let window_us = window.map(|duration| duration.as_micros()).unwrap_or(0);
    let members = observation
        .members
        .iter()
        .filter(|member| {
            member.cgroup_path == group.path
                || (group.path == "/"
                    || member
                        .cgroup_path
                        .strip_prefix(&group.path)
                        .is_some_and(|rest| rest.starts_with('/')))
        })
        .take(5)
        .map(|member| CgroupMember {
            key: member.key,
            name: member.name.clone(),
            label: if member.cgroup_path == group.path {
                "stable_direct_cgroup_member"
            } else {
                "stable_descendant_cgroup_member"
            },
        })
        .collect();
    let (some, full, state) = match &psi.value {
        Some(interval) => {
            let some = interval
                .some_total_usec
                .zip(window.filter(|duration| !duration.is_zero()))
                .map(|(value, duration)| value as f64 / duration.as_micros() as f64);
            let full = interval
                .full_total_usec
                .zip(window.filter(|duration| !duration.is_zero()))
                .map(|(value, duration)| value as f64 / duration.as_micros() as f64);
            (some, full, interval.state)
        }
        None => (None, None, CgroupPsiIntervalState::Partial),
    };
    let insufficient = window.is_none_or(|duration| duration < MIN_DIAGNOSIS_WINDOW);
    let some_exceeds_window = psi
        .value
        .as_ref()
        .and_then(|value| value.some_total_usec)
        .is_some_and(|value| u128::from(value) > window_us);
    let valid_some = matches!(
        state,
        CgroupPsiIntervalState::Available
            | CgroupPsiIntervalState::Partial
            | CgroupPsiIntervalState::FullExceedsSome
    ) && some.is_some()
        && !some_exceeds_window;
    let severity = if valid_some && !insufficient {
        severity_for_psi(some.unwrap_or(0.0))
    } else {
        Severity::None
    };
    if !valid_some {
        qualifiers.push(Qualifier { kind: "cgroup_psi_unavailable_or_invalid", message: "This cgroup PSI interval is unavailable or its `some` counter regressed; no pressure verdict was made." });
    }
    if some_exceeds_window {
        qualifiers.push(Qualifier { kind: "cgroup_some_exceeds_window", message: "Cgroup PSI `some` exceeded its measured interval and was rejected as inconsistent; no pressure verdict was made." });
    }
    if matches!(
        state,
        CgroupPsiIntervalState::Partial | CgroupPsiIntervalState::FullExceedsSome
    ) {
        qualifiers.push(Qualifier { kind: "cgroup_full_partial", message: "Cgroup PSI `full` is partial or inconsistent; valid `some` remains the sole pressure verdict." });
    }
    if insufficient {
        qualifiers.push(Qualifier {
            kind: "insufficient_observation",
            message: "A measured cgroup PSI interval of at least 1s is required for a diagnosis.",
        });
    }
    let kind = if insufficient || !valid_some {
        CgroupAssessmentKind::InsufficientObservation
    } else if severity == Severity::None {
        CgroupAssessmentKind::NoMeaningfulPressure
    } else {
        CgroupAssessmentKind::Pressure
    };
    let (mechanism, mechanism_confidence) = if resource == CgroupResourceKind::Memory
        && kind == CgroupAssessmentKind::Pressure
        && group.memory_stat.value.as_ref().is_some_and(|stat| {
            scoped_possible_thrashing(severity, full, window, state, observation.elapsed, stat)
        }) {
        (
            Some(CgroupMechanism::PossibleThrashing),
            Some(Confidence::Medium),
        )
    } else {
        cgroup_mechanism_label(resource, kind, group)
    };
    match mechanism {
        Some(
            CgroupMechanism::Reclaim | CgroupMechanism::Swap | CgroupMechanism::PossibleThrashing,
        ) => {
            qualifiers.push(Qualifier {
                kind: "cgroup_memory_mechanism_same_window_correlation",
                message: "Cgroup memory.stat page deltas occurred in the same window as scoped PSI pressure; they support a reclaim, swap, or possible-thrashing label but do not prove causality.",
            });
        }
        Some(CgroupMechanism::CpuQuotaThrottle) => {
            qualifiers.push(Qualifier {
                kind: "cgroup_cpu_quota_throttle_same_window_correlation",
                message: "Cgroup cpu.stat throttled time occurred in the same window as scoped CPU PSI pressure; it supports a quota-throttle label but does not prove the quota caused the stalls or host CPU pressure.",
            });
        }
        None => {}
    }
    if mechanism == Some(CgroupMechanism::PossibleThrashing) {
        qualifiers.push(Qualifier {
            kind: "cgroup_possible_thrashing_heuristic",
            message: "Scoped possible thrashing requires sustained high `some`, non-trivial valid `full`, and material direct-reclaim plus bidirectional swap churn over the cgroup observation interval; it remains a heuristic and may include descendant activity.",
        });
    }
    let confidence = if kind == CgroupAssessmentKind::InsufficientObservation {
        Confidence::Low
    } else if window.is_some_and(|duration| duration >= Duration::from_secs(5)) {
        Confidence::High
    } else {
        Confidence::Medium
    };
    let resource_name = match resource {
        CgroupResourceKind::Cpu => "CPU",
        CgroupResourceKind::Memory => "memory",
        CgroupResourceKind::Io => "I/O",
    };
    let summary = match (kind, mechanism) {
        (CgroupAssessmentKind::Pressure, Some(CgroupMechanism::Reclaim)) => format!(
            "Scoped memory reclaim pressure observed in {} ({:.2}% cgroup PSI some).",
            group.path,
            some.unwrap_or(0.0) * 100.0
        ),
        (CgroupAssessmentKind::Pressure, Some(CgroupMechanism::Swap)) => format!(
            "Scoped memory swap pressure observed in {} ({:.2}% cgroup PSI some).",
            group.path,
            some.unwrap_or(0.0) * 100.0
        ),
        (CgroupAssessmentKind::Pressure, Some(CgroupMechanism::PossibleThrashing)) => format!(
            "Scoped memory evidence is consistent with possible thrashing in {} ({:.2}% some, {:.2}% full PSI).",
            group.path,
            some.unwrap_or(0.0) * 100.0,
            full.unwrap_or(0.0) * 100.0
        ),
        (CgroupAssessmentKind::Pressure, Some(CgroupMechanism::CpuQuotaThrottle)) => format!(
            "Scoped CPU quota-throttle pressure observed in {} ({:.2}% cgroup PSI some).",
            group.path,
            some.unwrap_or(0.0) * 100.0
        ),
        (CgroupAssessmentKind::Pressure, None) => format!(
            "Scoped {resource_name} pressure observed in {} ({:.2}% cgroup PSI some).",
            group.path,
            some.unwrap_or(0.0) * 100.0
        ),
        (CgroupAssessmentKind::NoMeaningfulPressure, _) => format!(
            "No meaningful scoped {resource_name} pressure observed in {}.",
            group.path
        ),
        (CgroupAssessmentKind::InsufficientObservation, _) => format!(
            "Scoped {resource_name} assessment for {} is insufficient or unavailable.",
            group.path
        ),
    };
    CgroupFinding {
        path: group.path.clone(),
        resource,
        kind,
        severity,
        resource_confidence: confidence,
        mechanism,
        mechanism_confidence,
        summary,
        evidence: CgroupEvidence {
            psi_some_fraction: some,
            psi_some_total_delta_us: psi.value.as_ref().and_then(|x| x.some_total_usec),
            psi_full_fraction: full,
            psi_full_total_delta_us: psi.value.as_ref().and_then(|x| x.full_total_usec),
            psi_window_us: window_us,
            psi_state: psi.state,
            cpu: group.cpu.clone(),
            memory_current_end: group.memory_current_end.clone(),
            memory_events: group.memory_events.clone(),
            memory_stat: group.memory_stat.clone(),
            io: group.io.clone(),
        },
        systemd_unit_candidate: group.systemd_unit_candidate.clone(),
        members,
        qualifiers,
    }
}

fn scoped_possible_thrashing(
    severity: Severity,
    full: Option<f64>,
    psi_window: Option<Duration>,
    psi_state: CgroupPsiIntervalState,
    observation_elapsed: Duration,
    stat: &CgroupMemoryStatRaw,
) -> bool {
    matches!(severity, Severity::High | Severity::Severe)
        && psi_window.is_some_and(|window| window >= Duration::from_secs(5))
        && matches!(psi_state, CgroupPsiIntervalState::Available)
        && full.is_some_and(|fraction| fraction >= 0.01)
        && !observation_elapsed.is_zero()
        && page_rate_at_least(
            stat.pgscan_direct,
            observation_elapsed,
            THRASHING_MIN_PAGE_RATE_PER_SEC,
        )
        && page_rate_at_least(
            stat.pgsteal_direct,
            observation_elapsed,
            THRASHING_MIN_PAGE_RATE_PER_SEC,
        )
        && page_rate_at_least(
            stat.pswpin,
            observation_elapsed,
            THRASHING_MIN_PAGE_RATE_PER_SEC,
        )
        && page_rate_at_least(
            stat.pswpout,
            observation_elapsed,
            THRASHING_MIN_PAGE_RATE_PER_SEC,
        )
}

fn cgroup_mechanism_label(
    resource: CgroupResourceKind,
    kind: CgroupAssessmentKind,
    group: &crate::cgroup::CgroupInterval,
) -> (Option<CgroupMechanism>, Option<Confidence>) {
    if kind != CgroupAssessmentKind::Pressure {
        return (None, None);
    }
    match resource {
        CgroupResourceKind::Memory => {
            let Some(stat) = group.memory_stat.value.as_ref() else {
                return (None, None);
            };
            if stat.pswpin.is_some_and(|value| value > 0) {
                return (Some(CgroupMechanism::Swap), Some(Confidence::Low));
            }
            if stat.pgscan_direct.is_some_and(|value| value > 0)
                && stat.pgsteal_direct.is_some_and(|value| value > 0)
            {
                return (Some(CgroupMechanism::Reclaim), Some(Confidence::Low));
            }
            (None, None)
        }
        CgroupResourceKind::Cpu => {
            if group
                .cpu
                .value
                .as_ref()
                .and_then(|cpu| cpu.throttled_usec)
                .is_some_and(|value| value > 0)
            {
                (
                    Some(CgroupMechanism::CpuQuotaThrottle),
                    Some(Confidence::Low),
                )
            } else {
                (None, None)
            }
        }
        CgroupResourceKind::Io => (None, None),
    }
}

pub fn analyze_cpu(
    psi: Option<&CpuPsiObservation>,
    cpu: Option<&CpuProcessObservation>,
) -> AnalysisResult {
    let Some(psi) = psi else {
        return AnalysisResult {
            findings: vec![],
            qualifiers: vec![Qualifier {
                kind: "cpu_assessment_unavailable",
                message: "CPU PSI is unavailable, so no CPU contention assessment was produced.",
            }],
        };
    };
    if psi.requested.min(psi.interval.elapsed) < MIN_DIAGNOSIS_WINDOW {
        return AnalysisResult { findings: vec![CpuFinding { resource: Resource::Cpu, kind: AssessmentKind::InsufficientObservation, severity: Severity::None, resource_confidence: Confidence::Low, summary: "CPU observation is shorter than 1s; no healthy or contention conclusion was made.".into(), evidence: evidence(psi, cpu), victims: vec![], suspects: vec![], qualifiers: vec![Qualifier { kind: "insufficient_observation", message: "A requested and measured CPU PSI interval of at least 1s is required for a diagnosis." }] }], qualifiers: vec![] };
    }
    let severity = severity_for_psi(psi.interval.some_fraction);
    let contention = severity != Severity::None;
    let resource_confidence = if psi.requested >= Duration::from_secs(5)
        && psi.interval.elapsed >= Duration::from_secs(5)
    {
        Confidence::High
    } else {
        Confidence::Medium
    };
    let mut qualifiers = supporting_qualifiers(cpu);
    if cpu.is_none() {
        qualifiers.push(Qualifier { kind: "attribution_unavailable", message: "CPU interval context is unavailable; victim and suspect attribution was not produced." });
    }
    if cpu.is_some_and(|cpu| cpu.schedstat_capability != SchedstatCapability::Available) {
        qualifiers.push(Qualifier { kind: "victim_attribution_limited", message: "Scheduler accounting is unavailable or partial; victim attribution is limited." });
    }
    if cpu.is_some_and(process_coverage_partial) {
        qualifiers.push(Qualifier {
            kind: "suspect_attribution_limited",
            message: "Process collection is partial; suspect attribution is limited.",
        });
    }
    if !contention {
        qualifiers.push(Qualifier { kind: "cpu_no_meaningful_contention", message: "No meaningful CPU scheduling contention was observed from exact-interval CPU PSI." });
        if cpu.is_some_and(|cpu| {
            cpu.scheduler_delay_candidates
                .iter()
                .any(|candidate| candidate.runnable_wait_ns > 0)
        }) {
            qualifiers.push(Qualifier { kind: "scheduler_delay_context", message: "Positive scheduler-delay intervals are context but do not override the PSI no-contention verdict." });
        }
    }
    let victims = if contention {
        cpu.map(|cpu| victims(cpu, resource_confidence))
            .unwrap_or_default()
    } else {
        vec![]
    };
    let suspects = if contention {
        cpu.map(|cpu| suspects(cpu, resource_confidence, &mut qualifiers))
            .unwrap_or_default()
    } else {
        vec![]
    };
    let summary = if contention {
        format!(
            "CPU scheduling contention observed ({:.2}% CPU PSI some).",
            psi.interval.some_fraction * 100.0
        )
    } else {
        "No meaningful CPU scheduling contention observed.".into()
    };
    AnalysisResult {
        findings: vec![CpuFinding {
            resource: Resource::Cpu,
            kind: if contention {
                AssessmentKind::CpuContention
            } else {
                AssessmentKind::CpuNoMeaningfulContention
            },
            severity,
            resource_confidence,
            summary,
            evidence: evidence(psi, cpu),
            victims,
            suspects,
            qualifiers,
        }],
        qualifiers: vec![],
    }
}

/// Builds the six host role lists from normalized observations.  The resource
/// analyzers remain the authority for whether PSI established pressure; this
/// function only attributes an already-confirmed scope and never reads procfs.
pub fn host_process_scope(
    cpu: Option<&CpuProcessObservation>,
    process_io: Option<&ProcessIoObservation>,
    cpu_pressure: Option<Confidence>,
    memory_pressure: Option<Confidence>,
    io_pressure: Option<Confidence>,
) -> ProcessScope {
    let roles = vec![
        cpu_victims(cpu, cpu_pressure, None),
        cpu_suspects_role(cpu, cpu_pressure, None),
        memory_victims(cpu, memory_pressure, None),
        memory_suspects(cpu, memory_pressure, None),
        io_victims(cpu, io_pressure, None),
        io_suspects_role(process_io, io_pressure, None),
    ];
    ProcessScope {
        scope: ProcessScopeKind::Host,
        roles,
    }
}

/// Build one scope for each cgroup with PSI-backed pressure. Candidate
/// selection is performed against the complete stable membership set, rather
/// than the presentation-only five-member summary on `CgroupFinding`.
pub fn cgroup_process_scopes(
    observation: Option<&CgroupObservation>,
    cpu: Option<&CpuProcessObservation>,
    process_io: Option<&ProcessIoObservation>,
) -> Vec<ProcessScope> {
    let Some(observation) = observation else {
        return Vec::new();
    };
    let membership_complete = cgroup_membership_complete(observation);
    observation
        .groups
        .iter()
        .filter_map(|group| {
            let findings = [
                cgroup_finding(
                    group,
                    CgroupResourceKind::Cpu,
                    &group.cpu_pressure,
                    observation,
                ),
                cgroup_finding(
                    group,
                    CgroupResourceKind::Memory,
                    &group.memory_pressure,
                    observation,
                ),
                cgroup_finding(
                    group,
                    CgroupResourceKind::Io,
                    &group.io_pressure,
                    observation,
                ),
            ];
            let pressure = |resource| {
                findings
                    .iter()
                    .find(|finding| finding.resource == resource)
                    .and_then(|finding| {
                        (finding.kind == CgroupAssessmentKind::Pressure)
                            .then_some(finding.resource_confidence)
                    })
            };
            let keys = observation
                .members
                .iter()
                .filter(|member| cgroup_contains_path(&group.path, &member.cgroup_path))
                .map(|member| member.key)
                .collect::<BTreeSet<_>>();
            if pressure(CgroupResourceKind::Cpu).is_none()
                && pressure(CgroupResourceKind::Memory).is_none()
                && pressure(CgroupResourceKind::Io).is_none()
            {
                return None;
            }
            let mut roles = vec![
                cpu_victims(cpu, pressure(CgroupResourceKind::Cpu), Some(&keys)),
                cpu_suspects_role(cpu, pressure(CgroupResourceKind::Cpu), Some(&keys)),
                memory_victims(cpu, pressure(CgroupResourceKind::Memory), Some(&keys)),
                memory_suspects(cpu, pressure(CgroupResourceKind::Memory), Some(&keys)),
                io_victims(cpu, pressure(CgroupResourceKind::Io), Some(&keys)),
                io_suspects_role(process_io, pressure(CgroupResourceKind::Io), Some(&keys)),
            ];
            if !membership_complete {
                mark_roles_partial(&mut roles);
            }
            Some(ProcessScope {
                scope: ProcessScopeKind::Cgroup {
                    path: group.path.clone(),
                },
                roles,
            })
        })
        .collect()
}

fn cgroup_contains_path(scope: &str, member: &str) -> bool {
    scope == "/"
        || member == scope
        || member
            .strip_prefix(scope)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn cgroup_membership_complete(observation: &CgroupObservation) -> bool {
    let issues = &observation.issues;
    !issues.process_enumeration_failed
        && issues.process_enumeration_errors == 0
        && issues.process_disappeared == 0
        && issues.process_identity_changed == 0
        && issues.process_permission_denied == 0
        && issues.process_malformed == 0
        && !issues.process_limit_reached
        && !issues.budget_exhausted
        && issues.members_appeared == 0
        && issues.members_exited == 0
        && issues.members_reused == 0
        && issues.members_moved == 0
}

fn mark_roles_partial(roles: &mut [ProcessRoleList]) {
    for role in roles {
        if role.completeness == ProcessRoleCompleteness::Complete {
            role.availability = ProcessCandidateAvailability::UnavailableOrIncomplete;
            role.completeness = ProcessRoleCompleteness::Partial;
        }
    }
}

fn in_scope(key: ProcessKey, allowed: Option<&BTreeSet<ProcessKey>>) -> bool {
    allowed.is_none_or(|keys| keys.contains(&key))
}

fn unassessed(role: ProcessRole) -> ProcessRoleList {
    ProcessRoleList {
        role,
        availability: ProcessCandidateAvailability::NotAssessed,
        completeness: ProcessRoleCompleteness::Unavailable,
        stale: false,
        candidates: vec![],
    }
}

fn unavailable(role: ProcessRole) -> ProcessRoleList {
    ProcessRoleList {
        role,
        availability: ProcessCandidateAvailability::UnavailableOrIncomplete,
        completeness: ProcessRoleCompleteness::Unavailable,
        stale: false,
        candidates: vec![],
    }
}

fn role_list(
    role: ProcessRole,
    pressure: Option<Confidence>,
    complete: bool,
    candidates: Vec<ProcessCandidate>,
) -> ProcessRoleList {
    let Some(_) = pressure else {
        return unassessed(role);
    };
    ProcessRoleList {
        role,
        availability: if complete {
            ProcessCandidateAvailability::Available
        } else {
            ProcessCandidateAvailability::UnavailableOrIncomplete
        },
        completeness: if complete {
            ProcessRoleCompleteness::Complete
        } else {
            ProcessRoleCompleteness::Partial
        },
        stale: false,
        candidates,
    }
}

fn candidate_confidence(resource: Confidence, direct: bool, fallback: bool) -> Confidence {
    if fallback {
        Confidence::Low
    } else if direct {
        resource
    } else {
        Confidence::Medium.min(resource)
    }
}

fn cpu_victims(
    cpu: Option<&CpuProcessObservation>,
    pressure: Option<Confidence>,
    allowed: Option<&BTreeSet<ProcessKey>>,
) -> ProcessRoleList {
    let Some(cpu) = cpu else {
        return pressure.map_or_else(
            || unassessed(ProcessRole::CpuVictim),
            |_| unavailable(ProcessRole::CpuVictim),
        );
    };
    let complete = cpu.schedstat_capability == SchedstatCapability::Available;
    let taskstats: BTreeMap<_, _> = cpu.taskstats.iter().map(|item| (item.key, item)).collect();
    let mut candidates: Vec<_> = cpu
        .scheduler_delay_candidates
        .iter()
        .filter(|item| in_scope(item.key, allowed))
        .filter(|item| item.runnable_wait_ns > 0)
        .map(|item| {
            let corroboration = taskstats
                .get(&item.key)
                .and_then(|stats| stats.cpu_delay_ns);
            ProcessCandidate {
                role: ProcessRole::CpuVictim,
                key: item.key,
                name: item.name.clone(),
                confidence: candidate_confidence(pressure.unwrap_or(Confidence::Low), true, false),
                label: "observed_runnable_delay_victim_candidate",
                evidence: ProcessCandidateEvidence::RunnableDelay {
                    runnable_wait_ns: item.runnable_wait_ns,
                    runnable_delay_fraction: item.runnable_delay_fraction,
                    stable_task_count: item.task_count,
                    taskstats_cpu_delay_ns: corroboration,
                },
            }
        })
        .collect();
    let direct_keys: std::collections::BTreeSet<_> =
        candidates.iter().map(|candidate| candidate.key).collect();
    if matches!(
        cpu.taskstats_capability,
        TaskstatsCapability::Available | TaskstatsCapability::Partial
    ) {
        candidates.extend(
            cpu.taskstats
                .iter()
                .filter(|item| in_scope(item.key, allowed))
                .filter_map(|item| {
                    (!direct_keys.contains(&item.key)).then_some(())?;
                    item.cpu_delay_ns
                        .filter(|delay| *delay > 0)
                        .map(|delay| ProcessCandidate {
                            role: ProcessRole::CpuVictim,
                            key: item.key,
                            name: name_for_key(cpu, item.key),
                            confidence: candidate_confidence(
                                pressure.unwrap_or(Confidence::Low),
                                true,
                                false,
                            ),
                            label: "observed_taskstats_cpu_delay_victim_candidate",
                            evidence: ProcessCandidateEvidence::TaskstatsCpuDelay {
                                cpu_delay_ns: delay,
                            },
                        })
                }),
        );
    }
    candidates.sort_by(|a, b| {
        cpu_schedstat_direct(&b.evidence)
            .cmp(&cpu_schedstat_direct(&a.evidence))
            .then_with(|| score_cpu_victim(&b.evidence).cmp(&score_cpu_victim(&a.evidence)))
            .then_with(|| a.key.cmp(&b.key))
    });
    candidates.truncate(5);
    role_list(
        ProcessRole::CpuVictim,
        pressure,
        complete || taskstats_complete_for_cpu(cpu),
        candidates,
    )
}
fn cpu_schedstat_direct(evidence: &ProcessCandidateEvidence) -> bool {
    matches!(evidence, ProcessCandidateEvidence::RunnableDelay { .. })
}
fn taskstats_complete_for_cpu(cpu: &CpuProcessObservation) -> bool {
    matches!(cpu.taskstats_capability, TaskstatsCapability::Available)
        && matches!(cpu.delay_accounting, DelayAccountingState::Enabled)
        && process_window_complete(cpu)
        && cpu
            .taskstats
            .iter()
            .all(|item| item.field_support.cpu_delay)
}

fn score_cpu_victim(evidence: &ProcessCandidateEvidence) -> u64 {
    match evidence {
        ProcessCandidateEvidence::RunnableDelay {
            runnable_wait_ns, ..
        } => *runnable_wait_ns,
        ProcessCandidateEvidence::TaskstatsCpuDelay { cpu_delay_ns } => *cpu_delay_ns,
        _ => 0,
    }
}

fn cpu_suspects_role(
    cpu: Option<&CpuProcessObservation>,
    pressure: Option<Confidence>,
    allowed: Option<&BTreeSet<ProcessKey>>,
) -> ProcessRoleList {
    let Some(cpu) = cpu else {
        return pressure.map_or_else(
            || unassessed(ProcessRole::CpuSuspect),
            |_| unavailable(ProcessRole::CpuSuspect),
        );
    };
    let complete = !process_coverage_partial(cpu);
    let mut candidates: Vec<_> = cpu
        .processes
        .iter()
        .filter(|item| in_scope(item.key, allowed))
        .filter(|item| item.cpu_fraction_of_one >= SUSPECT_MIN_FRACTION)
        .map(|item| ProcessCandidate {
            role: ProcessRole::CpuSuspect,
            key: item.key,
            name: item.name.clone(),
            confidence: Confidence::Medium.min(pressure.unwrap_or(Confidence::Low)),
            label: "same_window_cpu_consumer_suspect",
            evidence: ProcessCandidateEvidence::CpuConsumption {
                cpu_fraction_of_one: item.cpu_fraction_of_one,
                cpu_ticks: item.cpu_ticks,
            },
        })
        .collect();
    candidates.sort_by(|a, b| match (&a.evidence, &b.evidence) {
        (
            ProcessCandidateEvidence::CpuConsumption {
                cpu_fraction_of_one: left,
                ..
            },
            ProcessCandidateEvidence::CpuConsumption {
                cpu_fraction_of_one: right,
                ..
            },
        ) => right.total_cmp(left).then_with(|| a.key.cmp(&b.key)),
        _ => a.key.cmp(&b.key),
    });
    candidates.truncate(5);
    role_list(ProcessRole::CpuSuspect, pressure, complete, candidates)
}

fn memory_victims(
    cpu: Option<&CpuProcessObservation>,
    pressure: Option<Confidence>,
    allowed: Option<&BTreeSet<ProcessKey>>,
) -> ProcessRoleList {
    let Some(cpu) = cpu else {
        return pressure.map_or_else(
            || unassessed(ProcessRole::MemoryVictim),
            |_| unavailable(ProcessRole::MemoryVictim),
        );
    };
    if pressure.is_some()
        && !matches!(
            cpu.taskstats_capability,
            TaskstatsCapability::Available | TaskstatsCapability::Partial
        )
        && cpu.process_resource_evidence.is_empty()
    {
        return unavailable(ProcessRole::MemoryVictim);
    }
    // A disabled or unknown delay-accounting state cannot prove a zero
    // memory-delay interval. Positive taskstats counters remain valid direct
    // evidence regardless of the state.
    let direct_complete = taskstats_complete_for_memory(cpu);
    let mut candidates = Vec::new();
    for item in cpu
        .taskstats
        .iter()
        .filter(|item| in_scope(item.key, allowed))
    {
        let components = [
            ("swapin", item.swapin_delay_ns),
            ("reclaim", item.reclaim_delay_ns),
            ("thrashing", item.thrashing_delay_ns),
            ("compaction", item.compaction_delay_ns),
            ("write_protect_copy", item.write_protect_copy_delay_ns),
        ];
        if let Some((name, delay)) = components
            .into_iter()
            .filter_map(|(name, value)| value.map(|value| (name, value)))
            .filter(|(_, value)| *value > 0)
            .max_by_key(|(_, value)| *value)
        {
            candidates.push(ProcessCandidate {
                role: ProcessRole::MemoryVictim,
                key: item.key,
                name: name_for_key(cpu, item.key),
                confidence: candidate_confidence(pressure.unwrap_or(Confidence::Low), true, false),
                label: "observed_taskstats_memory_delay_victim_candidate",
                evidence: ProcessCandidateEvidence::MemoryDelay {
                    largest_component: name,
                    largest_delay_ns: delay,
                    swapin_delay_ns: item.swapin_delay_ns,
                    reclaim_delay_ns: item.reclaim_delay_ns,
                    thrashing_delay_ns: item.thrashing_delay_ns,
                    compaction_delay_ns: item.compaction_delay_ns,
                    write_protect_copy_delay_ns: item.write_protect_copy_delay_ns,
                },
            });
        }
    }
    let direct_keys: std::collections::BTreeSet<_> =
        candidates.iter().map(|candidate| candidate.key).collect();
    candidates.extend(
        resource_evidence(cpu)
            .filter(|item| in_scope(item.key, allowed))
            .filter_map(|item| {
                (!direct_keys.contains(&item.key)).then_some(())?;
                item.major_faults
                    .filter(|value| *value > 0)
                    .map(|major_faults| ProcessCandidate {
                        role: ProcessRole::MemoryVictim,
                        key: item.key,
                        name: item.name.clone(),
                        confidence: Confidence::Low,
                        label: "major_fault_memory_victim_candidate",
                        evidence: ProcessCandidateEvidence::MajorFaults { major_faults },
                    })
            }),
    );
    candidates.sort_by(|a, b| {
        memory_direct(&b.evidence)
            .cmp(&memory_direct(&a.evidence))
            .then_with(|| score_memory(&b.evidence).cmp(&score_memory(&a.evidence)))
            .then_with(|| a.key.cmp(&b.key))
    });
    candidates.truncate(5);
    role_list(
        ProcessRole::MemoryVictim,
        pressure,
        direct_complete,
        candidates,
    )
}
fn memory_direct(e: &ProcessCandidateEvidence) -> bool {
    matches!(e, ProcessCandidateEvidence::MemoryDelay { .. })
}
fn taskstats_complete_for_memory(cpu: &CpuProcessObservation) -> bool {
    matches!(cpu.taskstats_capability, TaskstatsCapability::Available)
        && matches!(cpu.delay_accounting, DelayAccountingState::Enabled)
        && process_window_complete(cpu)
        && cpu.taskstats.iter().all(|item| {
            item.field_support.swapin_delay
                && item.field_support.reclaim_delay
                && item.field_support.thrashing_delay
                && item.field_support.compaction_delay
                && item.field_support.write_protect_copy_delay
        })
}
fn score_memory(e: &ProcessCandidateEvidence) -> u64 {
    match e {
        ProcessCandidateEvidence::MemoryDelay {
            largest_delay_ns, ..
        } => *largest_delay_ns,
        ProcessCandidateEvidence::MajorFaults { major_faults } => *major_faults,
        _ => 0,
    }
}

fn memory_suspects(
    cpu: Option<&CpuProcessObservation>,
    pressure: Option<Confidence>,
    allowed: Option<&BTreeSet<ProcessKey>>,
) -> ProcessRoleList {
    let Some(cpu) = cpu else {
        return pressure.map_or_else(
            || unassessed(ProcessRole::MemorySuspect),
            |_| unavailable(ProcessRole::MemorySuspect),
        );
    };
    if pressure.is_some()
        && matches!(
            cpu::process_resource_capability(cpu),
            cpu::ProcessResourceCapability::Unavailable
                | cpu::ProcessResourceCapability::NotRecorded
        )
    {
        return unavailable(ProcessRole::MemorySuspect);
    }
    let complete = resource_field_complete(cpu, |item| item.rss_growth_bytes.is_some())
        && cpu.collection_issues.resource_value_overflow == 0;
    let mut candidates: Vec<_> = resource_evidence(cpu)
        .filter(|item| in_scope(item.key, allowed))
        .filter_map(|item| {
            item.rss_growth_bytes
                .filter(|value| *value > 0)
                .map(|rss_growth_bytes| ProcessCandidate {
                    role: ProcessRole::MemorySuspect,
                    key: item.key,
                    name: item.name.clone(),
                    confidence: Confidence::Low,
                    label: "rss_growth_memory_suspect",
                    evidence: ProcessCandidateEvidence::RssGrowth { rss_growth_bytes },
                })
        })
        .collect();
    candidates.sort_by(|a, b| {
        score_rss(&b.evidence)
            .cmp(&score_rss(&a.evidence))
            .then_with(|| a.key.cmp(&b.key))
    });
    candidates.truncate(5);
    role_list(ProcessRole::MemorySuspect, pressure, complete, candidates)
}
fn score_rss(e: &ProcessCandidateEvidence) -> u64 {
    match e {
        ProcessCandidateEvidence::RssGrowth { rss_growth_bytes } => *rss_growth_bytes,
        _ => 0,
    }
}

fn io_victims(
    cpu: Option<&CpuProcessObservation>,
    pressure: Option<Confidence>,
    allowed: Option<&BTreeSet<ProcessKey>>,
) -> ProcessRoleList {
    let Some(cpu) = cpu else {
        return pressure.map_or_else(
            || unassessed(ProcessRole::IoVictim),
            |_| unavailable(ProcessRole::IoVictim),
        );
    };
    if pressure.is_some()
        && !matches!(
            cpu.taskstats_capability,
            TaskstatsCapability::Available | TaskstatsCapability::Partial
        )
        && cpu.process_resource_evidence.is_empty()
    {
        return unavailable(ProcessRole::IoVictim);
    }
    let mut candidates = Vec::new();
    let taskstats: BTreeMap<_, _> = cpu.taskstats.iter().map(|item| (item.key, item)).collect();
    let mut keys: std::collections::BTreeSet<_> = cpu
        .process_resource_evidence
        .iter()
        .filter(|item| in_scope(item.key, allowed))
        .map(|item| item.key)
        .collect();
    keys.extend(
        taskstats
            .keys()
            .copied()
            .filter(|key| in_scope(*key, allowed)),
    );
    for key in keys {
        let direct = taskstats
            .get(&key)
            .and_then(|stats| stats.block_io_delay_ns);
        let fallback = cpu
            .process_resource_evidence
            .iter()
            .find(|item| item.key == key)
            .and_then(|item| item.block_io_delay_ticks);
        if direct.is_some_and(|value| value > 0) || fallback.is_some_and(|value| value > 0) {
            candidates.push(ProcessCandidate {
                role: ProcessRole::IoVictim,
                key,
                name: name_for_key(cpu, key),
                confidence: if direct.is_some_and(|value| value > 0) {
                    candidate_confidence(pressure.unwrap_or(Confidence::Low), true, false)
                } else {
                    Confidence::Medium.min(pressure.unwrap_or(Confidence::Low))
                },
                label: if direct.is_some_and(|value| value > 0) {
                    "observed_taskstats_block_io_delay_victim_candidate"
                } else {
                    "observed_procfs_block_io_delay_victim_candidate"
                },
                evidence: ProcessCandidateEvidence::BlockIoDelay {
                    block_io_delay_ns: direct,
                    procfs_block_io_delay_ticks: fallback,
                },
            });
        }
    }
    candidates.sort_by(|a, b| {
        io_direct(&b.evidence)
            .cmp(&io_direct(&a.evidence))
            .then_with(|| {
                score_io_victim(&b.evidence)
                    .cmp(&score_io_victim(&a.evidence))
                    .then_with(|| a.key.cmp(&b.key))
            })
    });
    candidates.truncate(5);
    role_list(
        ProcessRole::IoVictim,
        pressure,
        taskstats_complete_for_io(cpu) || procfs_block_io_complete(cpu),
        candidates,
    )
}
fn taskstats_complete_for_io(cpu: &CpuProcessObservation) -> bool {
    matches!(cpu.taskstats_capability, TaskstatsCapability::Available)
        && matches!(cpu.delay_accounting, DelayAccountingState::Enabled)
        && process_window_complete(cpu)
        && cpu
            .taskstats
            .iter()
            .all(|item| item.field_support.block_io_delay)
}
fn procfs_block_io_complete(cpu: &CpuProcessObservation) -> bool {
    matches!(
        cpu::task_stat_capability(cpu),
        cpu::TaskStatCapability::Available
    ) && matches!(cpu.delay_accounting, DelayAccountingState::Enabled)
        && resource_field_complete(cpu, |item| item.block_io_delay_ticks.is_some())
}
fn io_direct(e: &ProcessCandidateEvidence) -> bool {
    matches!(e, ProcessCandidateEvidence::BlockIoDelay { block_io_delay_ns: Some(value), .. } if *value > 0)
}
fn score_io_victim(e: &ProcessCandidateEvidence) -> u64 {
    match e {
        ProcessCandidateEvidence::BlockIoDelay {
            block_io_delay_ns,
            procfs_block_io_delay_ticks,
        } => block_io_delay_ns
            .filter(|value| *value > 0)
            .or_else(|| procfs_block_io_delay_ticks.filter(|value| *value > 0))
            .unwrap_or(0),
        _ => 0,
    }
}

fn io_suspects_role(
    process_io: Option<&ProcessIoObservation>,
    pressure: Option<Confidence>,
    allowed: Option<&BTreeSet<ProcessKey>>,
) -> ProcessRoleList {
    let Some(process_io) = process_io else {
        return pressure.map_or_else(
            || unassessed(ProcessRole::IoSuspect),
            |_| unavailable(ProcessRole::IoSuspect),
        );
    };
    let complete = process_io.capability == IoCapability::Available;
    let mut candidates: Vec<_> = process_io
        .processes
        .iter()
        .filter(|item| in_scope(item.key, allowed))
        .filter_map(|item| {
            let known = u128::from(item.read_bytes.unwrap_or(0))
                + u128::from(item.write_bytes.unwrap_or(0));
            (known > 0).then(|| ProcessCandidate {
                role: ProcessRole::IoSuspect,
                key: item.key,
                name: item.name.clone(),
                confidence: Confidence::Medium.min(pressure.unwrap_or(Confidence::Low)),
                label: "same_window_process_io_activity_suspect",
                evidence: ProcessCandidateEvidence::IoActivity {
                    read_bytes: item.read_bytes,
                    write_bytes: item.write_bytes,
                    cancelled_write_bytes: item.cancelled_write_bytes,
                    known_accounted_bytes: known,
                },
            })
        })
        .collect();
    candidates.sort_by(|a, b| {
        score_io_activity(&b.evidence)
            .cmp(&score_io_activity(&a.evidence))
            .then_with(|| a.key.cmp(&b.key))
    });
    candidates.truncate(5);
    role_list(ProcessRole::IoSuspect, pressure, complete, candidates)
}
fn resource_field_complete(
    cpu: &CpuProcessObservation,
    supported: impl Fn(&ProcessResourceInterval) -> bool,
) -> bool {
    !cpu.process_resource_evidence.is_empty()
        && process_window_complete(cpu)
        && cpu.process_resource_evidence.iter().all(supported)
}
fn process_window_complete(cpu: &CpuProcessObservation) -> bool {
    let issues = &cpu.collection_issues;
    !cpu.process_resource_evidence.is_empty()
        && !issues.enumeration_failed
        && issues.enumeration_errors == 0
        && issues.disappeared == 0
        && issues.permission_denied == 0
        && issues.unreadable == 0
        && issues.malformed == 0
        && issues.appeared == 0
        && issues.exited == 0
        && !issues.limit_reached
}
fn score_io_activity(e: &ProcessCandidateEvidence) -> u128 {
    match e {
        ProcessCandidateEvidence::IoActivity {
            known_accounted_bytes,
            ..
        } => *known_accounted_bytes,
        _ => 0,
    }
}
fn resource_evidence(
    cpu: &CpuProcessObservation,
) -> impl Iterator<Item = &ProcessResourceInterval> {
    cpu.process_resource_evidence.iter()
}
fn name_for_key(cpu: &CpuProcessObservation, key: ProcessKey) -> String {
    cpu.processes
        .iter()
        .find(|item| item.key == key)
        .map(|item| item.name.clone())
        .or_else(|| {
            cpu.process_resource_evidence
                .iter()
                .find(|item| item.key == key)
                .map(|item| item.name.clone())
        })
        .or_else(|| {
            cpu.scheduler_delay_candidates
                .iter()
                .find(|item| item.key == key)
                .map(|item| item.name.clone())
        })
        .unwrap_or_else(|| format!("pid-{}", key.pid))
}

fn evidence(psi: &CpuPsiObservation, cpu: Option<&CpuProcessObservation>) -> CpuEvidence {
    CpuEvidence {
        psi_some_fraction: psi.interval.some_fraction,
        psi_total_delta_us: psi.interval.total_delta_us,
        psi_window_us: psi.interval.elapsed.as_micros(),
        host_utilization_fraction: cpu.map(|c| c.host.utilization_fraction),
        logical_cpu_count: cpu.map(|c| c.host.cpu_count),
        runnable_tasks: cpu.and_then(|c| c.load.as_ref().map(|l| l.runnable_tasks)),
        loadavg1: cpu.and_then(|c| c.load.as_ref().map(|l| l.avg1)),
    }
}
fn supporting_qualifiers(cpu: Option<&CpuProcessObservation>) -> Vec<Qualifier> {
    let mut result = Vec::new();
    if let Some(cpu) = cpu {
        if cpu.host.utilization_fraction >= 0.90 {
            result.push(Qualifier { kind: "high_utilization_context", message: "Host CPU utilization was at least 90%; this is supporting context, not the contention verdict." });
        }
        if cpu
            .load
            .as_ref()
            .is_some_and(|l| l.runnable_tasks > u64::from(cpu.host.cpu_count))
        {
            result.push(Qualifier { kind: "runnable_queue_context", message: "Runnable tasks exceeded logical CPU count; this is supporting context, not the contention verdict." });
        }
    } else {
        result.push(Qualifier { kind: "cpu_context_unavailable", message: "Host/process CPU context was unavailable; PSI alone determines the resource verdict." });
    }
    result
}
fn victims(cpu: &CpuProcessObservation, resource: Confidence) -> Vec<Victim> {
    let direct = match (
        cpu.schedstat_capability,
        cpu.elapsed >= Duration::from_secs(5),
    ) {
        (SchedstatCapability::Available, true) => Confidence::High,
        (SchedstatCapability::Available | SchedstatCapability::Partial, _) => Confidence::Medium,
        _ => Confidence::Low,
    };
    let confidence = direct.min(resource);
    let mut v: Vec<_> = cpu
        .scheduler_delay_candidates
        .iter()
        .filter(|x| x.runnable_wait_ns > 0)
        .map(|x| victim(x, confidence))
        .collect();
    v.sort_by(|a, b| {
        b.runnable_wait_ns
            .cmp(&a.runnable_wait_ns)
            .then_with(|| a.key.cmp(&b.key))
    });
    v.truncate(5);
    v
}
fn victim(x: &ProcessSchedulerDelayInterval, confidence: Confidence) -> Victim {
    Victim {
        key: x.key,
        name: x.name.clone(),
        runnable_wait_ns: x.runnable_wait_ns,
        runnable_delay_fraction: x.runnable_delay_fraction,
        stable_task_count: x.task_count,
        confidence,
        label: "observed_runnable_delay_victim_candidate",
    }
}
fn suspects(
    cpu: &CpuProcessObservation,
    resource: Confidence,
    qualifiers: &mut Vec<Qualifier>,
) -> Vec<Suspect> {
    let process_partial = process_coverage_partial(cpu);
    let confidence = if process_partial {
        Confidence::Low
    } else {
        resource.min(Confidence::Medium)
    };
    let mut s: Vec<_> = cpu
        .processes
        .iter()
        .filter(|x| x.cpu_fraction_of_one >= SUSPECT_MIN_FRACTION)
        .map(|x| Suspect {
            key: x.key,
            name: x.name.clone(),
            cpu_fraction_of_one: x.cpu_fraction_of_one,
            cpu_ticks: x.cpu_ticks,
            confidence,
            label: "concurrent_cpu_consumer",
        })
        .collect();
    s.sort_by(|a, b| {
        b.cpu_fraction_of_one
            .total_cmp(&a.cpu_fraction_of_one)
            .then_with(|| a.key.cmp(&b.key))
    });
    let non_unique = s.first().zip(s.get(1)).is_some_and(|(first, second)| {
        second.cpu_fraction_of_one >= first.cpu_fraction_of_one * 0.90
    });
    let unique_leader = !non_unique && !process_partial && cpu.host.utilization_fraction >= 0.90;
    if let Some(first) = s.first_mut() {
        if unique_leader {
            first.label = "leading_concurrent_cpu_consumer";
        }
        if non_unique {
            first.label = "concurrent_cpu_consumer";
            first.confidence = Confidence::Low;
            qualifiers.push(Qualifier {
                kind: "non_unique_attribution",
                message: "Leading CPU consumers were within 10%; attribution is non-unique.",
            });
        }
    }
    if non_unique {
        let leader = s[0].cpu_fraction_of_one;
        for suspect in &mut s {
            if suspect.cpu_fraction_of_one >= leader * 0.90 {
                suspect.confidence = Confidence::Low;
            }
        }
    }
    if !s.is_empty() {
        qualifiers.push(Qualifier { kind:"same_window_correlation", message:"Suspects consumed CPU in the same window; this correlation does not prove causality." });
    }
    s.truncate(3);
    s
}
fn process_coverage_partial(cpu: &CpuProcessObservation) -> bool {
    let issues = &cpu.collection_issues;
    cpu::process_capability(issues) != cpu::CollectorCapability::Available
        || issues.appeared != 0
        || issues.exited != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cgroup::{CgroupCollectionIssues, CgroupInterval, CgroupPsiIntervalState};
    use crate::cpu::{
        HostCpuInterval, LoadAverageAvailability, ProcessCollectionIssues, ProcessCpuInterval,
        SchedstatCollectionIssues,
    };
    use crate::io::{
        DiskstatsInterval, DiskstatsIntervalIssues, ProcessIoCollectionIssues, ProcessIoInterval,
    };
    use crate::memory::{MeminfoRaw, VmstatIntervalIssues};
    use crate::psi::{
        CpuPsiInterval, CpuPsiRaw, IoPsiInterval, IoPsiLine, IoPsiLineInterval, IoPsiRaw,
        MemoryPsiInterval, MemoryPsiLine, MemoryPsiLineInterval, MemoryPsiRaw,
    };
    use serde::Deserialize;
    use std::collections::BTreeMap;

    fn cgroup_observation(
        some_us: Option<u64>,
        elapsed: Duration,
        state: CgroupPsiIntervalState,
    ) -> CgroupObservation {
        let psi = CgroupResource {
            state: CgroupFileState::Available,
            value: Some(CgroupPsiInterval {
                elapsed: Some(elapsed),
                some_total_usec: some_us,
                full_total_usec: None,
                state,
            }),
        };
        CgroupObservation {
            elapsed,
            members: vec![],
            issues: CgroupCollectionIssues::default(),
            groups: vec![CgroupInterval {
                path: "/demo.service".into(),
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
                cpu_pressure: psi,
                memory_pressure: CgroupResource {
                    state: CgroupFileState::Missing,
                    value: None,
                },
                io_pressure: CgroupResource {
                    state: CgroupFileState::Missing,
                    value: None,
                },
                systemd_unit_candidate: Some("demo.service".into()),
            }],
        }
    }

    fn cgroup_psi(
        some_us: Option<u64>,
        elapsed: Duration,
        state: CgroupPsiIntervalState,
    ) -> CgroupResource<CgroupPsiInterval> {
        CgroupResource {
            state: if some_us.is_some() {
                CgroupFileState::Available
            } else {
                CgroupFileState::Missing
            },
            value: some_us.map(|some_total_usec| CgroupPsiInterval {
                elapsed: Some(elapsed),
                some_total_usec: Some(some_total_usec),
                full_total_usec: None,
                state,
            }),
        }
    }

    fn missing_cgroup_resource<T>() -> CgroupResource<T> {
        CgroupResource {
            state: CgroupFileState::Missing,
            value: None,
        }
    }

    fn cgroup_events(high: Option<u64>, max: Option<u64>) -> CgroupResource<CgroupMemoryEventsRaw> {
        match (high, max) {
            (None, None) => missing_cgroup_resource(),
            _ => CgroupResource {
                state: CgroupFileState::Available,
                value: Some(CgroupMemoryEventsRaw {
                    low: Some(0),
                    high,
                    max,
                    oom: Some(0),
                    oom_kill: Some(0),
                    oom_group_kill: Some(0),
                }),
            },
        }
    }

    fn cgroup_stat(
        pgscan_direct: Option<u64>,
        pgsteal_direct: Option<u64>,
        pswpin: Option<u64>,
        pswpout: Option<u64>,
    ) -> CgroupResource<CgroupMemoryStatRaw> {
        if pgscan_direct.is_none()
            && pgsteal_direct.is_none()
            && pswpin.is_none()
            && pswpout.is_none()
        {
            return missing_cgroup_resource();
        }
        CgroupResource {
            state: CgroupFileState::Available,
            value: Some(CgroupMemoryStatRaw {
                pgscan_direct,
                pgsteal_direct,
                pswpin,
                pswpout,
            }),
        }
    }

    fn scoped_memory_io_group(
        path: &str,
        memory_some_us: Option<u64>,
        io_some_us: Option<u64>,
        cpu_some_us: Option<u64>,
        events: CgroupResource<CgroupMemoryEventsRaw>,
        elapsed: Duration,
    ) -> CgroupInterval {
        CgroupInterval {
            path: path.into(),
            cpu: missing_cgroup_resource(),
            memory_current_end: missing_cgroup_resource(),
            memory_events: events,
            memory_stat: missing_cgroup_resource(),
            io: missing_cgroup_resource(),
            cpu_pressure: cgroup_psi(cpu_some_us, elapsed, CgroupPsiIntervalState::Available),
            memory_pressure: cgroup_psi(memory_some_us, elapsed, CgroupPsiIntervalState::Available),
            io_pressure: cgroup_psi(io_some_us, elapsed, CgroupPsiIntervalState::Available),
            systemd_unit_candidate: None,
        }
    }

    fn with_cgroup_stat(
        mut group: CgroupInterval,
        stat: CgroupResource<CgroupMemoryStatRaw>,
    ) -> CgroupInterval {
        group.memory_stat = stat;
        group
    }

    fn with_memory_full(mut group: CgroupInterval, full_us: Option<u64>) -> CgroupInterval {
        if let Some(psi) = group.memory_pressure.value.as_mut() {
            psi.full_total_usec = full_us;
        }
        group
    }

    fn scoped_memory_io_observation(
        groups: Vec<CgroupInterval>,
        elapsed: Duration,
    ) -> CgroupObservation {
        CgroupObservation {
            elapsed,
            members: vec![],
            issues: CgroupCollectionIssues::default(),
            groups,
        }
    }

    fn cgroup_chains_from(observation: &CgroupObservation) -> Vec<EvidenceChain> {
        analyze_evidence_chains(None, None, &analyze_cgroups(Some(observation)).findings)
    }

    #[test]
    fn cgroup_pressure_is_scoped_and_never_a_host_causal_claim() {
        let observation = cgroup_observation(
            Some(100_000),
            Duration::from_secs(1),
            CgroupPsiIntervalState::Available,
        );
        let finding = &analyze_cgroups(Some(&observation)).findings[0];
        assert_eq!(finding.kind, CgroupAssessmentKind::Pressure);
        assert_eq!(finding.severity, Severity::Moderate);
        assert_eq!(
            finding.systemd_unit_candidate.as_deref(),
            Some("demo.service")
        );
        assert!(
            finding
                .qualifiers
                .iter()
                .any(|q| q.kind == "cgroup_scoped_evidence")
        );
        assert!(
            finding
                .qualifiers
                .iter()
                .any(|q| q.kind == "systemd_unit_candidate")
        );
        assert!(finding.qualifiers.iter().any(|q| {
            q.message
                .contains("does not establish that this cgroup caused host pressure")
        }));
    }

    #[test]
    fn cgroup_short_or_invalid_some_has_no_pressure_verdict() {
        let short = cgroup_observation(
            Some(5_000),
            Duration::from_millis(500),
            CgroupPsiIntervalState::Available,
        );
        assert_eq!(
            analyze_cgroups(Some(&short)).findings[0].kind,
            CgroupAssessmentKind::InsufficientObservation
        );
        let invalid = cgroup_observation(
            None,
            Duration::from_secs(1),
            CgroupPsiIntervalState::SomeExceedsElapsed,
        );
        assert_eq!(
            analyze_cgroups(Some(&invalid)).findings[0].kind,
            CgroupAssessmentKind::InsufficientObservation
        );
    }

    fn with_cgroup_cpu(
        mut group: CgroupInterval,
        cpu: CgroupResource<CgroupCpuInterval>,
    ) -> CgroupInterval {
        group.cpu = cpu;
        group
    }

    fn cgroup_cpu(
        throttled_usec: Option<u64>,
        nr_throttled: Option<u64>,
    ) -> CgroupResource<CgroupCpuInterval> {
        CgroupResource {
            state: CgroupFileState::Available,
            value: Some(CgroupCpuInterval {
                usage_usec: Some(1_000_000),
                user_usec: None,
                system_usec: None,
                nr_periods: Some(100),
                nr_throttled,
                throttled_usec,
            }),
        }
    }

    fn cpu_finding(observation: &CgroupObservation) -> CgroupFinding {
        analyze_cgroups(Some(observation))
            .findings
            .into_iter()
            .find(|finding| finding.resource == CgroupResourceKind::Cpu)
            .expect("cpu finding")
    }

    fn memory_finding(observation: &CgroupObservation) -> CgroupFinding {
        analyze_cgroups(Some(observation))
            .findings
            .into_iter()
            .find(|finding| finding.resource == CgroupResourceKind::Memory)
            .expect("memory finding")
    }

    #[test]
    fn cgroup_memory_stat_labels_reclaim_or_swap_without_creating_pressure() {
        let elapsed = Duration::from_secs(10);
        let reclaim = scoped_memory_io_observation(
            vec![with_cgroup_stat(
                scoped_memory_io_group(
                    "/workload.service",
                    Some(800_000),
                    None,
                    None,
                    cgroup_events(None, None),
                    elapsed,
                ),
                cgroup_stat(Some(12), Some(8), Some(0), Some(0)),
            )],
            elapsed,
        );
        let reclaim_finding = memory_finding(&reclaim);
        assert_eq!(reclaim_finding.kind, CgroupAssessmentKind::Pressure);
        assert_eq!(reclaim_finding.mechanism, Some(CgroupMechanism::Reclaim));
        assert_eq!(reclaim_finding.mechanism_confidence, Some(Confidence::Low));
        assert!(reclaim_finding.summary.contains("reclaim pressure"));
        assert!(
            reclaim_finding.qualifiers.iter().any(
                |qualifier| qualifier.kind == "cgroup_memory_mechanism_same_window_correlation"
            )
        );

        let swap = scoped_memory_io_observation(
            vec![with_cgroup_stat(
                scoped_memory_io_group(
                    "/workload.service",
                    Some(800_000),
                    None,
                    None,
                    cgroup_events(None, None),
                    elapsed,
                ),
                cgroup_stat(Some(12), Some(8), Some(5), Some(2)),
            )],
            elapsed,
        );
        let swap_finding = memory_finding(&swap);
        assert_eq!(swap_finding.mechanism, Some(CgroupMechanism::Swap));
        assert!(swap_finding.summary.contains("swap pressure"));
        assert!(!swap_finding.summary.to_lowercase().contains("cause"));

        let unlabeled = scoped_memory_io_observation(
            vec![scoped_memory_io_group(
                "/workload.service",
                Some(800_000),
                None,
                None,
                cgroup_events(Some(3), Some(0)),
                elapsed,
            )],
            elapsed,
        );
        let unlabeled_finding = memory_finding(&unlabeled);
        assert_eq!(unlabeled_finding.kind, CgroupAssessmentKind::Pressure);
        assert_eq!(unlabeled_finding.mechanism, None);

        let scan_only = scoped_memory_io_observation(
            vec![with_cgroup_stat(
                scoped_memory_io_group(
                    "/workload.service",
                    Some(800_000),
                    None,
                    None,
                    cgroup_events(None, None),
                    elapsed,
                ),
                cgroup_stat(Some(12), Some(0), Some(0), Some(0)),
            )],
            elapsed,
        );
        let scan_only_finding = memory_finding(&scan_only);
        assert_eq!(scan_only_finding.kind, CgroupAssessmentKind::Pressure);
        assert_eq!(scan_only_finding.mechanism, None);

        let healthy = scoped_memory_io_observation(
            vec![with_cgroup_stat(
                scoped_memory_io_group(
                    "/workload.service",
                    Some(5_000),
                    None,
                    None,
                    cgroup_events(None, None),
                    elapsed,
                ),
                cgroup_stat(Some(12), Some(8), Some(5), Some(2)),
            )],
            elapsed,
        );
        assert!(
            analyze_cgroups(Some(&healthy))
                .findings
                .iter()
                .all(|finding| finding.kind != CgroupAssessmentKind::Pressure),
            "page counters must not create a pressure verdict"
        );
    }

    #[test]
    fn cgroup_memory_stat_labels_possible_thrashing_without_creating_pressure() {
        let elapsed = Duration::from_secs(5);
        let some_us = 1_000_000; // 20% over 5s: high severity
        let full_us = 100_000; // 2% valid full
        let material = 5_120;
        let thrash = scoped_memory_io_observation(
            vec![with_memory_full(
                with_cgroup_stat(
                    scoped_memory_io_group(
                        "/workload.service",
                        Some(some_us),
                        None,
                        None,
                        cgroup_events(None, None),
                        elapsed,
                    ),
                    cgroup_stat(
                        Some(material),
                        Some(material),
                        Some(material),
                        Some(material),
                    ),
                ),
                Some(full_us),
            )],
            elapsed,
        );
        let finding = memory_finding(&thrash);
        assert_eq!(finding.kind, CgroupAssessmentKind::Pressure);
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.mechanism, Some(CgroupMechanism::PossibleThrashing));
        assert_eq!(finding.mechanism_confidence, Some(Confidence::Medium));
        assert!(finding.summary.contains("possible thrashing"));
        assert!(!finding.summary.to_lowercase().contains("cause"));
        assert!(
            finding
                .qualifiers
                .iter()
                .any(|qualifier| qualifier.kind == "cgroup_possible_thrashing_heuristic")
        );

        let slower = scoped_memory_io_observation(
            vec![with_memory_full(
                with_cgroup_stat(
                    scoped_memory_io_group(
                        "/workload.service",
                        Some(some_us),
                        None,
                        None,
                        cgroup_events(None, None),
                        elapsed,
                    ),
                    cgroup_stat(
                        Some(material),
                        Some(material),
                        Some(material),
                        Some(material),
                    ),
                ),
                Some(full_us),
            )],
            Duration::from_secs(10),
        );
        assert_eq!(
            memory_finding(&slower).mechanism,
            Some(CgroupMechanism::Swap),
            "page rates must use the cgroup observation interval, not the PSI interval"
        );

        let short = scoped_memory_io_observation(
            vec![with_memory_full(
                with_cgroup_stat(
                    scoped_memory_io_group(
                        "/workload.service",
                        Some(400_000),
                        None,
                        None,
                        cgroup_events(None, None),
                        Duration::from_secs(2),
                    ),
                    cgroup_stat(
                        Some(material),
                        Some(material),
                        Some(material),
                        Some(material),
                    ),
                ),
                Some(40_000),
            )],
            Duration::from_secs(2),
        );
        assert_eq!(
            memory_finding(&short).mechanism,
            Some(CgroupMechanism::Swap),
            "a PSI window shorter than 5s must not receive a scoped thrashing label"
        );

        let moderate = scoped_memory_io_observation(
            vec![with_memory_full(
                with_cgroup_stat(
                    scoped_memory_io_group(
                        "/workload.service",
                        Some(800_000),
                        None,
                        None,
                        cgroup_events(None, None),
                        Duration::from_secs(10),
                    ),
                    cgroup_stat(Some(10_240), Some(10_240), Some(10_240), Some(10_240)),
                ),
                Some(200_000),
            )],
            Duration::from_secs(10),
        );
        assert_eq!(
            memory_finding(&moderate).mechanism,
            Some(CgroupMechanism::Swap),
            "moderate some must not be labeled possible thrashing"
        );

        let missing_full = scoped_memory_io_observation(
            vec![with_cgroup_stat(
                scoped_memory_io_group(
                    "/workload.service",
                    Some(some_us),
                    None,
                    None,
                    cgroup_events(None, None),
                    elapsed,
                ),
                cgroup_stat(
                    Some(material),
                    Some(material),
                    Some(material),
                    Some(material),
                ),
            )],
            elapsed,
        );
        assert_eq!(
            memory_finding(&missing_full).mechanism,
            Some(CgroupMechanism::Swap),
            "missing full must not be labeled possible thrashing"
        );

        let mut invalid_full = scoped_memory_io_observation(
            vec![with_memory_full(
                with_cgroup_stat(
                    scoped_memory_io_group(
                        "/workload.service",
                        Some(some_us),
                        None,
                        None,
                        cgroup_events(None, None),
                        elapsed,
                    ),
                    cgroup_stat(
                        Some(material),
                        Some(material),
                        Some(material),
                        Some(material),
                    ),
                ),
                Some(full_us),
            )],
            elapsed,
        );
        invalid_full.groups[0]
            .memory_pressure
            .value
            .as_mut()
            .unwrap()
            .state = CgroupPsiIntervalState::FullExceedsSome;
        assert_eq!(
            memory_finding(&invalid_full).mechanism,
            Some(CgroupMechanism::Swap),
            "invalid full must not be labeled possible thrashing"
        );

        let scan_only = scoped_memory_io_observation(
            vec![with_memory_full(
                with_cgroup_stat(
                    scoped_memory_io_group(
                        "/workload.service",
                        Some(some_us),
                        None,
                        None,
                        cgroup_events(None, None),
                        elapsed,
                    ),
                    cgroup_stat(Some(material), Some(0), Some(material), Some(material)),
                ),
                Some(full_us),
            )],
            elapsed,
        );
        assert_eq!(
            memory_finding(&scan_only).mechanism,
            Some(CgroupMechanism::Swap),
            "scan without steal is not scoped possible thrashing"
        );

        let healthy = scoped_memory_io_observation(
            vec![with_memory_full(
                with_cgroup_stat(
                    scoped_memory_io_group(
                        "/workload.service",
                        Some(5_000),
                        None,
                        None,
                        cgroup_events(None, None),
                        elapsed,
                    ),
                    cgroup_stat(
                        Some(material),
                        Some(material),
                        Some(material),
                        Some(material),
                    ),
                ),
                Some(full_us),
            )],
            elapsed,
        );
        assert!(
            analyze_cgroups(Some(&healthy))
                .findings
                .iter()
                .all(|finding| finding.kind != CgroupAssessmentKind::Pressure),
            "page counters and full PSI must not create a pressure verdict"
        );
    }

    #[test]
    fn cgroup_cpu_stat_labels_quota_throttle_without_creating_pressure() {
        let elapsed = Duration::from_secs(10);
        let throttled = scoped_memory_io_observation(
            vec![with_cgroup_cpu(
                scoped_memory_io_group(
                    "/workload.service",
                    None,
                    None,
                    Some(800_000),
                    cgroup_events(None, None),
                    elapsed,
                ),
                cgroup_cpu(Some(250_000), Some(4)),
            )],
            elapsed,
        );
        let finding = cpu_finding(&throttled);
        assert_eq!(finding.kind, CgroupAssessmentKind::Pressure);
        assert_eq!(finding.mechanism, Some(CgroupMechanism::CpuQuotaThrottle));
        assert_eq!(finding.mechanism_confidence, Some(Confidence::Low));
        assert!(finding.summary.contains("quota-throttle pressure"));
        assert!(!finding.summary.to_lowercase().contains("cause"));
        assert!(
            finding
                .qualifiers
                .iter()
                .any(|qualifier| qualifier.kind
                    == "cgroup_cpu_quota_throttle_same_window_correlation")
        );

        let count_only = scoped_memory_io_observation(
            vec![with_cgroup_cpu(
                scoped_memory_io_group(
                    "/workload.service",
                    None,
                    None,
                    Some(800_000),
                    cgroup_events(None, None),
                    elapsed,
                ),
                cgroup_cpu(Some(0), Some(4)),
            )],
            elapsed,
        );
        let unlabeled = cpu_finding(&count_only);
        assert_eq!(unlabeled.kind, CgroupAssessmentKind::Pressure);
        assert_eq!(unlabeled.mechanism, None);

        let healthy = scoped_memory_io_observation(
            vec![with_cgroup_cpu(
                scoped_memory_io_group(
                    "/workload.service",
                    None,
                    None,
                    Some(5_000),
                    cgroup_events(None, None),
                    elapsed,
                ),
                cgroup_cpu(Some(250_000), Some(4)),
            )],
            elapsed,
        );
        assert!(
            analyze_cgroups(Some(&healthy))
                .findings
                .iter()
                .all(|finding| finding.kind != CgroupAssessmentKind::Pressure),
            "cpu.stat throttle counters must not create a pressure verdict"
        );
    }

    fn psi(fraction: f64, elapsed: Duration) -> CpuPsiObservation {
        CpuPsiObservation {
            requested: elapsed,
            interval: CpuPsiInterval {
                elapsed,
                total_delta_us: (fraction * elapsed.as_micros() as f64) as u64,
                some_fraction: fraction,
            },
            start: CpuPsiRaw {
                avg10_percent: 0.0,
                avg60_percent: 0.0,
                avg300_percent: 0.0,
                total_us: 0,
            },
            end: CpuPsiRaw {
                avg10_percent: 0.0,
                avg60_percent: 0.0,
                avg300_percent: 0.0,
                total_us: 1,
            },
        }
    }
    fn cpu(
        processes: Vec<ProcessCpuInterval>,
        delays: Vec<ProcessSchedulerDelayInterval>,
    ) -> CpuProcessObservation {
        CpuProcessObservation {
            elapsed: Duration::from_secs(10),
            clock_ticks_per_second: 100,
            host: HostCpuInterval {
                total_ticks: 1000,
                busy_ticks: 1000,
                idle_ticks: 0,
                utilization_fraction: 1.0,
                cpu_count: 8,
            },
            load: None,
            load_availability: LoadAverageAvailability::Unreadable,
            processes,
            process_resource_evidence: Vec::new(),
            collection_issues: ProcessCollectionIssues::default(),
            scheduler_delay_candidates: delays,
            schedstat_collection_issues: SchedstatCollectionIssues::default(),
            task_stat_collection_issues: crate::cpu::TaskStatCollectionIssues::default(),
            schedstat_capability: SchedstatCapability::Available,
            taskstats: Vec::new(),
            taskstats_collection_issues: Default::default(),
            taskstats_capability: Default::default(),
            delay_accounting: Default::default(),
        }
    }
    fn key(pid: u32) -> ProcessKey {
        ProcessKey {
            pid,
            start_time_ticks: 1,
        }
    }
    fn resource(
        key: ProcessKey,
        rss: Option<u64>,
        major: Option<u64>,
        block: Option<u64>,
    ) -> ProcessResourceInterval {
        ProcessResourceInterval {
            key,
            name: format!("p{}", key.pid),
            leader_rss_bytes: Some(1),
            rss_growth_bytes: rss,
            minor_faults: Some(0),
            major_faults: major,
            stable_task_count: 1,
            block_io_delay_ticks: block,
        }
    }

    #[test]
    fn cgroup_roles_use_full_stable_descendant_membership_and_keep_host_rankings_independent() {
        let mut cgroup = cgroup_observation(
            Some(200_000),
            Duration::from_secs(1),
            CgroupPsiIntervalState::Available,
        );
        cgroup.groups[0].path = "/workload".into();
        cgroup.members = vec![
            crate::cgroup::CgroupProcessMember {
                key: key(1),
                name: "outside".into(),
                cgroup_path: "/other".into(),
            },
            crate::cgroup::CgroupProcessMember {
                key: key(2),
                name: "direct".into(),
                cgroup_path: "/workload".into(),
            },
            crate::cgroup::CgroupProcessMember {
                key: key(3),
                name: "child".into(),
                cgroup_path: "/workload/child".into(),
            },
            crate::cgroup::CgroupProcessMember {
                key: key(4),
                name: "prefix".into(),
                cgroup_path: "/workload-other".into(),
            },
            crate::cgroup::CgroupProcessMember {
                key: key(6),
                name: "outside-host-top-five".into(),
                cgroup_path: "/workload".into(),
            },
        ];
        let cpu = cpu(
            vec![
                ProcessCpuInterval {
                    key: key(1),
                    name: "outside".into(),
                    state: 'R',
                    cpu_ticks: 90,
                    cpu_fraction_of_one: 0.9,
                },
                ProcessCpuInterval {
                    key: key(2),
                    name: "direct".into(),
                    state: 'R',
                    cpu_ticks: 30,
                    cpu_fraction_of_one: 0.3,
                },
                ProcessCpuInterval {
                    key: key(3),
                    name: "child".into(),
                    state: 'R',
                    cpu_ticks: 40,
                    cpu_fraction_of_one: 0.4,
                },
                ProcessCpuInterval {
                    key: key(4),
                    name: "prefix".into(),
                    state: 'R',
                    cpu_ticks: 80,
                    cpu_fraction_of_one: 0.8,
                },
                ProcessCpuInterval {
                    key: key(5),
                    name: "host-five".into(),
                    state: 'R',
                    cpu_ticks: 70,
                    cpu_fraction_of_one: 0.7,
                },
                ProcessCpuInterval {
                    key: key(6),
                    name: "outside-host-top-five".into(),
                    state: 'R',
                    cpu_ticks: 30,
                    cpu_fraction_of_one: 0.3,
                },
            ],
            vec![],
        );
        let host = host_process_scope(Some(&cpu), None, Some(Confidence::Medium), None, None);
        let scopes = cgroup_process_scopes(Some(&cgroup), Some(&cpu), None);
        assert_eq!(scopes.len(), 1);
        let ProcessScopeKind::Cgroup { path } = &scopes[0].scope else {
            panic!("expected cgroup scope")
        };
        assert_eq!(path, "/workload");
        let suspects = scopes[0]
            .roles
            .iter()
            .find(|role| role.role == ProcessRole::CpuSuspect)
            .unwrap();
        assert_eq!(
            suspects
                .candidates
                .iter()
                .map(|candidate| candidate.key.pid)
                .collect::<Vec<_>>(),
            vec![3, 2, 6]
        );
        assert!(
            host.roles
                .iter()
                .find(|role| role.role == ProcessRole::CpuSuspect)
                .unwrap()
                .candidates
                .iter()
                .any(|candidate| candidate.key == key(1))
        );
        assert!(
            host.roles
                .iter()
                .find(|role| role.role == ProcessRole::CpuSuspect)
                .unwrap()
                .candidates
                .iter()
                .all(|candidate| candidate.key != key(6))
        );
        assert!(
            scopes[0]
                .roles
                .iter()
                .filter(|role| role.role != ProcessRole::CpuVictim
                    && role.role != ProcessRole::CpuSuspect)
                .all(|role| role.availability == ProcessCandidateAvailability::NotAssessed)
        );

        cgroup.issues.process_limit_reached = true;
        let partial = cgroup_process_scopes(Some(&cgroup), Some(&cpu), None);
        assert_eq!(
            partial[0]
                .roles
                .iter()
                .find(|role| role.role == ProcessRole::CpuSuspect)
                .unwrap()
                .completeness,
            ProcessRoleCompleteness::Partial
        );
        let unavailable = cgroup_process_scopes(Some(&cgroup), None, None);
        let victim = unavailable[0]
            .roles
            .iter()
            .find(|role| role.role == ProcessRole::CpuVictim)
            .unwrap();
        assert_eq!(victim.completeness, ProcessRoleCompleteness::Unavailable);
        assert_eq!(
            victim.availability,
            ProcessCandidateAvailability::UnavailableOrIncomplete
        );

        cgroup.issues = CgroupCollectionIssues::default();
        let child = cgroup.groups[0].clone();
        cgroup.groups[0].path = "/".into();
        cgroup.groups.push(child);
        let overlapping = cgroup_process_scopes(Some(&cgroup), Some(&cpu), None);
        assert_eq!(overlapping.len(), 2);
        for scope in &overlapping {
            let suspects = scope
                .roles
                .iter()
                .find(|role| role.role == ProcessRole::CpuSuspect)
                .unwrap();
            assert!(
                suspects
                    .candidates
                    .iter()
                    .any(|candidate| candidate.key == key(2))
            );
        }
    }
    fn memory_suspect_completeness(
        mut observation: CpuProcessObservation,
    ) -> ProcessRoleCompleteness {
        observation.process_resource_evidence = vec![resource(key(1), Some(0), Some(0), Some(0))];
        host_process_scope(Some(&observation), None, None, Some(Confidence::Low), None)
            .roles
            .into_iter()
            .find(|role| role.role == ProcessRole::MemorySuspect)
            .unwrap()
            .completeness
    }

    #[test]
    fn cgroup_scope_builds_all_six_roles_with_shared_cap_and_tie_rules() {
        let elapsed = Duration::from_secs(10);
        let mut cgroup =
            cgroup_observation(Some(2_000_000), elapsed, CgroupPsiIntervalState::Available);
        cgroup.groups[0].memory_pressure =
            cgroup_psi(Some(2_000_000), elapsed, CgroupPsiIntervalState::Available);
        cgroup.groups[0].io_pressure =
            cgroup_psi(Some(2_000_000), elapsed, CgroupPsiIntervalState::Available);
        cgroup.members = (1..=6)
            .map(|pid| crate::cgroup::CgroupProcessMember {
                key: key(pid),
                name: format!("p{pid}"),
                cgroup_path: "/demo.service".into(),
            })
            .collect();
        let mut cpu = cpu(
            (1..=6)
                .map(|pid| ProcessCpuInterval {
                    key: key(pid),
                    name: format!("p{pid}"),
                    state: 'R',
                    cpu_ticks: 25,
                    cpu_fraction_of_one: 0.25,
                })
                .collect(),
            vec![ProcessSchedulerDelayInterval {
                key: key(1),
                name: "p1".into(),
                task_count: 1,
                running_ns: 0,
                runnable_wait_ns: 10,
                timeslices: 1,
                runnable_delay_fraction: 0.0,
            }],
        );
        cpu.process_resource_evidence = (1..=6)
            .map(|pid| resource(key(pid), Some(1), Some(1), Some(1)))
            .collect();
        cpu.taskstats_capability = TaskstatsCapability::Available;
        cpu.delay_accounting = DelayAccountingState::Enabled;
        cpu.taskstats = vec![crate::taskstats::TaskstatsInterval {
            key: key(1),
            min_uapi_version: 13,
            field_support: crate::taskstats::TaskstatsFieldSupport {
                cpu_delay: true,
                block_io_delay: true,
                swapin_delay: true,
                reclaim_delay: true,
                thrashing_delay: true,
                compaction_delay: true,
                write_protect_copy_delay: true,
            },
            cpu_delay_ns: Some(1),
            block_io_delay_ns: Some(1),
            swapin_delay_ns: Some(1),
            reclaim_delay_ns: None,
            thrashing_delay_ns: None,
            compaction_delay_ns: None,
            write_protect_copy_delay_ns: None,
        }];
        let process_io = ProcessIoObservation {
            elapsed,
            capability: IoCapability::Available,
            processes: vec![ProcessIoInterval {
                key: key(1),
                name: "p1".into(),
                read_bytes: Some(1),
                write_bytes: None,
                cancelled_write_bytes: None,
                rchar: None,
                wchar: None,
            }],
            issues: ProcessIoCollectionIssues::default(),
            regressed: vec![],
        };
        let scope = cgroup_process_scopes(Some(&cgroup), Some(&cpu), Some(&process_io))
            .pop()
            .unwrap();
        for role in [
            ProcessRole::CpuVictim,
            ProcessRole::CpuSuspect,
            ProcessRole::MemoryVictim,
            ProcessRole::MemorySuspect,
            ProcessRole::IoVictim,
            ProcessRole::IoSuspect,
        ] {
            let list = scope.roles.iter().find(|list| list.role == role).unwrap();
            assert!(!list.candidates.is_empty(), "{role:?}");
        }
        let suspects = scope
            .roles
            .iter()
            .find(|list| list.role == ProcessRole::MemorySuspect)
            .unwrap();
        assert_eq!(suspects.candidates.len(), 5);
        assert_eq!(
            suspects
                .candidates
                .iter()
                .map(|candidate| candidate.key.pid)
                .collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 5]
        );
    }
    macro_rules! partial_window_case {
        ($name:ident, $mutate:expr) => {
            #[test]
            fn $name() {
                let mut observation = cpu(vec![], vec![]);
                $mutate(&mut observation);
                assert_eq!(
                    memory_suspect_completeness(observation),
                    ProcessRoleCompleteness::Partial
                );
            }
        };
    }
    partial_window_case!(
        rss_enumeration_error_is_partial,
        |cpu: &mut CpuProcessObservation| cpu.collection_issues.enumeration_errors = 1
    );
    partial_window_case!(
        rss_disappearance_is_partial,
        |cpu: &mut CpuProcessObservation| cpu.collection_issues.disappeared = 1
    );
    partial_window_case!(
        rss_permission_is_partial,
        |cpu: &mut CpuProcessObservation| cpu.collection_issues.permission_denied = 1
    );
    partial_window_case!(
        rss_unreadable_is_partial,
        |cpu: &mut CpuProcessObservation| cpu.collection_issues.unreadable = 1
    );
    partial_window_case!(
        rss_malformed_is_partial,
        |cpu: &mut CpuProcessObservation| cpu.collection_issues.malformed = 1
    );
    partial_window_case!(
        rss_appeared_is_partial,
        |cpu: &mut CpuProcessObservation| cpu.collection_issues.appeared = 1
    );
    partial_window_case!(rss_exited_is_partial, |cpu: &mut CpuProcessObservation| {
        cpu.collection_issues.exited = 1
    });
    #[test]
    fn fault_regression_does_not_weaken_rss_growth_or_taskstats_roles() {
        let process = key(1);
        let mut observation = cpu(vec![], vec![]);
        observation.schedstat_capability = SchedstatCapability::Unsupported;
        observation.process_resource_evidence = vec![resource(process, Some(1), None, Some(0))];
        observation.collection_issues.resource_counter_regressed = 1;
        observation.taskstats_capability = TaskstatsCapability::Available;
        observation.delay_accounting = DelayAccountingState::Enabled;
        observation.taskstats = vec![crate::taskstats::TaskstatsInterval {
            key: process,
            min_uapi_version: 13,
            field_support: crate::taskstats::TaskstatsFieldSupport {
                cpu_delay: true,
                block_io_delay: true,
                swapin_delay: true,
                reclaim_delay: true,
                thrashing_delay: true,
                compaction_delay: true,
                write_protect_copy_delay: true,
            },
            cpu_delay_ns: Some(0),
            block_io_delay_ns: Some(0),
            swapin_delay_ns: Some(0),
            reclaim_delay_ns: Some(0),
            thrashing_delay_ns: Some(0),
            compaction_delay_ns: Some(0),
            write_protect_copy_delay_ns: Some(0),
        }];
        let scope = host_process_scope(
            Some(&observation),
            None,
            Some(Confidence::High),
            Some(Confidence::High),
            Some(Confidence::High),
        );
        for role in [
            ProcessRole::CpuVictim,
            ProcessRole::MemorySuspect,
            ProcessRole::IoVictim,
        ] {
            assert_eq!(
                scope
                    .roles
                    .iter()
                    .find(|list| list.role == role)
                    .unwrap()
                    .completeness,
                ProcessRoleCompleteness::Complete,
                "unrelated fault regression weakened {role:?}"
            );
        }
    }
    partial_window_case!(
        rss_overflow_is_partial,
        |cpu: &mut CpuProcessObservation| cpu.collection_issues.resource_value_overflow = 1
    );
    #[test]
    fn rss_cap_is_partial() {
        let mut observation = cpu(vec![], vec![]);
        observation.collection_issues.limit_reached = true;
        assert_eq!(
            memory_suspect_completeness(observation),
            ProcessRoleCompleteness::Partial
        );
    }
    #[test]
    fn scoped_roles_keep_positive_partial_taskstats_and_direct_cpu_first() {
        let first = key(1);
        let second = key(2);
        let mut observation = cpu(
            vec![
                ProcessCpuInterval {
                    key: first,
                    name: "one".into(),
                    state: 'R',
                    cpu_ticks: 25,
                    cpu_fraction_of_one: 0.25,
                },
                ProcessCpuInterval {
                    key: second,
                    name: "two".into(),
                    state: 'R',
                    cpu_ticks: 24,
                    cpu_fraction_of_one: 0.24,
                },
            ],
            vec![ProcessSchedulerDelayInterval {
                key: second,
                name: "two".into(),
                task_count: 1,
                running_ns: 0,
                runnable_wait_ns: 1,
                runnable_delay_fraction: 0.0,
                timeslices: 1,
            }],
        );
        observation.process_resource_evidence = vec![
            resource(first, Some(2), Some(3), Some(4)),
            resource(second, Some(0), Some(0), Some(0)),
        ];
        observation.taskstats_capability = TaskstatsCapability::Partial;
        observation.delay_accounting = DelayAccountingState::Unknown;
        observation
            .taskstats
            .push(crate::taskstats::TaskstatsInterval {
                key: first,
                min_uapi_version: 13,
                field_support: crate::taskstats::TaskstatsFieldSupport {
                    cpu_delay: true,
                    block_io_delay: true,
                    swapin_delay: true,
                    reclaim_delay: true,
                    thrashing_delay: true,
                    compaction_delay: true,
                    write_protect_copy_delay: true,
                },
                cpu_delay_ns: Some(100),
                block_io_delay_ns: Some(100),
                swapin_delay_ns: Some(99),
                reclaim_delay_ns: None,
                thrashing_delay_ns: None,
                compaction_delay_ns: None,
                write_protect_copy_delay_ns: None,
            });
        let scope = host_process_scope(
            Some(&observation),
            None,
            Some(Confidence::High),
            Some(Confidence::High),
            Some(Confidence::High),
        );
        let role = |role| scope.roles.iter().find(|list| list.role == role).unwrap();
        assert_eq!(
            role(ProcessRole::CpuVictim).candidates[0].key,
            second,
            "schedstat ranks before taskstats fallback"
        );
        assert_eq!(
            role(ProcessRole::CpuSuspect).candidates.len(),
            1,
            "25% is inclusive"
        );
        assert_eq!(role(ProcessRole::MemoryVictim).candidates[0].key, first);
        assert_eq!(
            role(ProcessRole::MemorySuspect).candidates[0].confidence,
            Confidence::Low
        );
        assert_eq!(role(ProcessRole::IoVictim).candidates[0].key, first);
        assert_eq!(
            role(ProcessRole::MemoryVictim).completeness,
            ProcessRoleCompleteness::Partial
        );
        assert_eq!(
            role(ProcessRole::IoSuspect).completeness,
            ProcessRoleCompleteness::Unavailable
        );
    }
    #[test]
    fn missing_telemetry_is_unavailable_and_static_or_decreasing_rss_is_not_a_suspect() {
        let absent = host_process_scope(
            None,
            None,
            Some(Confidence::Low),
            Some(Confidence::Low),
            Some(Confidence::Low),
        );
        assert!(
            absent
                .roles
                .iter()
                .all(|role| role.completeness == ProcessRoleCompleteness::Unavailable)
        );
        let mut observation = cpu(vec![], vec![]);
        observation.process_resource_evidence = vec![resource(key(1), Some(0), Some(0), Some(0))];
        let scope = host_process_scope(Some(&observation), None, None, Some(Confidence::Low), None);
        assert!(
            scope
                .roles
                .iter()
                .find(|role| role.role == ProcessRole::MemorySuspect)
                .unwrap()
                .candidates
                .is_empty()
        );
    }
    #[test]
    fn taskstats_only_io_victim_is_retained_without_procfs_key() {
        let mut observation = cpu(vec![], vec![]);
        observation.taskstats_capability = TaskstatsCapability::Partial;
        observation
            .taskstats
            .push(crate::taskstats::TaskstatsInterval {
                key: key(7),
                min_uapi_version: 1,
                field_support: crate::taskstats::TaskstatsFieldSupport {
                    block_io_delay: true,
                    ..Default::default()
                },
                cpu_delay_ns: None,
                block_io_delay_ns: Some(4),
                swapin_delay_ns: None,
                reclaim_delay_ns: None,
                thrashing_delay_ns: None,
                compaction_delay_ns: None,
                write_protect_copy_delay_ns: None,
            });
        let scope = host_process_scope(
            Some(&observation),
            None,
            None,
            None,
            Some(Confidence::Medium),
        );
        let io = scope
            .roles
            .iter()
            .find(|role| role.role == ProcessRole::IoVictim)
            .unwrap();
        assert_eq!(io.candidates[0].key, key(7));
        assert_eq!(io.completeness, ProcessRoleCompleteness::Partial);
    }
    #[test]
    fn missing_procfs_block_delay_cannot_complete_io_negative() {
        let mut observation = cpu(vec![], vec![]);
        observation.delay_accounting = DelayAccountingState::Enabled;
        observation.task_stat_collection_issues.tasks_read = 1;
        observation.process_resource_evidence = vec![resource(key(1), Some(0), Some(0), None)];
        let scope = host_process_scope(Some(&observation), None, None, None, Some(Confidence::Low));
        assert_eq!(
            scope
                .roles
                .iter()
                .find(|role| role.role == ProcessRole::IoVictim)
                .unwrap()
                .completeness,
            ProcessRoleCompleteness::Partial
        );
    }
    macro_rules! memory_version_completeness_case {
        ($name:ident, $support:expr, $expected:expr) => {
            #[test]
            fn $name() {
                let mut observation = cpu(vec![], vec![]);
                observation.process_resource_evidence =
                    vec![resource(key(1), Some(0), Some(0), Some(0))];
                observation.taskstats_capability = TaskstatsCapability::Available;
                observation.delay_accounting = DelayAccountingState::Enabled;
                observation
                    .taskstats
                    .push(crate::taskstats::TaskstatsInterval {
                        key: key(1),
                        min_uapi_version: 13,
                        field_support: $support,
                        cpu_delay_ns: Some(0),
                        block_io_delay_ns: Some(0),
                        swapin_delay_ns: Some(0),
                        reclaim_delay_ns: Some(0),
                        thrashing_delay_ns: Some(0),
                        compaction_delay_ns: Some(0),
                        write_protect_copy_delay_ns: Some(0),
                    });
                let scope =
                    host_process_scope(Some(&observation), None, None, Some(Confidence::Low), None);
                assert_eq!(
                    scope
                        .roles
                        .iter()
                        .find(|role| role.role == ProcessRole::MemoryVictim)
                        .unwrap()
                        .completeness,
                    $expected
                );
            }
        };
    }
    memory_version_completeness_case!(
        memory_version_one_is_partial,
        crate::taskstats::TaskstatsFieldSupport {
            swapin_delay: true,
            ..Default::default()
        },
        ProcessRoleCompleteness::Partial
    );
    memory_version_completeness_case!(
        memory_version_seven_is_partial,
        crate::taskstats::TaskstatsFieldSupport {
            swapin_delay: true,
            reclaim_delay: true,
            ..Default::default()
        },
        ProcessRoleCompleteness::Partial
    );
    memory_version_completeness_case!(
        memory_version_nine_is_partial,
        crate::taskstats::TaskstatsFieldSupport {
            swapin_delay: true,
            reclaim_delay: true,
            thrashing_delay: true,
            ..Default::default()
        },
        ProcessRoleCompleteness::Partial
    );
    memory_version_completeness_case!(
        memory_version_eleven_is_partial,
        crate::taskstats::TaskstatsFieldSupport {
            swapin_delay: true,
            reclaim_delay: true,
            thrashing_delay: true,
            compaction_delay: true,
            ..Default::default()
        },
        ProcessRoleCompleteness::Partial
    );
    memory_version_completeness_case!(
        memory_version_thirteen_is_complete,
        crate::taskstats::TaskstatsFieldSupport {
            swapin_delay: true,
            reclaim_delay: true,
            thrashing_delay: true,
            compaction_delay: true,
            write_protect_copy_delay: true,
            ..Default::default()
        },
        ProcessRoleCompleteness::Complete
    );
    #[test]
    fn boundaries_are_exact() {
        assert_eq!(severity_for_psi(0.009), Severity::None);
        assert_eq!(severity_for_psi(0.01), Severity::Low);
        assert_eq!(severity_for_psi(0.05), Severity::Moderate);
        assert_eq!(severity_for_psi(0.15), Severity::High);
        assert_eq!(severity_for_psi(0.30), Severity::Severe);
    }
    #[test]
    fn psi_alone_controls_negative_and_short_verdicts() {
        let busy = cpu(vec![], vec![]);
        assert_eq!(
            analyze_cpu(Some(&psi(0.005, Duration::from_secs(10))), Some(&busy)).findings[0].kind,
            AssessmentKind::CpuNoMeaningfulContention
        );
        assert_eq!(
            analyze_cpu(Some(&psi(0.20, Duration::from_millis(999))), Some(&busy)).findings[0].kind,
            AssessmentKind::InsufficientObservation
        );
        assert!(analyze_cpu(None, Some(&busy)).findings.is_empty());
    }
    #[test]
    fn ranks_stable_victims_and_non_unique_consumers() {
        let key1 = ProcessKey {
            pid: 1,
            start_time_ticks: 1,
        };
        let key2 = ProcessKey {
            pid: 2,
            start_time_ticks: 1,
        };
        let c = cpu(
            vec![
                ProcessCpuInterval {
                    key: key2,
                    name: "b".into(),
                    state: 'R',
                    cpu_ticks: 1,
                    cpu_fraction_of_one: 0.90,
                },
                ProcessCpuInterval {
                    key: key1,
                    name: "a".into(),
                    state: 'R',
                    cpu_ticks: 1,
                    cpu_fraction_of_one: 1.0,
                },
            ],
            vec![
                ProcessSchedulerDelayInterval {
                    key: key2,
                    name: "b".into(),
                    task_count: 1,
                    running_ns: 0,
                    runnable_wait_ns: 100,
                    runnable_delay_fraction: 0.1,
                    timeslices: 1,
                },
                ProcessSchedulerDelayInterval {
                    key: key1,
                    name: "a".into(),
                    task_count: 1,
                    running_ns: 0,
                    runnable_wait_ns: 100,
                    runnable_delay_fraction: 0.1,
                    timeslices: 1,
                },
                ProcessSchedulerDelayInterval {
                    key: ProcessKey {
                        pid: 3,
                        start_time_ticks: 1,
                    },
                    name: "zero".into(),
                    task_count: 1,
                    running_ns: 0,
                    runnable_wait_ns: 0,
                    runnable_delay_fraction: 0.0,
                    timeslices: 1,
                },
            ],
        );
        let finding = &analyze_cpu(Some(&psi(0.2, Duration::from_secs(10))), Some(&c)).findings[0];
        assert_eq!(
            finding
                .victims
                .iter()
                .map(|x| x.key.pid)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(finding.suspects[0].label, "concurrent_cpu_consumer");
        assert!(
            finding
                .qualifiers
                .iter()
                .any(|q| q.kind == "non_unique_attribution")
        );
    }
    #[test]
    fn normalized_fixtures_drive_analyzer() {
        for fixture in [
            include_str!("../tests/fixtures/cpu/healthy.json"),
            include_str!("../tests/fixtures/cpu/saturated.json"),
            include_str!("../tests/fixtures/cpu/saturated_no_schedstat.json"),
            include_str!("../tests/fixtures/cpu/busy_but_not_pressured.json"),
        ] {
            let fixture: Fixture = serde_json::from_str(fixture).unwrap();
            assert_eq!(fixture.schema, "normalized_cpu_fixture_v1");
            let key = |pid| ProcessKey {
                pid,
                start_time_ticks: 1,
            };
            let mut c = cpu(
                fixture
                    .processes
                    .iter()
                    .map(|p| ProcessCpuInterval {
                        key: key(p.pid),
                        name: format!("p{}", p.pid),
                        state: 'R',
                        cpu_ticks: p.cpu_ticks,
                        cpu_fraction_of_one: p.cpu_fraction,
                    })
                    .collect(),
                fixture
                    .delays
                    .iter()
                    .map(|d| ProcessSchedulerDelayInterval {
                        key: key(d.pid),
                        name: format!("p{}", d.pid),
                        task_count: d.task_count,
                        running_ns: 0,
                        runnable_wait_ns: d.wait_ns,
                        runnable_delay_fraction: 0.0,
                        timeslices: 1,
                    })
                    .collect(),
            );
            c.elapsed = Duration::from_millis(fixture.window_ms);
            c.host.utilization_fraction = fixture.host_utilization_fraction.unwrap_or(0.0);
            c.host.cpu_count = fixture.logical_cpu_count.unwrap_or(8);
            c.load = fixture
                .runnable_tasks
                .map(|runnable_tasks| crate::cpu::LoadAverageRaw {
                    avg1: 0.0,
                    avg5: 0.0,
                    avg15: 0.0,
                    runnable_tasks,
                    total_tasks: runnable_tasks,
                    last_pid: 0,
                });
            if fixture.schedstat.as_deref() == Some("unsupported") {
                c.schedstat_capability = SchedstatCapability::Unsupported;
            }
            let finding = &analyze_cpu(
                Some(&psi(
                    fixture.psi_some_fraction,
                    Duration::from_millis(fixture.window_ms),
                )),
                Some(&c),
            )
            .findings[0];
            let json = serde_json::to_value(finding).unwrap();
            assert_eq!(json["kind"], fixture.expected_kind);
            assert_eq!(json["severity"], fixture.expected_severity);
            assert_eq!(finding.victims.len(), fixture.expected_victims);
            assert_eq!(finding.suspects.len(), fixture.expected_suspects);
            assert!(
                finding
                    .qualifiers
                    .iter()
                    .any(|q| q.kind == fixture.expected_qualifier)
            );
            assert_eq!(
                finding
                    .victims
                    .iter()
                    .map(|v| v.key.pid)
                    .collect::<Vec<_>>(),
                fixture.expected_victim_pids
            );
            assert_eq!(
                finding
                    .suspects
                    .iter()
                    .map(|s| s.key.pid)
                    .collect::<Vec<_>>(),
                fixture.expected_suspect_pids
            );
            assert_eq!(
                finding.suspects.iter().map(|s| s.label).collect::<Vec<_>>(),
                fixture
                    .expected_suspect_labels
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                finding
                    .suspects
                    .iter()
                    .map(|s| format!("{:?}", s.confidence).to_lowercase())
                    .collect::<Vec<_>>(),
                fixture.expected_suspect_confidences
            );
        }
    }
    fn process(pid: u32, fraction: f64) -> ProcessCpuInterval {
        ProcessCpuInterval {
            key: ProcessKey {
                pid,
                start_time_ticks: 1,
            },
            name: format!("p{pid}"),
            state: 'R',
            cpu_ticks: pid as u64,
            cpu_fraction_of_one: fraction,
        }
    }
    fn delay(pid: u32, wait: u64) -> ProcessSchedulerDelayInterval {
        ProcessSchedulerDelayInterval {
            key: ProcessKey {
                pid,
                start_time_ticks: 1,
            },
            name: format!("p{pid}"),
            task_count: 1,
            running_ns: 0,
            runnable_wait_ns: wait,
            runnable_delay_fraction: 0.0,
            timeslices: 1,
        }
    }
    #[test]
    fn threshold_edges_and_confidence_are_deterministic() {
        let c = cpu(vec![], vec![]);
        for (value, severity) in [
            (0.009_999, Severity::None),
            (0.01, Severity::Low),
            (0.049_999, Severity::Low),
            (0.05, Severity::Moderate),
            (0.149_999, Severity::Moderate),
            (0.15, Severity::High),
            (0.299_999, Severity::High),
            (0.30, Severity::Severe),
        ] {
            assert_eq!(severity_for_psi(value), severity);
        }
        assert_eq!(
            analyze_cpu(Some(&psi(0.2, Duration::from_secs(1))), Some(&c)).findings[0]
                .resource_confidence,
            Confidence::Medium
        );
        assert_eq!(
            analyze_cpu(Some(&psi(0.2, Duration::from_millis(4_999))), Some(&c)).findings[0]
                .resource_confidence,
            Confidence::Medium
        );
        assert_eq!(
            analyze_cpu(Some(&psi(0.2, Duration::from_secs(5))), Some(&c)).findings[0]
                .resource_confidence,
            Confidence::High
        );
        let mut requested_short = psi(0.2, Duration::from_secs(1));
        requested_short.requested = Duration::from_millis(100);
        assert_eq!(
            analyze_cpu(Some(&requested_short), Some(&c)).findings[0].kind,
            AssessmentKind::InsufficientObservation
        );
        let mut exact_one = psi(0.2, Duration::from_secs(1));
        exact_one.requested = Duration::from_secs(1);
        assert_eq!(
            analyze_cpu(Some(&exact_one), Some(&c)).findings[0].resource_confidence,
            Confidence::Medium
        );
    }
    #[test]
    fn missing_intervals_and_suspect_boundary_are_conservative() {
        let c = cpu(vec![process(1, 0.25), process(2, 0.249_999)], vec![]);
        let f = &analyze_cpu(Some(&psi(0.2, Duration::from_secs(10))), Some(&c)).findings[0];
        assert_eq!(
            f.suspects.iter().map(|x| x.key.pid).collect::<Vec<_>>(),
            vec![1]
        );
        let no_cpu = analyze_cpu(Some(&psi(0.2, Duration::from_secs(10))), None);
        assert_eq!(no_cpu.findings[0].kind, AssessmentKind::CpuContention);
        assert!(
            no_cpu.findings[0]
                .qualifiers
                .iter()
                .any(|q| q.kind == "cpu_context_unavailable")
        );
        assert!(analyze_cpu(None, Some(&c)).findings.is_empty());
        assert_eq!(
            analyze_cpu(Some(&psi(0.2, Duration::from_millis(999))), Some(&c)).findings[0].kind,
            AssessmentKind::InsufficientObservation
        );
    }
    #[test]
    fn attribution_limits_and_top_n_are_enforced() {
        let mut c = cpu(
            (1..=5).rev().map(|pid| process(pid, 0.5)).collect(),
            (1..=6).rev().map(|pid| delay(pid, 100)).collect(),
        );
        let f = &analyze_cpu(Some(&psi(0.2, Duration::from_secs(10))), Some(&c)).findings[0];
        assert_eq!(
            f.suspects.iter().map(|x| x.key.pid).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert_eq!(
            f.victims.iter().map(|x| x.key.pid).collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 5]
        );
        c.collection_issues.appeared = 1;
        c.schedstat_capability = SchedstatCapability::Partial;
        let f = &analyze_cpu(Some(&psi(0.2, Duration::from_secs(10))), Some(&c)).findings[0];
        assert!(f.suspects.iter().all(|x| x.confidence == Confidence::Low));
        assert!(f.victims.iter().all(|x| x.confidence == Confidence::Medium));
        assert!(
            f.qualifiers
                .iter()
                .any(|q| q.kind == "suspect_attribution_limited")
        );
        assert!(
            f.qualifiers
                .iter()
                .any(|q| q.kind == "victim_attribution_limited")
        );
    }
    #[test]
    fn no_contention_keeps_positive_delay_as_context() {
        let c = cpu(vec![process(1, 1.0)], vec![delay(1, 100)]);
        let f = &analyze_cpu(Some(&psi(0.005, Duration::from_secs(10))), Some(&c)).findings[0];
        assert!(f.victims.is_empty() && f.suspects.is_empty());
        assert!(
            f.qualifiers
                .iter()
                .any(|q| q.kind == "scheduler_delay_context")
        );
    }
    #[test]
    fn low_share_consumer_is_never_called_major_or_causal() {
        let mut c = cpu(vec![process(1, 0.25)], vec![]);
        c.host.cpu_count = 128;
        c.host.utilization_fraction = 1.0;
        let suspect = &analyze_cpu(Some(&psi(0.2, Duration::from_secs(10))), Some(&c)).findings[0]
            .suspects[0];
        assert_eq!(suspect.label, "leading_concurrent_cpu_consumer");
        assert!(suspect.confidence <= Confidence::Medium);
        assert!(!suspect.label.contains("major") && !suspect.label.contains("cause"));
    }

    fn memory_psi(
        some_fraction: f64,
        full_fraction: Option<f64>,
        elapsed: Duration,
    ) -> MemoryPsiObservation {
        let elapsed_us = elapsed.as_micros() as f64;
        let some_delta = (some_fraction * elapsed_us) as u64;
        let full_delta = full_fraction.map(|fraction| (fraction * elapsed_us) as u64);
        let line = MemoryPsiLine {
            avg10_percent: 0.0,
            avg60_percent: 0.0,
            avg300_percent: 0.0,
            total_us: 0,
        };
        MemoryPsiObservation {
            requested: elapsed,
            interval: MemoryPsiInterval {
                elapsed,
                some: MemoryPsiLineInterval {
                    total_delta_us: some_delta,
                    fraction: some_fraction,
                },
                full: full_delta.map_or(MemoryPsiFullInterval::Missing, |total_delta_us| {
                    MemoryPsiFullInterval::Available(MemoryPsiLineInterval {
                        total_delta_us,
                        fraction: full_fraction.unwrap(),
                    })
                }),
            },
            start: MemoryPsiRaw {
                some: line,
                full: full_delta.map(|_| line),
            },
            end: MemoryPsiRaw {
                some: MemoryPsiLine {
                    total_us: some_delta,
                    ..line
                },
                full: full_delta.map(|total_us| MemoryPsiLine { total_us, ..line }),
            },
        }
    }

    fn io_psi(
        some_fraction: f64,
        full_fraction: Option<f64>,
        elapsed: Duration,
    ) -> IoPsiObservation {
        let elapsed_us = elapsed.as_micros() as f64;
        let some_delta = (some_fraction * elapsed_us) as u64;
        let full_delta = full_fraction.map(|fraction| (fraction * elapsed_us) as u64);
        let line = IoPsiLine {
            avg10_percent: 0.0,
            avg60_percent: 0.0,
            avg300_percent: 0.0,
            total_us: 0,
        };
        IoPsiObservation {
            requested: elapsed,
            interval: IoPsiInterval {
                elapsed,
                some: IoPsiLineInterval {
                    total_delta_us: some_delta,
                    fraction: some_fraction,
                },
                full: full_delta.map_or(IoPsiFullInterval::Missing, |total_delta_us| {
                    IoPsiFullInterval::Available(IoPsiLineInterval {
                        total_delta_us,
                        fraction: full_fraction.unwrap(),
                    })
                }),
            },
            start: IoPsiRaw {
                some: line,
                full: full_delta.map(|_| line),
            },
            end: IoPsiRaw {
                some: IoPsiLine {
                    total_us: some_delta,
                    ..line
                },
                full: full_delta.map(|total_us| IoPsiLine { total_us, ..line }),
            },
        }
    }

    fn io_context() -> (DiskstatsObservation, ProcessIoObservation) {
        let diskstats = DiskstatsObservation {
            elapsed: Duration::from_secs(10),
            capability: IoCapability::Available,
            devices: vec![
                DiskstatsInterval {
                    key: BlockDeviceKey {
                        major: 8,
                        minor: 16,
                    },
                    name: "sdb".into(),
                    reads_completed: Some(2),
                    sectors_read_512: Some(100),
                    writes_completed: Some(2),
                    sectors_written_512: Some(200),
                    io_ticks_ms: Some(1),
                    weighted_io_ticks_ms: Some(1),
                    end_in_flight: 0,
                },
                DiskstatsInterval {
                    key: BlockDeviceKey { major: 8, minor: 0 },
                    name: "sda".into(),
                    reads_completed: Some(1),
                    sectors_read_512: Some(1_000),
                    writes_completed: Some(0),
                    sectors_written_512: Some(0),
                    io_ticks_ms: Some(1),
                    weighted_io_ticks_ms: Some(1),
                    end_in_flight: 0,
                },
            ],
            issues: DiskstatsIntervalIssues::default(),
        };
        let process_io = ProcessIoObservation {
            elapsed: Duration::from_secs(10),
            capability: IoCapability::Available,
            processes: vec![
                ProcessIoInterval {
                    key: ProcessKey {
                        pid: 2,
                        start_time_ticks: 1,
                    },
                    name: "writer".into(),
                    read_bytes: Some(1),
                    write_bytes: Some(900),
                    cancelled_write_bytes: Some(0),
                    rchar: None,
                    wchar: None,
                },
                ProcessIoInterval {
                    key: ProcessKey {
                        pid: 1,
                        start_time_ticks: 1,
                    },
                    name: "reader".into(),
                    read_bytes: Some(1_000),
                    write_bytes: Some(0),
                    cancelled_write_bytes: Some(0),
                    rchar: None,
                    wchar: None,
                },
            ],
            issues: ProcessIoCollectionIssues::default(),
            regressed: vec![],
        };
        (diskstats, process_io)
    }

    #[test]
    fn io_psi_alone_controls_pressure_and_activity_is_ranked_only_when_pressured() {
        let (diskstats, process_io) = io_context();
        let pressured = &analyze_io(
            Some(&io_psi(0.08, Some(0.02), Duration::from_secs(10))),
            Some(&diskstats),
            Some(&process_io),
        )
        .findings[0];
        assert_eq!(pressured.kind, IoAssessmentKind::Pressure);
        assert_eq!(pressured.device_candidates[0].name, "sda");
        assert_eq!(pressured.process_suspects[0].name, "reader");
        assert!(
            pressured
                .qualifiers
                .iter()
                .any(|q| q.kind == "no_affected_workload_attribution")
        );
        let healthy = &analyze_io(
            Some(&io_psi(0.005, Some(0.001), Duration::from_secs(10))),
            Some(&diskstats),
            Some(&process_io),
        )
        .findings[0];
        assert_eq!(healthy.kind, IoAssessmentKind::NoMeaningfulContention);
        assert!(healthy.device_candidates.is_empty() && healthy.process_suspects.is_empty());
    }

    #[test]
    fn io_boundaries_missing_and_contradictory_context_are_conservative() {
        assert_eq!(severity_for_io_psi(0.009_999), Severity::None);
        assert_eq!(severity_for_io_psi(0.01), Severity::Low);
        assert_eq!(severity_for_io_psi(0.05), Severity::Moderate);
        assert_eq!(severity_for_io_psi(0.15), Severity::High);
        assert_eq!(severity_for_io_psi(0.30), Severity::Severe);
        let missing = &analyze_io(
            Some(&io_psi(0.20, None, Duration::from_secs(10))),
            None,
            None,
        )
        .findings[0];
        assert_eq!(missing.kind, IoAssessmentKind::Pressure);
        assert!(
            missing
                .qualifiers
                .iter()
                .any(|q| q.kind == "diskstats_unavailable")
        );
        let short = &analyze_io(
            Some(&io_psi(0.20, Some(0.01), Duration::from_millis(999))),
            None,
            None,
        )
        .findings[0];
        assert_eq!(short.kind, IoAssessmentKind::InsufficientObservation);
        assert!(analyze_io(None, None, None).findings.is_empty());
    }

    #[test]
    fn partial_io_context_reduces_attribution_confidence() {
        let (mut diskstats, mut process_io) = io_context();
        diskstats.capability = IoCapability::Partial;
        process_io.capability = IoCapability::Partial;
        let finding = &analyze_io(
            Some(&io_psi(0.08, Some(0.02), Duration::from_secs(10))),
            Some(&diskstats),
            Some(&process_io),
        )
        .findings[0];
        assert!(
            finding
                .device_candidates
                .iter()
                .all(|candidate| candidate.confidence == Confidence::Low)
        );
        assert!(
            finding
                .process_suspects
                .iter()
                .all(|suspect| suspect.confidence == Confidence::Low)
        );
        assert!(
            finding
                .qualifiers
                .iter()
                .any(|qualifier| qualifier.kind == "diskstats_partial")
        );
    }

    #[test]
    fn normalized_io_fixtures_drive_analyzer() {
        for input in [
            include_str!("../tests/fixtures/io/pressure-ranked.json"),
            include_str!("../tests/fixtures/io/healthy-high-activity.json"),
            include_str!("../tests/fixtures/io/boundary-low.json"),
            include_str!("../tests/fixtures/io/missing-context.json"),
            include_str!("../tests/fixtures/io/short-window.json"),
        ] {
            let fixture: IoFixture = serde_json::from_str(input).unwrap();
            assert_eq!(fixture.schema, "normalized_io_fixture_v1");
            let (diskstats, process_io) = io_context();
            let finding = &analyze_io(
                Some(&io_psi(
                    fixture.psi_some_fraction,
                    fixture.psi_full_fraction,
                    Duration::from_millis(fixture.window_ms),
                )),
                fixture.diskstats.then_some(&diskstats),
                fixture.process_io.then_some(&process_io),
            )
            .findings[0];
            let json = serde_json::to_value(finding).unwrap();
            assert_eq!(json["kind"], fixture.expected_kind);
            assert_eq!(json["severity"], fixture.expected_severity);
            if let Some(expected) = fixture.expected_first_device {
                assert_eq!(finding.device_candidates[0].name, expected);
            }
            if let Some(expected) = fixture.expected_first_process {
                assert_eq!(finding.process_suspects[0].name, expected);
            }
        }
    }

    fn memory_context(occupancy_fraction: f64) -> MemoryContextObservation {
        let total = 1_000_000_u64;
        let available = ((1.0 - occupancy_fraction) * total as f64) as u64;
        let mut vmstat_deltas = BTreeMap::new();
        for counter in VmstatCounter::ALL {
            vmstat_deltas.insert(counter, 0);
        }
        MemoryContextObservation {
            elapsed: Duration::from_secs(10),
            end_meminfo: Some(MeminfoRaw {
                mem_total_bytes: total,
                mem_available_bytes: available,
                swap_total_bytes: 100_000,
                swap_free_bytes: 100_000,
                cached_bytes: Some(400_000),
                sreclaimable_bytes: Some(50_000),
                anon_pages_bytes: Some(300_000),
            }),
            meminfo_capability: MemoryContextCapability::Available,
            vmstat_capability: MemoryContextCapability::Available,
            vmstat_deltas,
            vmstat_issues: VmstatIntervalIssues::default(),
        }
    }

    #[test]
    fn memory_psi_boundaries_windows_and_missing_data_are_conservative() {
        for (fraction, severity) in [
            (0.009_999, Severity::None),
            (0.01, Severity::Low),
            (0.049_999, Severity::Low),
            (0.05, Severity::Moderate),
            (0.149_999, Severity::Moderate),
            (0.15, Severity::High),
            (0.299_999, Severity::High),
            (0.30, Severity::Severe),
        ] {
            assert_eq!(severity_for_memory_psi(fraction), severity);
        }
        let context = memory_context(0.5);
        let short = memory_psi(0.2, Some(0.1), Duration::from_millis(999));
        assert_eq!(
            analyze_memory(Some(&short), Some(&context)).findings[0].kind,
            MemoryAssessmentKind::InsufficientObservation
        );
        let mut requested_short = memory_psi(0.2, Some(0.1), Duration::from_secs(1));
        requested_short.requested = Duration::from_millis(100);
        assert_eq!(
            analyze_memory(Some(&requested_short), Some(&context)).findings[0].kind,
            MemoryAssessmentKind::InsufficientObservation
        );
        assert!(analyze_memory(None, Some(&context)).findings.is_empty());
    }

    #[test]
    fn high_occupancy_and_allocated_swap_do_not_create_memory_pressure() {
        let mut context = memory_context(0.95);
        context.end_meminfo.as_mut().unwrap().swap_free_bytes = 25_000;
        let finding = &analyze_memory(
            Some(&memory_psi(0.005, Some(0.001), Duration::from_secs(10))),
            Some(&context),
        )
        .findings[0];
        assert_eq!(finding.kind, MemoryAssessmentKind::NoHarmfulPressure);
        assert_eq!(finding.severity, Severity::None);
        assert!(finding.summary.contains("despite high memory occupancy"));
        assert!(
            finding
                .qualifiers
                .iter()
                .any(|qualifier| qualifier.kind == "swap_allocated_context")
        );
    }

    #[test]
    fn memory_mechanisms_require_conservative_counter_conjunctions() {
        let pressure = memory_psi(0.08, Some(0.01), Duration::from_secs(10));
        let mut context = memory_context(0.8);
        context.vmstat_deltas.insert(VmstatCounter::ScanKswapd, 10);
        assert_eq!(
            analyze_memory(Some(&pressure), Some(&context)).findings[0].kind,
            MemoryAssessmentKind::Pressure
        );
        context.vmstat_deltas.insert(VmstatCounter::ScanDirect, 10);
        assert_eq!(
            analyze_memory(Some(&pressure), Some(&context)).findings[0].kind,
            MemoryAssessmentKind::Pressure
        );
        context.vmstat_deltas.insert(VmstatCounter::StealDirect, 5);
        assert_eq!(
            analyze_memory(Some(&pressure), Some(&context)).findings[0].kind,
            MemoryAssessmentKind::ReclaimPressure
        );
        context.vmstat_deltas.insert(VmstatCounter::SwapOut, 3);
        assert_eq!(
            analyze_memory(Some(&pressure), Some(&context)).findings[0].kind,
            MemoryAssessmentKind::ReclaimPressure
        );
        context.vmstat_deltas.insert(VmstatCounter::SwapIn, 1);
        assert_eq!(
            analyze_memory(Some(&pressure), Some(&context)).findings[0].kind,
            MemoryAssessmentKind::SwapPressure
        );
    }

    #[test]
    fn possible_thrashing_requires_sustained_high_some_full_and_mechanism() {
        let mut context = memory_context(0.95);
        context.elapsed = Duration::from_secs(5);
        for counter in [
            VmstatCounter::ScanDirect,
            VmstatCounter::StealDirect,
            VmstatCounter::SwapIn,
            VmstatCounter::SwapOut,
        ] {
            context.vmstat_deltas.insert(counter, 5_120);
        }
        let finding = &analyze_memory(
            Some(&memory_psi(0.20, Some(0.02), Duration::from_secs(5))),
            Some(&context),
        )
        .findings[0];
        assert_eq!(finding.kind, MemoryAssessmentKind::PossibleThrashing);
        assert_eq!(finding.resource_confidence, Confidence::High);
        assert_eq!(finding.mechanism_confidence, Some(Confidence::Medium));
        assert_eq!(finding.evidence.memory_context_window_us, Some(5_000_000));

        context.elapsed = Duration::from_secs(10);
        let slower_context = &analyze_memory(
            Some(&memory_psi(0.20, Some(0.02), Duration::from_secs(5))),
            Some(&context),
        )
        .findings[0];
        assert_eq!(slower_context.kind, MemoryAssessmentKind::SwapPressure);
        context.elapsed = Duration::from_secs(5);

        context.vmstat_deltas.insert(VmstatCounter::SwapIn, 1);
        let immaterial = &analyze_memory(
            Some(&memory_psi(0.20, Some(0.02), Duration::from_secs(5))),
            Some(&context),
        )
        .findings[0];
        assert_eq!(immaterial.kind, MemoryAssessmentKind::SwapPressure);
        assert_eq!(immaterial.mechanism_confidence, Some(Confidence::Low));
        context.vmstat_deltas.insert(VmstatCounter::SwapIn, 0);
        context.vmstat_deltas.insert(VmstatCounter::SwapOut, 0);

        let moderate = &analyze_memory(
            Some(&memory_psi(0.149, Some(0.02), Duration::from_secs(5))),
            Some(&context),
        )
        .findings[0];
        assert_eq!(moderate.kind, MemoryAssessmentKind::ReclaimPressure);
        let short = &analyze_memory(
            Some(&memory_psi(0.20, Some(0.02), Duration::from_secs(4))),
            Some(&context),
        )
        .findings[0];
        assert_eq!(short.kind, MemoryAssessmentKind::ReclaimPressure);
    }

    #[test]
    fn invalid_host_full_blocks_possible_thrashing_but_not_pressure() {
        let mut context = memory_context(0.95);
        context.elapsed = Duration::from_secs(5);
        for counter in [
            VmstatCounter::ScanDirect,
            VmstatCounter::StealDirect,
            VmstatCounter::SwapIn,
            VmstatCounter::SwapOut,
        ] {
            context.vmstat_deltas.insert(counter, 5_120);
        }

        let mut psi = memory_psi(0.20, Some(0.02), Duration::from_secs(5));
        psi.interval.full = MemoryPsiFullInterval::ExceedsSome;
        let finding = &analyze_memory(Some(&psi), Some(&context)).findings[0];
        assert_eq!(finding.kind, MemoryAssessmentKind::SwapPressure);
        assert_eq!(
            finding.evidence.psi_full_state,
            MemoryFullEvidenceState::ExceedsSome
        );
        assert_eq!(finding.evidence.psi_full_fraction, None);
        assert!(
            finding
                .qualifiers
                .iter()
                .any(|qualifier| qualifier.kind == "memory_full_interval_invalid")
        );
        assert!(!finding.summary.to_lowercase().contains("thrashing"));

        for state in [
            MemoryPsiFullInterval::CounterRegressed,
            MemoryPsiFullInterval::DeltaExceedsElapsed,
        ] {
            let mut psi = memory_psi(0.20, Some(0.02), Duration::from_secs(5));
            psi.interval.full = state;
            let finding = &analyze_memory(Some(&psi), Some(&context)).findings[0];
            assert_eq!(finding.kind, MemoryAssessmentKind::SwapPressure);
            assert_ne!(
                finding.evidence.psi_full_state,
                MemoryFullEvidenceState::Available
            );
        }
    }

    #[test]
    fn valid_some_survives_missing_full_and_memory_context() {
        let psi = memory_psi(0.08, None, Duration::from_secs(10));
        let finding = &analyze_memory(Some(&psi), None).findings[0];
        assert_eq!(finding.kind, MemoryAssessmentKind::Pressure);
        assert_eq!(finding.severity, Severity::Moderate);
        assert!(
            finding
                .qualifiers
                .iter()
                .any(|qualifier| qualifier.kind == "memory_full_unavailable")
        );
        assert!(
            finding
                .qualifiers
                .iter()
                .any(|qualifier| qualifier.kind == "memory_context_unavailable")
        );
    }

    #[test]
    fn ranked_findings_put_more_severe_memory_evidence_first() {
        let cpu = analyze_cpu(
            Some(&psi(0.005, Duration::from_secs(10))),
            Some(&cpu(vec![], vec![])),
        );
        let memory = analyze_memory(
            Some(&memory_psi(0.20, Some(0.02), Duration::from_secs(10))),
            Some(&memory_context(0.8)),
        );
        assert!(matches!(
            ranked_findings_with_io(cpu, memory, IoAnalysisResult::default()).first(),
            Some(Finding::Memory(_))
        ));
    }

    fn evidence_chains_from(
        memory_psi: &MemoryPsiObservation,
        memory_context: Option<&MemoryContextObservation>,
        io_psi: Option<&IoPsiObservation>,
        diskstats: Option<&DiskstatsObservation>,
        process_io: Option<&ProcessIoObservation>,
    ) -> Vec<EvidenceChain> {
        let memory = analyze_memory(Some(memory_psi), memory_context);
        let io = analyze_io(io_psi, diskstats, process_io);
        analyze_evidence_chains(memory.findings.first(), io.findings.first(), &[])
    }

    #[test]
    fn memory_mechanism_and_io_pressure_form_a_non_causal_chain() {
        let (diskstats, process_io) = io_context();
        let mut reclaim_context = memory_context(0.8);
        reclaim_context
            .vmstat_deltas
            .insert(VmstatCounter::ScanDirect, 10);
        reclaim_context
            .vmstat_deltas
            .insert(VmstatCounter::StealDirect, 5);
        let reclaim = evidence_chains_from(
            &memory_psi(0.08, Some(0.01), Duration::from_secs(10)),
            Some(&reclaim_context),
            Some(&io_psi(0.08, Some(0.02), Duration::from_secs(10))),
            Some(&diskstats),
            Some(&process_io),
        );
        assert_eq!(reclaim.len(), 1);
        assert_eq!(reclaim[0].kind, ChainKind::MemoryMechanismConsistentWithIo);
        assert_eq!(reclaim[0].relation, ChainRelation::ConsistentWith);
        assert_eq!(reclaim[0].confidence, Confidence::Low);
        assert!(matches!(
            reclaim[0].from,
            ChainEndpoint::Memory {
                kind: MemoryAssessmentKind::ReclaimPressure
            }
        ));
        assert!(matches!(
            reclaim[0].to,
            ChainEndpoint::Io {
                kind: IoAssessmentKind::Pressure
            }
        ));
        assert!(
            reclaim[0]
                .qualifiers
                .iter()
                .any(|qualifier| qualifier.kind == "chain_not_causal")
        );
        assert!(!reclaim[0].summary.to_lowercase().contains("cause"));

        reclaim_context
            .vmstat_deltas
            .insert(VmstatCounter::SwapIn, 4);
        let swap = evidence_chains_from(
            &memory_psi(0.08, Some(0.01), Duration::from_secs(10)),
            Some(&reclaim_context),
            Some(&io_psi(0.01, Some(0.002), Duration::from_secs(10))),
            None,
            None,
        );
        assert_eq!(swap.len(), 1);
        assert!(matches!(
            swap[0].from,
            ChainEndpoint::Memory {
                kind: MemoryAssessmentKind::SwapPressure
            }
        ));
        assert_eq!(swap[0].confidence, Confidence::Low);
        assert_eq!(swap[0].evidence.swap_in_pages, Some(4));

        let mut thrash_context = memory_context(0.95);
        thrash_context.elapsed = Duration::from_secs(5);
        for counter in [
            VmstatCounter::ScanDirect,
            VmstatCounter::StealDirect,
            VmstatCounter::SwapIn,
            VmstatCounter::SwapOut,
        ] {
            thrash_context.vmstat_deltas.insert(counter, 5_120);
        }
        let thrash = evidence_chains_from(
            &memory_psi(0.20, Some(0.02), Duration::from_secs(5)),
            Some(&thrash_context),
            Some(&io_psi(0.15, Some(0.04), Duration::from_secs(5))),
            Some(&diskstats),
            Some(&process_io),
        );
        assert_eq!(thrash.len(), 1);
        assert!(matches!(
            thrash[0].from,
            ChainEndpoint::Memory {
                kind: MemoryAssessmentKind::PossibleThrashing
            }
        ));
        assert_eq!(thrash[0].confidence, Confidence::Medium);
        assert_ne!(thrash[0].confidence, Confidence::High);
    }

    #[test]
    fn coincident_or_incomplete_pressure_does_not_form_a_chain() {
        let (diskstats, process_io) = io_context();
        let healthy_memory = memory_context(0.95);
        assert!(
            evidence_chains_from(
                &memory_psi(0.005, Some(0.001), Duration::from_secs(10)),
                Some(&healthy_memory),
                Some(&io_psi(0.20, Some(0.05), Duration::from_secs(10))),
                Some(&diskstats),
                Some(&process_io),
            )
            .is_empty()
        );

        let mut reclaim_context = memory_context(0.8);
        reclaim_context
            .vmstat_deltas
            .insert(VmstatCounter::ScanDirect, 10);
        reclaim_context
            .vmstat_deltas
            .insert(VmstatCounter::StealDirect, 5);
        assert!(
            evidence_chains_from(
                &memory_psi(0.20, Some(0.02), Duration::from_secs(10)),
                Some(&reclaim_context),
                Some(&io_psi(0.005, Some(0.001), Duration::from_secs(10))),
                Some(&diskstats),
                Some(&process_io),
            )
            .is_empty()
        );

        let generic = memory_context(0.8);
        assert!(
            evidence_chains_from(
                &memory_psi(0.20, Some(0.02), Duration::from_secs(10)),
                Some(&generic),
                Some(&io_psi(0.20, Some(0.05), Duration::from_secs(10))),
                Some(&diskstats),
                Some(&process_io),
            )
            .is_empty(),
            "PSI coincidence without a VM-counter mechanism must not form a chain"
        );

        assert!(
            evidence_chains_from(
                &memory_psi(0.20, Some(0.02), Duration::from_secs(10)),
                Some(&reclaim_context),
                None,
                None,
                None,
            )
            .is_empty()
        );
        assert!(analyze_evidence_chains(None, None, &[]).is_empty());

        assert!(
            evidence_chains_from(
                &memory_psi(0.20, Some(0.02), Duration::from_millis(999)),
                Some(&reclaim_context),
                Some(&io_psi(0.20, Some(0.05), Duration::from_secs(10))),
                Some(&diskstats),
                Some(&process_io),
            )
            .is_empty()
        );
        assert!(
            evidence_chains_from(
                &memory_psi(0.20, Some(0.02), Duration::from_secs(10)),
                Some(&reclaim_context),
                Some(&io_psi(0.20, Some(0.05), Duration::from_millis(999))),
                Some(&diskstats),
                Some(&process_io),
            )
            .is_empty()
        );
    }

    #[test]
    fn same_cgroup_memory_and_io_pressure_form_a_non_causal_chain() {
        let elapsed = Duration::from_secs(10);
        let observation = scoped_memory_io_observation(
            vec![scoped_memory_io_group(
                "/workload.service",
                Some(800_000),
                Some(800_000),
                None,
                cgroup_events(Some(3), Some(0)),
                elapsed,
            )],
            elapsed,
        );
        let chains = cgroup_chains_from(&observation);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].kind, ChainKind::CgroupMemoryConsistentWithIo);
        assert_eq!(chains[0].relation, ChainRelation::ConsistentWith);
        assert_eq!(chains[0].confidence, Confidence::Low);
        assert_ne!(chains[0].confidence, Confidence::High);
        assert!(matches!(
            &chains[0].from,
            ChainEndpoint::CgroupMemory {
                path,
                kind: CgroupAssessmentKind::Pressure
            } if path == "/workload.service"
        ));
        assert!(matches!(
            &chains[0].to,
            ChainEndpoint::CgroupIo {
                path,
                kind: CgroupAssessmentKind::Pressure
            } if path == "/workload.service"
        ));
        assert_eq!(
            chains[0].evidence.path.as_deref(),
            Some("/workload.service")
        );
        assert_eq!(chains[0].evidence.high_events, Some(3));
        assert!(
            chains[0]
                .qualifiers
                .iter()
                .any(|qualifier| qualifier.kind == "chain_not_causal")
        );
        assert!(
            chains[0]
                .qualifiers
                .iter()
                .any(|qualifier| qualifier.kind == "same_cgroup_scope_only")
        );
        assert!(!chains[0].summary.to_lowercase().contains("cause"));

        let max_only = scoped_memory_io_observation(
            vec![scoped_memory_io_group(
                "/workload.service",
                Some(800_000),
                Some(800_000),
                None,
                cgroup_events(Some(0), Some(2)),
                elapsed,
            )],
            elapsed,
        );
        let max_chains = cgroup_chains_from(&max_only);
        assert_eq!(max_chains.len(), 1);
        assert_eq!(max_chains[0].evidence.max_events, Some(2));
        assert_eq!(max_chains[0].evidence.high_events, None);

        let nested = scoped_memory_io_observation(
            vec![
                scoped_memory_io_group(
                    "/parent.scope",
                    Some(1_500_000),
                    Some(1_500_000),
                    None,
                    cgroup_events(Some(1), Some(0)),
                    elapsed,
                ),
                scoped_memory_io_group(
                    "/parent.scope/child.service",
                    Some(800_000),
                    Some(800_000),
                    None,
                    cgroup_events(Some(2), Some(0)),
                    elapsed,
                ),
            ],
            elapsed,
        );
        let nested_chains = cgroup_chains_from(&nested);
        assert_eq!(nested_chains.len(), 2);
        assert_eq!(
            nested_chains[0].evidence.path.as_deref(),
            Some("/parent.scope")
        );
        assert_eq!(
            nested_chains[1].evidence.path.as_deref(),
            Some("/parent.scope/child.service")
        );
        assert!(
            nested_chains
                .iter()
                .all(|chain| match (&chain.from, &chain.to) {
                    (
                        ChainEndpoint::CgroupMemory { path: from, .. },
                        ChainEndpoint::CgroupIo { path: to, .. },
                    ) => from == to,
                    _ => false,
                })
        );
    }

    #[test]
    fn evidence_chain_truncation_keeps_ranked_prefix_and_deterministic_order() {
        let elapsed = Duration::from_secs(10);
        // 18 eligible same-cgroup memory+I/O chain candidates. Groups 0..=15
        // have moderate PSI (`some` 5%), while groups 16..=17 have low PSI
        // (`some` 1.5%). Ranking is severity-descending then path-ascending,
        // so the kept prefix is groups 00-15 in path order and the two lower
        // ranked candidates truncate away.
        let mut groups = Vec::new();
        for index in 0..(MAX_CGROUP_EVIDENCE_CHAINS + 2) {
            let some_us = if index < MAX_CGROUP_EVIDENCE_CHAINS {
                500_000
            } else {
                150_000
            };
            groups.push(scoped_memory_io_group(
                &format!("/slice/group-{index:02}.service"),
                Some(some_us),
                Some(some_us),
                None,
                cgroup_events(Some(1), Some(0)),
                elapsed,
            ));
        }
        let observation = scoped_memory_io_observation(groups, elapsed);
        let findings = analyze_cgroups(Some(&observation)).findings;
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.kind == CgroupAssessmentKind::Pressure)
                .count(),
            2 * (MAX_CGROUP_EVIDENCE_CHAINS + 2),
            "every fixture group must produce eligible memory and I/O pressure findings"
        );
        let chains = analyze_evidence_chains(None, None, &findings);

        assert_eq!(chains.len(), MAX_CGROUP_EVIDENCE_CHAINS);
        for (position, chain) in chains.iter().enumerate() {
            assert_eq!(
                chain.evidence.path.as_deref(),
                Some(format!("/slice/group-{position:02}.service").as_str()),
                "chain at position {position} must follow the documented rank-then-path order"
            );
        }
    }

    #[test]
    fn cgroup_memory_stat_direct_reclaim_or_swap_in_forms_a_chain() {
        let elapsed = Duration::from_secs(10);
        let reclaim = scoped_memory_io_observation(
            vec![with_cgroup_stat(
                scoped_memory_io_group(
                    "/workload.service",
                    Some(800_000),
                    Some(800_000),
                    None,
                    cgroup_events(None, None),
                    elapsed,
                ),
                cgroup_stat(Some(12), Some(8), Some(0), Some(0)),
            )],
            elapsed,
        );
        let chains = cgroup_chains_from(&reclaim);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].kind, ChainKind::CgroupMemoryConsistentWithIo);
        assert_eq!(chains[0].confidence, Confidence::Low);
        assert_eq!(chains[0].evidence.scan_direct_pages, Some(12));
        assert_eq!(chains[0].evidence.steal_direct_pages, Some(8));
        assert_eq!(chains[0].evidence.high_events, None);

        let swap = scoped_memory_io_observation(
            vec![with_cgroup_stat(
                scoped_memory_io_group(
                    "/workload.service",
                    Some(800_000),
                    Some(800_000),
                    None,
                    cgroup_events(Some(0), Some(0)),
                    elapsed,
                ),
                cgroup_stat(Some(0), Some(0), Some(5), Some(2)),
            )],
            elapsed,
        );
        let swap_chains = cgroup_chains_from(&swap);
        assert_eq!(swap_chains.len(), 1);
        assert_eq!(swap_chains[0].evidence.swap_in_pages, Some(5));
        assert_eq!(swap_chains[0].evidence.swap_out_pages, Some(2));
    }

    #[test]
    fn cgroup_coincident_or_cross_scope_pressure_does_not_form_a_chain() {
        let elapsed = Duration::from_secs(10);
        let coincident = scoped_memory_io_observation(
            vec![scoped_memory_io_group(
                "/workload.service",
                Some(800_000),
                Some(800_000),
                None,
                cgroup_events(Some(0), Some(0)),
                elapsed,
            )],
            elapsed,
        );
        assert!(
            cgroup_chains_from(&coincident).is_empty(),
            "same-cgroup PSI coincidence without memory.events high/max or memory.stat mechanism must not form a chain"
        );

        let scan_without_steal = scoped_memory_io_observation(
            vec![with_cgroup_stat(
                scoped_memory_io_group(
                    "/workload.service",
                    Some(800_000),
                    Some(800_000),
                    None,
                    cgroup_events(Some(0), Some(0)),
                    elapsed,
                ),
                cgroup_stat(Some(12), Some(0), Some(0), Some(0)),
            )],
            elapsed,
        );
        assert!(
            cgroup_chains_from(&scan_without_steal).is_empty(),
            "direct scan without steal is not a reclaim mechanism"
        );

        let missing_events = scoped_memory_io_observation(
            vec![scoped_memory_io_group(
                "/workload.service",
                Some(800_000),
                Some(800_000),
                None,
                cgroup_events(None, None),
                elapsed,
            )],
            elapsed,
        );
        assert!(cgroup_chains_from(&missing_events).is_empty());

        let io_healthy = scoped_memory_io_observation(
            vec![scoped_memory_io_group(
                "/workload.service",
                Some(800_000),
                Some(5_000),
                None,
                cgroup_events(Some(3), Some(0)),
                elapsed,
            )],
            elapsed,
        );
        assert!(cgroup_chains_from(&io_healthy).is_empty());

        let cpu_and_io = scoped_memory_io_observation(
            vec![scoped_memory_io_group(
                "/workload.service",
                None,
                Some(800_000),
                Some(800_000),
                cgroup_events(Some(3), Some(0)),
                elapsed,
            )],
            elapsed,
        );
        assert!(
            cgroup_chains_from(&cpu_and_io).is_empty(),
            "CPU plus I/O pressure must not form a chain"
        );

        let split_scopes = scoped_memory_io_observation(
            vec![
                scoped_memory_io_group(
                    "/parent.scope",
                    Some(800_000),
                    None,
                    None,
                    cgroup_events(Some(4), Some(0)),
                    elapsed,
                ),
                scoped_memory_io_group(
                    "/parent.scope/child.service",
                    None,
                    Some(800_000),
                    None,
                    cgroup_events(Some(4), Some(0)),
                    elapsed,
                ),
            ],
            elapsed,
        );
        assert!(
            cgroup_chains_from(&split_scopes).is_empty(),
            "memory in one cgroup and I/O in another, including parent/child, must not form a chain"
        );

        let mut reclaim_context = memory_context(0.8);
        reclaim_context
            .vmstat_deltas
            .insert(VmstatCounter::ScanDirect, 10);
        reclaim_context
            .vmstat_deltas
            .insert(VmstatCounter::StealDirect, 5);
        let host_memory = analyze_memory(
            Some(&memory_psi(0.08, Some(0.01), elapsed)),
            Some(&reclaim_context),
        );
        let host_io = analyze_io(Some(&io_psi(0.08, Some(0.02), elapsed)), None, None);
        let host_and_other_cgroup = analyze_evidence_chains(
            host_memory.findings.first(),
            host_io.findings.first(),
            &analyze_cgroups(Some(&split_scopes)).findings,
        );
        assert_eq!(host_and_other_cgroup.len(), 1);
        assert_eq!(
            host_and_other_cgroup[0].kind,
            ChainKind::MemoryMechanismConsistentWithIo
        );
        assert!(
            !host_and_other_cgroup
                .iter()
                .any(|chain| chain.kind == ChainKind::CgroupMemoryConsistentWithIo)
        );
    }

    #[test]
    fn normalized_memory_fixtures_drive_analyzer() {
        for input in [
            include_str!("../tests/fixtures/memory/benign-high-occupancy.json"),
            include_str!("../tests/fixtures/memory/reclaim-pressure.json"),
            include_str!("../tests/fixtures/memory/swap-pressure.json"),
            include_str!("../tests/fixtures/memory/possible-thrashing.json"),
            include_str!("../tests/fixtures/memory/pressure-missing-context.json"),
        ] {
            let fixture: MemoryFixture = serde_json::from_str(input).unwrap();
            assert_eq!(fixture.schema, "normalized_memory_fixture_v1");
            let mut context = fixture.context.then(|| {
                let mut context = memory_context(fixture.occupancy_fraction.unwrap_or(0.5));
                if let Some(swap_used) = fixture.swap_used_bytes {
                    let meminfo = context.end_meminfo.as_mut().unwrap();
                    meminfo.swap_free_bytes = meminfo.swap_total_bytes - swap_used;
                }
                for (counter, value) in [
                    (VmstatCounter::ScanDirect, fixture.scan_direct),
                    (VmstatCounter::StealDirect, fixture.steal_direct),
                    (VmstatCounter::SwapIn, fixture.swap_in),
                    (VmstatCounter::SwapOut, fixture.swap_out),
                ] {
                    if let Some(value) = value {
                        context.vmstat_deltas.insert(counter, value);
                    }
                }
                context
            });
            if let Some(context) = &mut context {
                context.elapsed = Duration::from_millis(fixture.window_ms);
            }
            let finding = &analyze_memory(
                Some(&memory_psi(
                    fixture.psi_some_fraction,
                    fixture.psi_full_fraction,
                    Duration::from_millis(fixture.window_ms),
                )),
                context.as_ref(),
            )
            .findings[0];
            let json = serde_json::to_value(finding).unwrap();
            assert_eq!(json["kind"], fixture.expected_kind);
            assert_eq!(json["severity"], fixture.expected_severity);
            assert!(
                finding
                    .qualifiers
                    .iter()
                    .any(|qualifier| qualifier.kind == fixture.expected_qualifier)
            );
        }
    }

    #[derive(Deserialize)]
    struct MemoryFixture {
        schema: String,
        psi_some_fraction: f64,
        psi_full_fraction: Option<f64>,
        window_ms: u64,
        context: bool,
        occupancy_fraction: Option<f64>,
        swap_used_bytes: Option<u64>,
        scan_direct: Option<u64>,
        steal_direct: Option<u64>,
        swap_in: Option<u64>,
        swap_out: Option<u64>,
        expected_kind: String,
        expected_severity: String,
        expected_qualifier: String,
    }

    #[derive(Deserialize)]
    struct IoFixture {
        schema: String,
        psi_some_fraction: f64,
        psi_full_fraction: Option<f64>,
        window_ms: u64,
        diskstats: bool,
        process_io: bool,
        expected_kind: String,
        expected_severity: String,
        expected_first_device: Option<String>,
        expected_first_process: Option<String>,
    }

    #[derive(Deserialize)]
    struct Fixture {
        schema: String,
        psi_some_fraction: f64,
        window_ms: u64,
        host_utilization_fraction: Option<f64>,
        runnable_tasks: Option<u64>,
        logical_cpu_count: Option<u32>,
        schedstat: Option<String>,
        #[serde(default)]
        processes: Vec<FixtureProcess>,
        #[serde(default)]
        delays: Vec<FixtureDelay>,
        expected_kind: String,
        expected_severity: String,
        expected_victims: usize,
        expected_suspects: usize,
        expected_qualifier: String,
        #[serde(default)]
        expected_victim_pids: Vec<u32>,
        #[serde(default)]
        expected_suspect_pids: Vec<u32>,
        #[serde(default)]
        expected_suspect_labels: Vec<String>,
        #[serde(default)]
        expected_suspect_confidences: Vec<String>,
    }
    #[derive(Deserialize)]
    struct FixtureProcess {
        pid: u32,
        cpu_fraction: f64,
        cpu_ticks: u64,
    }
    #[derive(Deserialize)]
    struct FixtureDelay {
        pid: u32,
        wait_ns: u64,
        task_count: u32,
    }
}
