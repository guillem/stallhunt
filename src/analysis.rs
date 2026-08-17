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
    self, CpuProcessObservation, ProcessKey, ProcessSchedulerDelayInterval, SchedstatCapability,
};
use crate::io::{BlockDeviceKey, DiskstatsObservation, IoCapability, ProcessIoObservation};
use crate::memory::{MemoryContextCapability, MemoryContextObservation, VmstatCounter};
use crate::psi::{
    CpuPsiObservation, IoPsiFullInterval, IoPsiObservation, MemoryPsiFullInterval,
    MemoryPsiObservation,
};
use std::collections::BTreeMap;

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
        let left_busy = left.io_ticks_ms.map_or(0, |value| value);
        let right_busy = right.io_ticks_ms.map_or(0, |value| value);
        let left_weighted = left.weighted_io_ticks_ms.map_or(0, |value| value);
        let right_weighted = right.weighted_io_ticks_ms.map_or(0, |value| value);
        let left_activity = u128::from(left.read_sectors_512.map_or(0, |value| value))
            + u128::from(left.write_sectors_512.map_or(0, |value| value));
        let right_activity = u128::from(right.read_sectors_512.map_or(0, |value| value))
            + u128::from(right.write_sectors_512.map_or(0, |value| value));
        right_busy
            .cmp(&left_busy)
            .then_with(|| right_weighted.cmp(&left_weighted))
            .then_with(|| right.end_in_flight.cmp(&left.end_in_flight))
            .then_with(|| right_activity.cmp(&left_activity))
            .then_with(|| {
                (u128::from(right.reads_completed.map_or(0, |value| value))
                    + u128::from(right.writes_completed.map_or(0, |value| value)))
                .cmp(
                    &(u128::from(left.reads_completed.map_or(0, |value| value))
                        + u128::from(left.writes_completed.map_or(0, |value| value))),
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
    if findings.is_empty()
        && let Some(summary) = all_findings.into_iter().next()
    {
        findings.push(summary);
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
    let summary = match kind {
        CgroupAssessmentKind::Pressure => format!(
            "Scoped {resource_name} pressure observed in {} ({:.2}% cgroup PSI some).",
            group.path,
            some.unwrap_or(0.0) * 100.0
        ),
        CgroupAssessmentKind::NoMeaningfulPressure => format!(
            "No meaningful scoped {resource_name} pressure observed in {}.",
            group.path
        ),
        CgroupAssessmentKind::InsufficientObservation => format!(
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
            collection_issues: ProcessCollectionIssues::default(),
            scheduler_delay_candidates: delays,
            schedstat_collection_issues: SchedstatCollectionIssues::default(),
            schedstat_capability: SchedstatCapability::Available,
        }
    }
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
