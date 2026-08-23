//! Presentation-only diagnosis model shared by compact text and the watch TUI.
//!
//! This module never collects telemetry or makes a new inference. It flattens
//! the existing typed analyzer results into bounded, terminal-safe rows.

use std::collections::BTreeSet;
use std::time::Duration;

use crate::analysis::{
    self, AssessmentKind, CgroupAssessmentKind, CgroupMechanism, CgroupResourceKind, Confidence,
    IoAssessmentKind, MemoryAssessmentKind, Severity,
};
use crate::observe::HuntObservation;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverallStatus {
    Healthy,
    Degraded,
    Incomplete,
}

impl OverallStatus {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Healthy => "HEALTHY",
            Self::Degraded => "DEGRADED",
            Self::Incomplete => "INCOMPLETE",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceState {
    Healthy,
    Pressure,
    Inconclusive,
    Unavailable,
}

impl ResourceState {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Pressure => "pressure",
            Self::Inconclusive => "inconclusive",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResourceView {
    pub name: &'static str,
    pub state: ResourceState,
    pub severity: Severity,
    pub confidence: Confidence,
    pub psi_some_fraction: Option<f64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CandidateView {
    pub name: String,
    pub metric: String,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FindingView {
    pub id: String,
    pub resource: &'static str,
    pub scope: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub psi_some_fraction: Option<f64>,
    pub affected: Vec<CandidateView>,
    pub contributors: Vec<CandidateView>,
    pub evidence: Vec<String>,
    pub qualifiers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChainView {
    pub summary: String,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DiagnosisView {
    pub status: OverallStatus,
    pub requested_duration_ms: u64,
    pub resources: Vec<ResourceView>,
    pub findings: Vec<FindingView>,
    pub chains: Vec<ChainView>,
    pub limitations: Vec<String>,
}

impl DiagnosisView {
    pub fn from_observation(observation: &HuntObservation, requested_duration_ms: u64) -> Self {
        let cpu =
            analysis::analyze_cpu(observation.psi.as_ref().ok(), observation.cpu.as_ref().ok());
        let memory = observation.memory.as_ref().map(|memory| {
            analysis::analyze_memory(memory.psi.as_ref().ok(), memory.context.as_ref().ok())
        });
        let io = observation.io.as_ref().map(|io| {
            analysis::analyze_io(
                io.psi.as_ref().ok(),
                io.diskstats.as_ref().ok(),
                io.processes.as_ref().ok(),
            )
        });
        let cgroups = observation
            .cgroup
            .as_ref()
            .and_then(|cgroup| cgroup.observation.as_ref().ok())
            .map(|value| analysis::analyze_cgroups(Some(value)))
            .unwrap_or_default();

        let mut resources = Vec::with_capacity(3);
        let mut findings = Vec::new();
        let mut limitations = BTreeSet::new();

        if let Some(finding) = cpu.findings.first() {
            let state = match finding.kind {
                AssessmentKind::CpuContention => ResourceState::Pressure,
                AssessmentKind::CpuNoMeaningfulContention => ResourceState::Healthy,
                AssessmentKind::InsufficientObservation => ResourceState::Inconclusive,
            };
            resources.push(ResourceView {
                name: "CPU",
                state,
                severity: finding.severity,
                confidence: finding.resource_confidence,
                psi_some_fraction: Some(finding.evidence.psi_some_fraction),
            });
            finding.qualifiers.iter().for_each(|value| {
                limitations.insert(value.message.to_owned());
            });
            if state != ResourceState::Healthy {
                findings.push(FindingView {
                    id: "host:cpu".into(),
                    resource: "CPU",
                    scope: "host".into(),
                    title: terminal_text(&finding.summary, 120),
                    severity: finding.severity,
                    confidence: finding.resource_confidence,
                    psi_some_fraction: Some(finding.evidence.psi_some_fraction),
                    affected: finding
                        .victims
                        .iter()
                        .map(|victim| CandidateView {
                            name: format!(
                                "{} [{}]",
                                terminal_text(&victim.name, 48),
                                victim.key.pid
                            ),
                            metric: format!(
                                "{} runnable delay",
                                human_duration(Duration::from_nanos(victim.runnable_wait_ns))
                            ),
                            confidence: victim.confidence,
                        })
                        .collect(),
                    contributors: finding
                        .suspects
                        .iter()
                        .map(|suspect| CandidateView {
                            name: format!(
                                "{} [{}]",
                                terminal_text(&suspect.name, 48),
                                suspect.key.pid
                            ),
                            metric: format!(
                                "{:.1}% of one CPU",
                                suspect.cpu_fraction_of_one * 100.0
                            ),
                            confidence: suspect.confidence,
                        })
                        .collect(),
                    evidence: vec![
                        format!(
                            "CPU PSI some {:.2}% ({} stalled)",
                            finding.evidence.psi_some_fraction * 100.0,
                            human_duration(Duration::from_micros(
                                finding.evidence.psi_total_delta_us
                            ))
                        ),
                        finding.evidence.host_utilization_fraction.map_or_else(
                            || "Host CPU utilization unavailable".into(),
                            |fraction| format!("Host CPU {:.1}% busy", fraction * 100.0),
                        ),
                    ],
                    qualifiers: finding
                        .qualifiers
                        .iter()
                        .map(|value| value.message.to_owned())
                        .collect(),
                });
            }
        } else {
            resources.push(unavailable_resource("CPU"));
            limitations.insert(
                "CPU assessment unavailable: no valid exact-interval CPU PSI evidence.".into(),
            );
        }

        if let Some(finding) = memory.as_ref().and_then(|value| value.findings.first()) {
            let state = match finding.kind {
                MemoryAssessmentKind::NoHarmfulPressure => ResourceState::Healthy,
                MemoryAssessmentKind::InsufficientObservation => ResourceState::Inconclusive,
                _ => ResourceState::Pressure,
            };
            resources.push(ResourceView {
                name: "Memory",
                state,
                severity: finding.severity,
                confidence: finding.resource_confidence,
                psi_some_fraction: Some(finding.evidence.psi_some_fraction),
            });
            finding.qualifiers.iter().for_each(|value| {
                limitations.insert(value.message.to_owned());
            });
            if state != ResourceState::Healthy {
                let mut evidence = vec![format!(
                    "Memory PSI some {:.2}% ({} stalled)",
                    finding.evidence.psi_some_fraction * 100.0,
                    human_duration(Duration::from_micros(
                        finding.evidence.psi_some_total_delta_us
                    ))
                )];
                if let Some(occupancy) = finding.evidence.memory_occupancy_fraction {
                    evidence.push(format!("Memory {:.1}% occupied", occupancy * 100.0));
                }
                if let (Some(available), Some(total)) = (
                    finding.evidence.memory_available_bytes,
                    finding.evidence.memory_total_bytes,
                ) {
                    evidence.push(format!(
                        "{} available of {} total",
                        human_bytes(u128::from(available)),
                        human_bytes(u128::from(total))
                    ));
                }
                if let Some(full) = finding.evidence.psi_full_fraction {
                    evidence.push(format!("Memory PSI full {:.2}%", full * 100.0));
                }
                evidence.push(format!(
                    "VM pages: direct scan/steal {}/{}; swap in/out {}/{}; major faults {}",
                    optional_counter(finding.evidence.scan_direct_pages),
                    optional_counter(finding.evidence.steal_direct_pages),
                    optional_counter(finding.evidence.swap_in_pages),
                    optional_counter(finding.evidence.swap_out_pages),
                    optional_counter(finding.evidence.major_page_faults),
                ));
                findings.push(FindingView {
                    id: "host:memory".into(),
                    resource: "Memory",
                    scope: "host".into(),
                    title: terminal_text(&finding.summary, 120),
                    severity: finding.severity,
                    confidence: finding.resource_confidence,
                    psi_some_fraction: Some(finding.evidence.psi_some_fraction),
                    affected: Vec::new(),
                    contributors: Vec::new(),
                    evidence,
                    qualifiers: finding
                        .qualifiers
                        .iter()
                        .map(|value| value.message.to_owned())
                        .collect(),
                });
            }
        } else {
            resources.push(unavailable_resource("Memory"));
            limitations.insert(
                "Memory assessment unavailable: no valid exact-interval memory PSI evidence."
                    .into(),
            );
        }

        if let Some(finding) = io.as_ref().and_then(|value| value.findings.first()) {
            let state = match finding.kind {
                IoAssessmentKind::NoMeaningfulContention => ResourceState::Healthy,
                IoAssessmentKind::InsufficientObservation => ResourceState::Inconclusive,
                IoAssessmentKind::Pressure => ResourceState::Pressure,
            };
            resources.push(ResourceView {
                name: "I/O",
                state,
                severity: finding.severity,
                confidence: finding.resource_confidence,
                psi_some_fraction: Some(finding.evidence.psi_some_fraction),
            });
            finding.qualifiers.iter().for_each(|value| {
                limitations.insert(value.message.to_owned());
            });
            if state != ResourceState::Healthy {
                let mut contributors: Vec<_> = finding
                    .process_suspects
                    .iter()
                    .map(|candidate| CandidateView {
                        name: format!(
                            "{} [{}]",
                            terminal_text(&candidate.name, 48),
                            candidate.key.pid
                        ),
                        metric: format!(
                            "{} accounted I/O",
                            human_bytes(candidate.known_accounted_bytes)
                        ),
                        confidence: candidate.confidence,
                    })
                    .collect();
                contributors.extend(finding.device_candidates.iter().map(|candidate| {
                    CandidateView {
                        name: format!(
                            "{} ({}:{})",
                            terminal_text(&candidate.name, 48),
                            candidate.key.major,
                            candidate.key.minor
                        ),
                        metric: format!(
                            "read/write {} / {} sectors; I/O time {}; in-flight {}",
                            optional_counter(candidate.read_sectors_512),
                            optional_counter(candidate.write_sectors_512),
                            candidate.io_ticks_ms.map_or_else(
                                || "unavailable".into(),
                                |value| human_duration(Duration::from_millis(value))
                            ),
                            candidate.end_in_flight
                        ),
                        confidence: candidate.confidence,
                    }
                }));
                findings.push(FindingView {
                    id: "host:io".into(),
                    resource: "I/O",
                    scope: "host".into(),
                    title: terminal_text(&finding.summary, 120),
                    severity: finding.severity,
                    confidence: finding.resource_confidence,
                    psi_some_fraction: Some(finding.evidence.psi_some_fraction),
                    affected: Vec::new(),
                    contributors,
                    evidence: {
                        let mut evidence = vec![format!(
                            "I/O PSI some {:.2}% ({} stalled)",
                            finding.evidence.psi_some_fraction * 100.0,
                            human_duration(Duration::from_micros(
                                finding.evidence.psi_some_total_delta_us
                            ))
                        )];
                        if let Some(full) = finding.evidence.psi_full_fraction {
                            evidence.push(format!("I/O PSI full {:.2}%", full * 100.0));
                        }
                        evidence.push(format!(
                            "Intervals: PSI {}; diskstats {}; process I/O {}",
                            human_duration(Duration::from_micros(
                                u64::try_from(finding.evidence.psi_window_us).unwrap_or(u64::MAX)
                            )),
                            optional_window(finding.evidence.diskstats_window_us),
                            optional_window(finding.evidence.process_io_window_us),
                        ));
                        evidence
                    },
                    qualifiers: finding
                        .qualifiers
                        .iter()
                        .map(|value| value.message.to_owned())
                        .collect(),
                });
            }
        } else {
            resources.push(unavailable_resource("I/O"));
            limitations.insert(
                "I/O assessment unavailable: no valid exact-interval I/O PSI evidence.".into(),
            );
        }

        for finding in cgroups
            .findings
            .iter()
            .filter(|finding| finding.kind == CgroupAssessmentKind::Pressure)
        {
            finding.qualifiers.iter().for_each(|value| {
                limitations.insert(value.message.to_owned());
            });
            let resource = match finding.resource {
                CgroupResourceKind::Cpu => "CPU",
                CgroupResourceKind::Memory => "Memory",
                CgroupResourceKind::Io => "I/O",
            };
            let mechanism = finding.mechanism.map(mechanism_label);
            let mut evidence = vec![finding.evidence.psi_some_fraction.map_or_else(
                || "Scoped PSI unavailable".into(),
                |fraction| format!("Scoped {resource} PSI some {:.2}%", fraction * 100.0),
            )];
            if let Some(label) = mechanism {
                evidence.push(format!("Mechanism: {label}"));
            }
            if let Some(cpu) = &finding.evidence.cpu.value {
                evidence.push(format!(
                    "Controller CPU usage +{}; throttled +{}",
                    human_duration(Duration::from_micros(cpu.usage_usec.unwrap_or(0))),
                    human_duration(Duration::from_micros(cpu.throttled_usec.unwrap_or(0)))
                ));
            }
            if let Some(current) = finding.evidence.memory_current_end.value {
                evidence.push(format!(
                    "memory.current {}",
                    human_bytes(u128::from(current))
                ));
            }
            if let Some(events) = &finding.evidence.memory_events.value {
                evidence.push(format!(
                    "memory.events high/max/oom_kill {}/{}/{}",
                    optional_counter(events.high),
                    optional_counter(events.max),
                    optional_counter(events.oom_kill)
                ));
            }
            if let Some(io) = &finding.evidence.io.value {
                let read = io.values().filter_map(|value| value.rbytes).sum::<u64>();
                let write = io.values().filter_map(|value| value.wbytes).sum::<u64>();
                evidence.push(format!(
                    "Controller I/O +{} read / +{} write across {} device(s)",
                    human_bytes(u128::from(read)),
                    human_bytes(u128::from(write)),
                    io.len()
                ));
            }
            if let Some(unit) = &finding.systemd_unit_candidate {
                evidence.push(format!(
                    "systemd path candidate: {} (not authoritative)",
                    terminal_text(unit, 80)
                ));
            }
            findings.push(FindingView {
                id: format!("cgroup:{}:{resource}", finding.path),
                resource,
                scope: terminal_text(&finding.path, 120),
                title: terminal_text(&finding.summary, 120),
                severity: finding.severity,
                confidence: finding.resource_confidence,
                psi_some_fraction: finding.evidence.psi_some_fraction,
                affected: finding
                    .members
                    .iter()
                    .map(|member| CandidateView {
                        name: format!("{} [{}]", terminal_text(&member.name, 48), member.key.pid),
                        metric: "stable cgroup member".into(),
                        confidence: Confidence::Low,
                    })
                    .collect(),
                contributors: Vec::new(),
                evidence,
                qualifiers: finding
                    .qualifiers
                    .iter()
                    .map(|value| value.message.to_owned())
                    .collect(),
            });
        }

        let memory_finding = memory.as_ref().and_then(|value| value.findings.first());
        let io_finding = io.as_ref().and_then(|value| value.findings.first());
        let chains =
            analysis::analyze_evidence_chains(memory_finding, io_finding, &cgroups.findings)
                .into_iter()
                .map(|chain| ChainView {
                    summary: terminal_text(&chain.summary, 160),
                    confidence: chain.confidence,
                })
                .collect();

        findings.sort_by(|left, right| {
            severity_rank(right.severity)
                .cmp(&severity_rank(left.severity))
                .then_with(|| {
                    confidence_rank(right.confidence).cmp(&confidence_rank(left.confidence))
                })
                .then_with(|| left.id.cmp(&right.id))
        });
        let any_pressure = resources
            .iter()
            .any(|value| value.state == ResourceState::Pressure)
            || findings
                .iter()
                .any(|value| value.severity != Severity::None);
        let any_incomplete = resources.iter().any(|value| {
            matches!(
                value.state,
                ResourceState::Inconclusive | ResourceState::Unavailable
            )
        });
        let status = if any_pressure {
            OverallStatus::Degraded
        } else if any_incomplete {
            OverallStatus::Incomplete
        } else {
            OverallStatus::Healthy
        };

        Self {
            status,
            requested_duration_ms,
            resources,
            findings,
            chains,
            limitations: limitations.into_iter().collect(),
        }
    }
}

fn unavailable_resource(name: &'static str) -> ResourceView {
    ResourceView {
        name,
        state: ResourceState::Unavailable,
        severity: Severity::None,
        confidence: Confidence::Low,
        psi_some_fraction: None,
    }
}

fn mechanism_label(mechanism: CgroupMechanism) -> &'static str {
    match mechanism {
        CgroupMechanism::Reclaim => "reclaim",
        CgroupMechanism::Swap => "swap",
        CgroupMechanism::PossibleThrashing => "possible thrashing",
        CgroupMechanism::CpuQuotaThrottle => "CPU quota throttle",
    }
}

pub const fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::None => "none",
        Severity::Low => "low",
        Severity::Moderate => "moderate",
        Severity::High => "high",
        Severity::Severe => "severe",
    }
}

pub const fn confidence_name(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Low => "low",
        Confidence::Medium => "medium",
        Confidence::High => "high",
    }
}

pub const fn severity_rank(severity: Severity) -> u8 {
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

pub fn terminal_text(value: &str, max_chars: usize) -> String {
    let mut rendered = String::new();
    for character in value.chars().take(max_chars) {
        rendered.push(if character.is_control() {
            '\u{fffd}'
        } else {
            character
        });
    }
    if value.chars().count() > max_chars {
        rendered.push('…');
    }
    if rendered.is_empty() {
        "<unnamed>".into()
    } else {
        rendered
    }
}

pub fn human_duration(duration: Duration) -> String {
    let micros = duration.as_micros();
    if micros >= 1_000_000 {
        format!("{:.2}s", micros as f64 / 1_000_000.0)
    } else if micros >= 1_000 {
        format!("{:.1}ms", micros as f64 / 1_000.0)
    } else {
        format!("{micros}µs")
    }
}

fn human_bytes(bytes: u128) -> String {
    const KIB: u128 = 1_024;
    const MIB: u128 = KIB * 1_024;
    const GIB: u128 = MIB * 1_024;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

fn optional_counter(value: Option<u64>) -> String {
    value.map_or_else(|| "unavailable".into(), |value| value.to_string())
}

fn optional_window(value: Option<u128>) -> String {
    value.map_or_else(
        || "unavailable".into(),
        |value| {
            human_duration(Duration::from_micros(
                u64::try_from(value).unwrap_or(u64::MAX),
            ))
        },
    )
}
