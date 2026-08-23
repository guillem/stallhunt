//! Compact hunt/replay snapshot renderer.
//!
//! Default output is facts: health, PSI bars, ranked findings, compact
//! related-evidence. Narrative qualifiers and static kind help are appended
//! only when `--explain` is set.

use std::time::Duration;

use crate::analysis::{
    self, AssessmentKind, CgroupAssessmentKind, CgroupFinding, CgroupMechanism, CgroupResourceKind,
    Confidence, CpuFinding, EvidenceChain, IoAssessmentKind, IoFinding, MemoryAssessmentKind,
    MemoryFinding, Severity,
};
use crate::cgroup::{cgroup_capability_explanation, cgroup_capability_from_observation};
use crate::cli::{HuntOptions, TextStyle};
use crate::observe::{
    CgroupHuntObservation, HuntObservation, IoHuntObservation, MemoryHuntObservation,
};
use crate::style::{
    confidence_name, human_bytes, human_duration, human_duration_from_duration, paint_severity,
    pressure_bar, psi_percent, severity_abbrev, terminal_name,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    Healthy,
    Degraded,
    Incomplete,
    Unavailable,
}

impl Health {
    fn label(self) -> &'static str {
        match self {
            Self::Healthy => "HEALTHY",
            Self::Degraded => "DEGRADED",
            Self::Incomplete => "INCOMPLETE",
            Self::Unavailable => "UNAVAILABLE",
        }
    }
}

pub fn hunt_text(options: &HuntOptions, result: &HuntObservation) -> String {
    let style = options.style;
    let analyzed = AnalyzedHunt::from_observation(result);
    let mut output = String::new();
    output.push_str(&header(
        options.duration_ms,
        analyzed.health,
        &analyzed.incomplete,
        style,
    ));
    output.push('\n');
    output.push_str(&resource_row("CPU", &analyzed.cpu_row, style));
    output.push_str(&resource_row("MEM", &analyzed.memory_row, style));
    output.push_str(&resource_row("I/O", &analyzed.io_row, style));
    output.push('\n');

    if analyzed.cpu_row.status.contains("no scheduling contention") {
        output.push_str("CPU victims/suspects not ranked without a contention finding.\n");
    }
    if analyzed.io_row.status.contains("no block-I/O pressure") {
        output.push_str("I/O candidates not ranked without an I/O pressure finding.\n");
    }
    if analyzed.health == Health::Healthy {
        output.push_str("No significant resource contention detected.\n");
        if let Some(busy) = &analyzed.busiest {
            output.push_str(&format!("Busy ≠ bottleneck: {busy}\n"));
        }
        output.push('\n');
    }

    for (index, card) in analyzed.cards.iter().enumerate() {
        output.push_str(&finding_card(index + 1, card, style));
        output.push('\n');
    }

    if !analyzed.chains.is_empty() {
        output.push_str("Related evidence\n");
        for chain in &analyzed.chains {
            output.push_str(&chain_line(chain, style));
        }
        output.push('\n');
    }

    if !analyzed.cgroups.is_empty() {
        output.push_str("Scoped cgroup findings\n");
        for line in &analyzed.cgroups {
            output.push_str(line);
        }
        output.push_str("Scoped findings are not host-causality claims; overlapping ancestor and child scopes are not summed.\n");
        output.push('\n');
    } else if analyzed.cgroup_empty_note {
        output.push_str("Scoped cgroup findings\nNo scoped cgroup pressure findings are prominent; healthy, unavailable, and short-window groups are omitted from this bounded text summary.\n\n");
    }

    if let Some(unavailable) = &analyzed.unavailable_notes {
        output.push_str(unavailable);
        if !unavailable.ends_with('\n') {
            output.push('\n');
        }
        output.push('\n');
    }

    if !analyzed.timing.is_empty() {
        output.push_str(&analyzed.timing);
        output.push('\n');
    }

    if style.explain {
        output.push_str(&explain_section(&analyzed));
    } else {
        output.push_str("Explain: stallhunt --explain     Evidence: stallhunt --json\n");
    }
    output
}

struct AnalyzedHunt {
    health: Health,
    incomplete: Vec<&'static str>,
    cpu_row: ResourceRow,
    memory_row: ResourceRow,
    io_row: ResourceRow,
    cards: Vec<FindingCard>,
    chains: Vec<EvidenceChain>,
    cgroups: Vec<String>,
    cgroup_empty_note: bool,
    busiest: Option<String>,
    timing: String,
    unavailable_notes: Option<String>,
    explain_blocks: Vec<ExplainBlock>,
}

struct ResourceRow {
    psi: Option<f64>,
    severity: Severity,
    status: String,
    extra: Option<String>,
}

struct FindingCard {
    title: String,
    severity: Severity,
    confidence: Confidence,
    impact: String,
    lines: Vec<(String, String)>,
    cue: Option<String>,
    qualifiers: Vec<String>,
    help: &'static str,
}

struct ExplainBlock {
    title: String,
    help: &'static str,
    qualifiers: Vec<String>,
}

impl AnalyzedHunt {
    fn from_observation(result: &HuntObservation) -> Self {
        let cpu = analysis::analyze_cpu(result.psi.as_ref().ok(), result.cpu.as_ref().ok());
        let memory = result
            .memory
            .as_ref()
            .map(|memory| {
                analysis::analyze_memory(memory.psi.as_ref().ok(), memory.context.as_ref().ok())
            })
            .unwrap_or_default();
        let io = result
            .io
            .as_ref()
            .map(|io| {
                analysis::analyze_io(
                    io.psi.as_ref().ok(),
                    io.diskstats.as_ref().ok(),
                    io.processes.as_ref().ok(),
                )
            })
            .unwrap_or_default();
        let cgroup_analysis = result
            .cgroup
            .as_ref()
            .and_then(|cgroup| cgroup.observation.as_ref().ok())
            .map(|observation| analysis::analyze_cgroups(Some(observation)))
            .unwrap_or_default();
        let chains = analysis::analyze_evidence_chains(
            memory.findings.first(),
            io.findings.first(),
            &cgroup_analysis.findings,
        );

        let cpu_finding = cpu.findings.first();
        let memory_finding = memory.findings.first();
        let io_finding = io.findings.first();

        let cpu_row = cpu_resource_row(result, cpu_finding);
        let memory_row = memory_resource_row(result.memory.as_ref(), memory_finding);
        let io_row = io_resource_row(result.io.as_ref(), io_finding);

        let mut cards = Vec::new();
        let mut explain_blocks = Vec::new();
        if let Some(finding) = cpu_finding {
            if finding.kind != AssessmentKind::CpuNoMeaningfulContention {
                let card = cpu_card(finding, result.cpu.is_ok());
                explain_blocks.push(ExplainBlock {
                    title: card.title.clone(),
                    help: card.help,
                    qualifiers: card.qualifiers.clone(),
                });
                cards.push(card);
            }
        }
        if let Some(finding) = memory_finding {
            if finding.kind != MemoryAssessmentKind::NoHarmfulPressure {
                let card = memory_card(finding);
                explain_blocks.push(ExplainBlock {
                    title: card.title.clone(),
                    help: card.help,
                    qualifiers: card.qualifiers.clone(),
                });
                cards.push(card);
            }
        }
        if let Some(finding) = io_finding {
            if finding.kind != IoAssessmentKind::NoMeaningfulContention {
                let card = io_card(finding);
                explain_blocks.push(ExplainBlock {
                    title: card.title.clone(),
                    help: card.help,
                    qualifiers: card.qualifiers.clone(),
                });
                cards.push(card);
            }
        }
        cards.sort_by(|left, right| {
            severity_rank(right.severity)
                .cmp(&severity_rank(left.severity))
                .then_with(|| left.title.cmp(&right.title))
        });

        let pressured_cgroups: Vec<&CgroupFinding> = cgroup_analysis
            .findings
            .iter()
            .filter(|finding| finding.kind == CgroupAssessmentKind::Pressure)
            .take(10)
            .collect();
        let cgroup_empty_note = result.cgroup.is_some()
            && result
                .cgroup
                .as_ref()
                .is_some_and(|cgroup| cgroup.observation.is_ok())
            && pressured_cgroups.is_empty();
        let cgroups = pressured_cgroups
            .iter()
            .map(|finding| cgroup_line(finding))
            .collect();

        for finding in &pressured_cgroups {
            explain_blocks.push(ExplainBlock {
                title: finding.summary.clone(),
                help: CGROUP_HELP,
                qualifiers: finding
                    .qualifiers
                    .iter()
                    .map(|qualifier| qualifier.message.to_string())
                    .collect(),
            });
        }
        for chain in &chains {
            explain_blocks.push(ExplainBlock {
                title: chain.summary.clone(),
                help: CHAIN_HELP,
                qualifiers: chain
                    .qualifiers
                    .iter()
                    .map(|qualifier| qualifier.message.to_string())
                    .collect(),
            });
        }

        let incomplete = incomplete_tags(result);
        let health = health_from(
            cpu_finding,
            memory_finding,
            io_finding,
            !pressured_cgroups.is_empty(),
            result.psi.is_err() && cpu_finding.is_none(),
            !incomplete.is_empty(),
        );
        let busiest = if health == Health::Healthy {
            busiest_consumer(result)
        } else {
            None
        };
        let unavailable_notes = unavailable_block(result);
        let timing = timing_line(result);

        Self {
            health,
            incomplete,
            cpu_row,
            memory_row,
            io_row,
            cards,
            chains,
            cgroups,
            cgroup_empty_note,
            busiest,
            timing,
            unavailable_notes,
            explain_blocks,
        }
    }
}

fn health_from(
    cpu: Option<&CpuFinding>,
    memory: Option<&MemoryFinding>,
    io: Option<&IoFinding>,
    cgroup_pressure: bool,
    cpu_unavailable: bool,
    incomplete: bool,
) -> Health {
    let degraded = cpu.is_some_and(|finding| finding.kind == AssessmentKind::CpuContention)
        || memory.is_some_and(|finding| {
            matches!(
                finding.kind,
                MemoryAssessmentKind::Pressure
                    | MemoryAssessmentKind::ReclaimPressure
                    | MemoryAssessmentKind::SwapPressure
                    | MemoryAssessmentKind::PossibleThrashing
            )
        })
        || io.is_some_and(|finding| finding.kind == IoAssessmentKind::Pressure)
        || cgroup_pressure;
    if degraded {
        Health::Degraded
    } else if cpu_unavailable {
        Health::Unavailable
    } else if cpu.is_some_and(|finding| finding.kind == AssessmentKind::InsufficientObservation)
        && (incomplete || (memory.is_none() && io.is_none()))
    {
        Health::Incomplete
    } else {
        Health::Healthy
    }
}

fn incomplete_tags(result: &HuntObservation) -> Vec<&'static str> {
    let mut tags = Vec::new();
    if result.cpu.is_err() {
        tags.push("cpu");
    }
    if let Some(memory) = &result.memory {
        if memory.psi.is_err() || memory.context.is_err() {
            tags.push("memory");
        }
    }
    if let Some(io) = &result.io {
        if io.psi.is_err() || io.diskstats.is_err() || io.processes.is_err() {
            tags.push("io");
        }
    }
    if let Some(cgroup) = &result.cgroup {
        match &cgroup.observation {
            Err(_) => tags.push("cgroup"),
            Ok(observation) => {
                let capability = cgroup_capability_from_observation(observation);
                if capability != crate::cgroup::CgroupCapability::Available {
                    tags.push("cgroup");
                }
            }
        }
    }
    tags
}

fn cpu_resource_row(result: &HuntObservation, finding: Option<&CpuFinding>) -> ResourceRow {
    match (result.psi.as_ref(), finding) {
        (Ok(_psi), Some(finding)) => ResourceRow {
            psi: Some(finding.evidence.psi_some_fraction),
            severity: finding.severity,
            status: match finding.kind {
                AssessmentKind::CpuContention => "scheduling contention".into(),
                AssessmentKind::CpuNoMeaningfulContention => "no scheduling contention".into(),
                AssessmentKind::InsufficientObservation => "insufficient observation".into(),
            },
            extra: None,
        },
        (Ok(psi), None) => ResourceRow {
            psi: Some(psi.interval.some_fraction),
            severity: Severity::None,
            status: "assessment unavailable".into(),
            extra: None,
        },
        (Err(_), _) => ResourceRow {
            psi: None,
            severity: Severity::None,
            status: "unavailable".into(),
            extra: Some("no exact CPU PSI interval".into()),
        },
    }
}

fn memory_resource_row(
    memory: Option<&MemoryHuntObservation>,
    finding: Option<&MemoryFinding>,
) -> ResourceRow {
    let Some(memory) = memory else {
        return ResourceRow {
            psi: None,
            severity: Severity::None,
            status: "unavailable".into(),
            extra: None,
        };
    };
    match (memory.psi.as_ref(), finding) {
        (Ok(_), Some(finding)) => {
            let extra = finding
                .evidence
                .memory_occupancy_fraction
                .map(|fraction| format!("{:.0}% occupied · host-wide", fraction * 100.0));
            ResourceRow {
                psi: Some(finding.evidence.psi_some_fraction),
                severity: finding.severity,
                status: match finding.kind {
                    MemoryAssessmentKind::NoHarmfulPressure => "no harmful pressure".into(),
                    MemoryAssessmentKind::Pressure => "active pressure".into(),
                    MemoryAssessmentKind::ReclaimPressure => "reclaim pressure".into(),
                    MemoryAssessmentKind::SwapPressure => "swap pressure".into(),
                    MemoryAssessmentKind::PossibleThrashing => "possible thrashing".into(),
                    MemoryAssessmentKind::InsufficientObservation => {
                        "insufficient observation".into()
                    }
                },
                extra,
            }
        }
        _ => ResourceRow {
            psi: None,
            severity: Severity::None,
            status: "unavailable".into(),
            extra: Some("no exact memory PSI interval".into()),
        },
    }
}

fn io_resource_row(io: Option<&IoHuntObservation>, finding: Option<&IoFinding>) -> ResourceRow {
    let Some(io) = io else {
        return ResourceRow {
            psi: None,
            severity: Severity::None,
            status: "unavailable".into(),
            extra: None,
        };
    };
    match (io.psi.as_ref(), finding) {
        (Ok(_), Some(finding)) => ResourceRow {
            psi: Some(finding.evidence.psi_some_fraction),
            severity: finding.severity,
            status: match finding.kind {
                IoAssessmentKind::NoMeaningfulContention => "no block-I/O pressure".into(),
                IoAssessmentKind::Pressure => "block-I/O pressure".into(),
                IoAssessmentKind::InsufficientObservation => "insufficient observation".into(),
            },
            extra: None,
        },
        _ => ResourceRow {
            psi: None,
            severity: Severity::None,
            status: "unavailable".into(),
            extra: Some("no exact I/O PSI interval".into()),
        },
    }
}

fn cpu_card(finding: &CpuFinding, cpu_context_available: bool) -> FindingCard {
    let victim_attribution_limited = finding
        .qualifiers
        .iter()
        .any(|qualifier| qualifier.kind == "victim_attribution_limited");
    let suspect_attribution_limited = finding
        .qualifiers
        .iter()
        .any(|qualifier| qualifier.kind == "suspect_attribution_limited");
    let mut lines = Vec::new();
    if !cpu_context_available {
        lines.push(("victims".into(), "unavailable".into()));
        lines.push(("suspects".into(), "unavailable".into()));
    } else if finding.kind == AssessmentKind::InsufficientObservation {
        lines.push((
            "victims".into(),
            "not assessed for a short observation".into(),
        ));
        lines.push((
            "suspects".into(),
            "not assessed for a short observation".into(),
        ));
    } else if finding.kind == AssessmentKind::CpuNoMeaningfulContention {
        lines.push((
            "victims".into(),
            "not ranked without a contention finding".into(),
        ));
        lines.push((
            "suspects".into(),
            "not ranked without a contention finding".into(),
        ));
    } else {
        if !finding.victims.is_empty() {
            let listed = finding
                .victims
                .iter()
                .map(|victim| {
                    format!(
                        "{} [{}] — {} delay",
                        terminal_name(&victim.name),
                        victim.key.pid,
                        human_duration_from_duration(Duration::from_nanos(victim.runnable_wait_ns))
                    )
                })
                .collect::<Vec<_>>()
                .join(" · ");
            lines.push(("victims".into(), listed));
        } else if victim_attribution_limited {
            lines.push(("victims".into(), "unavailable or incomplete".into()));
        } else {
            lines.push((
                "victims".into(),
                "no positive stable runnable-delay candidates".into(),
            ));
        }
        if !finding.suspects.is_empty() {
            let listed = finding
                .suspects
                .iter()
                .map(|suspect| {
                    format!(
                        "{} [{}] {:.1}%",
                        terminal_name(&suspect.name),
                        suspect.key.pid,
                        suspect.cpu_fraction_of_one * 100.0
                    )
                })
                .collect::<Vec<_>>()
                .join(" · ");
            lines.push(("suspects".into(), listed));
        } else if suspect_attribution_limited {
            lines.push(("suspects".into(), "unavailable or incomplete".into()));
        } else {
            lines.push((
                "suspects".into(),
                "no consumers above 25% of one CPU".into(),
            ));
        }
    }
    for qualifier in &finding.qualifiers {
        if qualifier.message.contains("partial") {
            lines.push(("limit".into(), qualifier.message.to_string()));
        }
    }
    let cue = (finding.kind == AssessmentKind::CpuContention)
        .then(|| "same-window; not causal".to_owned());
    FindingCard {
        title: match finding.kind {
            AssessmentKind::CpuContention => "CPU scheduling contention".into(),
            AssessmentKind::CpuNoMeaningfulContention => {
                "No meaningful CPU scheduling contention".into()
            }
            AssessmentKind::InsufficientObservation => "CPU insufficient observation".into(),
        },
        severity: finding.severity,
        confidence: finding.resource_confidence,
        impact: format!(
            "PSI some {} · {} stalled / {}",
            psi_percent(finding.evidence.psi_some_fraction),
            human_duration_from_duration(Duration::from_micros(
                finding.evidence.psi_total_delta_us
            )),
            human_duration_from_duration(Duration::from_micros(
                finding.evidence.psi_window_us as u64
            )),
        ),
        lines,
        cue,
        qualifiers: finding
            .qualifiers
            .iter()
            .map(|qualifier| qualifier.message.to_string())
            .collect(),
        help: CPU_HELP,
    }
}

fn memory_card(finding: &MemoryFinding) -> FindingCard {
    let mut lines = Vec::new();
    lines.push((
        "attrib".into(),
        "unavailable (host-wide evidence only)".into(),
    ));
    if let Some(occupancy) = finding.evidence.memory_occupancy_fraction {
        lines.push((
            "occupancy".into(),
            format!(
                "{:.1}% occupied (context, not a verdict)",
                occupancy * 100.0
            ),
        ));
    }
    FindingCard {
        title: match finding.kind {
            MemoryAssessmentKind::NoHarmfulPressure => "No harmful memory pressure".into(),
            MemoryAssessmentKind::Pressure => "Memory pressure".into(),
            MemoryAssessmentKind::ReclaimPressure => "Memory reclaim pressure".into(),
            MemoryAssessmentKind::SwapPressure => "Memory swap pressure".into(),
            MemoryAssessmentKind::PossibleThrashing => "Possible memory thrashing".into(),
            MemoryAssessmentKind::InsufficientObservation => {
                "Memory insufficient observation".into()
            }
        },
        severity: finding.severity,
        confidence: finding.resource_confidence,
        impact: format!(
            "PSI some {}{}",
            psi_percent(finding.evidence.psi_some_fraction),
            finding
                .mechanism_confidence
                .map(|confidence| format!(
                    " · mechanism confidence {}",
                    confidence_name(confidence)
                ))
                .unwrap_or_default()
        ),
        lines,
        cue: Some("host-wide; occupancy is context and is not itself evidence".into()),
        qualifiers: finding
            .qualifiers
            .iter()
            .map(|qualifier| qualifier.message.to_string())
            .collect(),
        help: MEMORY_HELP,
    }
}

fn io_card(finding: &IoFinding) -> FindingCard {
    let mut lines = Vec::new();
    if finding.kind == IoAssessmentKind::Pressure {
        if finding.device_candidates.is_empty() {
            lines.push((
                "disks".into(),
                "unavailable or no positive stable activity".into(),
            ));
        } else {
            let listed = finding
                .device_candidates
                .iter()
                .map(|candidate| {
                    format!("{} (activity, not mapped)", terminal_name(&candidate.name))
                })
                .collect::<Vec<_>>()
                .join(" · ");
            lines.push(("disks".into(), listed));
        }
        if finding.process_suspects.is_empty() {
            lines.push((
                "procs".into(),
                "unavailable or no positive stable activity".into(),
            ));
        } else {
            let listed = finding
                .process_suspects
                .iter()
                .map(|candidate| {
                    format!(
                        "{} [{}] (activity, not causal)",
                        terminal_name(&candidate.name),
                        candidate.key.pid
                    )
                })
                .collect::<Vec<_>>()
                .join(" · ");
            lines.push(("procs".into(), listed));
        }
        lines.push((
            "victims".into(),
            "unavailable (this telemetry does not identify I/O stall victims or map processes to devices)".into(),
        ));
    } else {
        lines.push((
            "candidates".into(),
            "not ranked without an I/O pressure finding".into(),
        ));
    }
    FindingCard {
        title: match finding.kind {
            IoAssessmentKind::NoMeaningfulContention => "No meaningful block-I/O pressure".into(),
            IoAssessmentKind::Pressure => "Block-I/O pressure".into(),
            IoAssessmentKind::InsufficientObservation => "I/O insufficient observation".into(),
        },
        severity: finding.severity,
        confidence: finding.resource_confidence,
        impact: format!(
            "PSI some {}",
            psi_percent(finding.evidence.psi_some_fraction)
        ),
        lines,
        cue: (finding.kind == IoAssessmentKind::Pressure)
            .then(|| "same-window activity; not proven causal or device-mapped".into()),
        qualifiers: finding
            .qualifiers
            .iter()
            .map(|qualifier| qualifier.message.to_string())
            .collect(),
        help: IO_HELP,
    }
}

fn cgroup_line(finding: &CgroupFinding) -> String {
    let mechanism = match finding.mechanism {
        Some(CgroupMechanism::Reclaim) => " reclaim",
        Some(CgroupMechanism::Swap) => " swap",
        Some(CgroupMechanism::PossibleThrashing) => " possible thrashing",
        Some(CgroupMechanism::CpuQuotaThrottle) => " quota-throttle",
        None => "",
    };
    let resource = match finding.resource {
        CgroupResourceKind::Cpu => "cpu",
        CgroupResourceKind::Memory => "memory",
        CgroupResourceKind::Io => "io",
    };
    let mut line = format!(
        "Cgroup  {}  {resource} {}{mechanism}  conf {}{}\n",
        finding.path,
        severity_abbrev(finding.severity),
        confidence_name(finding.resource_confidence),
        finding
            .mechanism_confidence
            .map(|confidence| format!(" · mechanism confidence {}", confidence_name(confidence)))
            .unwrap_or_default()
    );
    line.push_str(&format!("        {}\n", finding.summary));
    if let Some(unit) = &finding.systemd_unit_candidate {
        line.push_str(&format!(
            "        systemd path candidate: {unit} (not authoritative)\n"
        ));
    }
    if !finding.members.is_empty() {
        line.push_str(&format!(
            "        stable members: {}\n",
            finding
                .members
                .iter()
                .map(|member| member.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    line.push_str(&cgroup_controller_context(finding));
    line
}

fn cgroup_controller_context(finding: &CgroupFinding) -> String {
    let evidence = &finding.evidence;
    let mut lines = Vec::new();
    if let Some(cpu) = &evidence.cpu.value {
        let mut context = format!(
            "CPU usage +{}",
            human_duration_from_duration(Duration::from_micros(cpu.usage_usec.unwrap_or(0)))
        );
        if let Some(throttled) = cpu.throttled_usec {
            context.push_str(&format!(
                "; throttled +{}",
                human_duration_from_duration(Duration::from_micros(throttled))
            ));
        }
        lines.push(context);
    }
    if let Some(current) = evidence.memory_current_end.value {
        let mut context = format!("memory.current {}", human_bytes(current));
        if let Some(events) = &evidence.memory_events.value {
            if let Some(oom_kill) = events.oom_kill {
                context.push_str(&format!("; oom_kill +{oom_kill}"));
            }
            if let Some(high) = events.high {
                context.push_str(&format!("; high events +{high}"));
            }
        }
        lines.push(context);
    }
    if let Some(stat) = &evidence.memory_stat.value {
        let mut parts = Vec::new();
        if let Some(pages) = stat.pgscan_direct.filter(|pages| *pages > 0) {
            parts.push(format!("{pages} direct-reclaim scan pages"));
        }
        if let Some(pages) = stat.pgsteal_direct.filter(|pages| *pages > 0) {
            parts.push(format!("{pages} stolen pages"));
        }
        if let Some(pages) = stat.pswpin.filter(|pages| *pages > 0) {
            parts.push(format!("{pages} swap-in pages"));
        }
        if let Some(pages) = stat.pswpout.filter(|pages| *pages > 0) {
            parts.push(format!("{pages} swap-out pages"));
        }
        if !parts.is_empty() {
            lines.push(parts.join("; "));
        }
    }
    if let Some(io) = &evidence.io.value {
        let read = io.values().filter_map(|device| device.rbytes).sum::<u64>();
        let write = io.values().filter_map(|device| device.wbytes).sum::<u64>();
        if read != 0 || write != 0 {
            lines.push(format!(
                "I/O +{} read / +{} write across {} controller device(s)",
                human_bytes(read),
                human_bytes(write),
                io.len()
            ));
        }
    }
    if lines.is_empty() {
        "        controller context: unavailable or incomplete\n".to_owned()
    } else {
        format!(
            "        controller context: {} (scoped context only; not causal proof)\n",
            lines.join("; ")
        )
    }
}

fn chain_line(chain: &EvidenceChain, style: TextStyle) -> String {
    let compact = match chain.kind {
        analysis::ChainKind::MemoryMechanismConsistentWithIo => {
            format!(
                "{} ~ I/O  ({}; consistent with, not a causal claim)\n",
                chain
                    .summary
                    .split(" is consistent")
                    .next()
                    .unwrap_or("memory"),
                confidence_name(chain.confidence)
            )
        }
        analysis::ChainKind::CgroupMemoryConsistentWithIo => format!(
            "cgroup memory ~ I/O  ({}; consistent with, not a causal claim)\n",
            confidence_name(chain.confidence)
        ),
    };
    if !style.explain {
        return compact;
    }
    let mut output = compact;
    output.push_str(&format!("{}\n", chain.summary));
    output.push_str(&format!(
        "Confidence: {}\nIndependent evidence: {}.\n",
        confidence_name(chain.confidence),
        chain_evidence_details(chain)
    ));
    for qualifier in &chain.qualifiers {
        output.push_str(&format!("  {}\n", qualifier.message));
    }
    output
}

fn chain_evidence_details(chain: &EvidenceChain) -> String {
    let evidence = &chain.evidence;
    let mut parts = Vec::new();
    if let Some(path) = &evidence.path {
        parts.push(format!("cgroup {path}"));
    }
    parts.push(format!(
        "memory PSI some {}",
        psi_percent(evidence.memory_psi_some_fraction)
    ));
    parts.push(format!(
        "I/O PSI some {}",
        psi_percent(evidence.io_psi_some_fraction)
    ));
    if let Some(pages) = evidence.scan_direct_pages.filter(|pages| *pages > 0) {
        parts.push(format!("{pages} direct-reclaim scan pages"));
    }
    if let Some(pages) = evidence.steal_direct_pages.filter(|pages| *pages > 0) {
        parts.push(format!("{pages} stolen pages"));
    }
    if let Some(pages) = evidence.swap_in_pages.filter(|pages| *pages > 0) {
        parts.push(format!("{pages} swap-in pages"));
    }
    if let Some(pages) = evidence.swap_out_pages.filter(|pages| *pages > 0) {
        parts.push(format!("{pages} swap-out pages"));
    }
    if let Some(events) = evidence.high_events.filter(|events| *events > 0) {
        parts.push(format!("{events} memory.high events"));
    }
    if let Some(events) = evidence.max_events.filter(|events| *events > 0) {
        parts.push(format!("{events} memory.max events"));
    }
    parts.join("; ")
}

fn busiest_consumer(result: &HuntObservation) -> Option<String> {
    let cpu = result.cpu.as_ref().ok()?;
    let process = cpu.processes.iter().max_by(|left, right| {
        left.cpu_fraction_of_one
            .partial_cmp(&right.cpu_fraction_of_one)
            .unwrap_or(std::cmp::Ordering::Equal)
    })?;
    if process.cpu_fraction_of_one < 0.25 {
        return None;
    }
    Some(format!(
        "{} [{}]  {:.0}% of one CPU",
        terminal_name(&process.name),
        process.key.pid,
        process.cpu_fraction_of_one * 100.0
    ))
}

fn unavailable_block(result: &HuntObservation) -> Option<String> {
    let mut notes = String::new();
    match (&result.psi, &result.cpu) {
        (Err(error), Ok(cpu)) => {
            notes.push_str("CPU assessment unavailable\n");
            notes.push_str(&format!(
                "Capability: CPU PSI {} — {}\n",
                error.capability().as_str(),
                error.explanation()
            ));
            notes.push_str(&format!(
                "Retained context: host CPU {:.1}% busy across {} logical CPUs; {} stable process CPU interval(s); {} scheduler-delay candidate(s) ({}).\n",
                cpu.host.utilization_fraction * 100.0,
                cpu.host.cpu_count,
                cpu.processes.len(),
                cpu.scheduler_delay_candidates.len(),
                cpu.schedstat_capability.as_str(),
            ));
            notes.push_str("CPU/process context was collected but cannot establish CPU contention without exact-interval PSI.\n");
        }
        (Err(error), Err(_)) => {
            notes.push_str("CPU assessment unavailable\n");
            notes.push_str(&format!(
                "Capability: CPU PSI {} — {}\n",
                error.capability().as_str(),
                error.explanation()
            ));
            notes
                .push_str("CPU/process context was also unavailable; no diagnosis was produced.\n");
        }
        (Ok(_), Err(error)) => {
            notes.push_str(&format!(
                "CPU/process telemetry: unavailable — {}\n",
                error.explanation()
            ));
            notes.push_str("CPU interval context is unavailable\n");
        }
        _ => {}
    }
    if let Some(CgroupHuntObservation {
        observation: Err(_),
    }) = &result.cgroup
    {
        notes.push_str("Cgroup v2 assessment unavailable.\n");
        notes.push_str(&format!(
            "{}\n",
            cgroup_capability_explanation(crate::cgroup::CgroupCapability::Failed)
        ));
    }
    if notes.is_empty() { None } else { Some(notes) }
}

fn timing_line(result: &HuntObservation) -> String {
    let mut parts = Vec::new();
    if let Ok(psi) = &result.psi {
        parts.push(format!(
            "PSI {}",
            human_duration_from_duration(psi.interval.elapsed)
        ));
    }
    if let Ok(cpu) = &result.cpu {
        parts.push(format!("CPU {}", human_duration_from_duration(cpu.elapsed)));
    }
    if let Some(memory) = &result.memory {
        if let Ok(psi) = &memory.psi {
            parts.push(format!(
                "memory PSI {}",
                human_duration_from_duration(psi.interval.elapsed)
            ));
        }
    }
    if let Some(io) = &result.io {
        if let Ok(psi) = &io.psi {
            parts.push(format!(
                "I/O PSI {}",
                human_duration_from_duration(psi.interval.elapsed)
            ));
        }
    }
    if parts.is_empty() {
        return String::new();
    }
    format!("Timing  {}", parts.join(" · "))
}

fn header(duration_ms: u64, health: Health, incomplete: &[&str], style: TextStyle) -> String {
    let health_label = paint_severity(
        health.label(),
        match health {
            Health::Healthy => Severity::None,
            Health::Degraded => Severity::High,
            Health::Incomplete | Health::Unavailable => Severity::Moderate,
        },
        style.color,
    );
    if incomplete.is_empty() {
        format!(
            "stallhunt  {}  {health_label}\n",
            human_duration(duration_ms)
        )
    } else {
        format!(
            "stallhunt  {}  {health_label}  incomplete:{}\n",
            human_duration(duration_ms),
            incomplete.join(",")
        )
    }
}

fn resource_row(label: &str, row: &ResourceRow, style: TextStyle) -> String {
    let bar = match row.psi {
        Some(fraction) => pressure_bar(fraction, style.unicode),
        None => {
            if style.unicode {
                "░░░░░░░░░░".into()
            } else {
                "[----------]".into()
            }
        }
    };
    let psi = row.psi.map(psi_percent).unwrap_or_else(|| "     --".into());
    let severity = paint_severity(severity_abbrev(row.severity), row.severity, style.color);
    let extra = row
        .extra
        .as_deref()
        .map(|extra| format!(" · {extra}"))
        .unwrap_or_default();
    format!(
        " {label:<4} {bar} {psi:>7}  {severity:<4}  {}{extra}\n",
        row.status
    )
}

fn finding_card(index: usize, card: &FindingCard, style: TextStyle) -> String {
    let severity = paint_severity(severity_abbrev(card.severity), card.severity, style.color);
    let mut output = format!(
        "{index}  {:<36}  {severity}  conf {}\n",
        card.title,
        confidence_name(card.confidence)
    );
    output.push_str(&format!("   impact    {}\n", card.impact));
    for (label, value) in &card.lines {
        output.push_str(&format!("   {label:<8}  {value}\n"));
    }
    if let Some(cue) = &card.cue {
        output.push_str(&format!("   note      {cue}\n"));
    }
    output
}

fn explain_section(analyzed: &AnalyzedHunt) -> String {
    let mut output = String::from("Explain\n");
    for block in &analyzed.explain_blocks {
        output.push_str(&format!("  {}\n    {}\n", block.title, block.help));
        for qualifier in &block.qualifiers {
            output.push_str(&format!("    {qualifier}\n"));
        }
    }
    output.push_str("Evidence: stallhunt --json\n");
    output
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

const CPU_HELP: &str = "CPU PSI some is the share of the observation during which some tasks were stalled on the run queue. Victim candidates are stable-thread runnable-delay observations, not confirmed user-visible harm. Suspect candidates consumed CPU in the same window; that correlation does not prove they caused the delay.";
const MEMORY_HELP: &str = "Memory PSI some is the sole host-wide pressure verdict. Occupancy, reclaim, and swap counters classify or qualify that verdict. This slice has no process attribution.";
const IO_HELP: &str = "I/O PSI some is the sole block-I/O pressure verdict. Disk and process I/O-accounting candidates are same-window activity, not victims, device mappings, or causal claims.";
const CGROUP_HELP: &str = "Per-cgroup PSI is a verdict about that scope only. Controller deltas and path-derived systemd names are scoped context, never host or cross-cgroup causality.";
const CHAIN_HELP: &str = "A related-evidence chain requires independent mechanism evidence in the same window. It is consistent with a shared path and is not a causal claim.";
