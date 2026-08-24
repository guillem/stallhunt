use std::path::Path;
use std::time::Duration;

use serde::Serialize;

use crate::analysis::{
    self, AnalysisResult, AssessmentKind, CgroupAssessmentKind, IoAssessmentKind,
};
use crate::cgroup::{
    CgroupCapability, CgroupObservation, cgroup_capability_explanation,
    cgroup_capability_from_observation,
};
use crate::cli::{CapabilitiesOptions, HuntOptions, OutputFormat, RedactOptions, ReplayOptions};
use crate::cpu::{CpuProcessObservation, CpuTelemetryCapabilities};
use crate::io::{DiskstatsError, IoCapabilities, IoCapability, ProcessIoObservation};
use crate::memory::{
    MemoryContextCapabilities, MemoryContextCapability, MemoryContextObservation, VmstatCounter,
};
use crate::observe::{
    CgroupHuntObservation, HuntObservation, IoHuntObservation, MemoryHuntObservation,
};
use crate::psi::{
    CpuPsiCapability, CpuPsiObservation, IoPsiCapability, IoPsiFullInterval, IoPsiObservation,
    MemoryPsiCapability, MemoryPsiFullInterval, MemoryPsiObservation,
};
use crate::style::{confidence_name, severity_name};

pub fn version() -> String {
    format!("stallhunt {}\n", env!("CARGO_PKG_VERSION"))
}

pub fn record_written(path: &Path, recording: &crate::record::Recording) -> String {
    let redaction = match recording.redaction {
        crate::record::Redaction::None => {
            "redaction none; this file can contain process names, cgroup paths, and device names"
        }
        crate::record::Redaction::Identifiers => {
            "redaction identifiers; names and paths were replaced, counters and process keys were kept"
        }
    };
    format!(
        "Wrote recording to {} (schema {}, {redaction}).\nReplay with: stallhunt replay {}\n",
        path.display(),
        recording.schema_version,
        path.display()
    )
}

pub fn replay(
    options: &ReplayOptions,
    recording: crate::record::Recording,
) -> Result<String, crate::record::RecordError> {
    let observation = crate::record::observation_from_recording(&recording)?;
    hunt(
        &HuntOptions {
            duration_ms: recording.requested_duration_ms,
            output: options.output,
            verbose: false,
            no_color: false,
        },
        |_| observation,
    )
    .map_err(crate::record::RecordError::from)
}

pub fn redact_written(options: &RedactOptions, recording: &crate::record::Recording) -> String {
    record_written(&options.output, recording)
}

pub fn hunt<F>(options: &HuntOptions, observe: F) -> Result<String, serde_json::Error>
where
    F: FnOnce(Duration) -> HuntObservation,
{
    let result = observe(Duration::from_millis(options.duration_ms));
    match options.output {
        OutputFormat::Text => Ok(hunt_text(options, result)),
        OutputFormat::Json => hunt_json(options, result),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn capabilities(
    options: &CapabilitiesOptions,
    cpu_psi: CpuPsiCapability,
    cpu: CpuTelemetryCapabilities,
    memory_psi: MemoryPsiCapability,
    memory: MemoryContextCapabilities,
    io_psi: IoPsiCapability,
    io: IoCapabilities,
    cgroup: CgroupCapability,
) -> Result<String, serde_json::Error> {
    match options.output {
        OutputFormat::Text => Ok(format!(
            "Telemetry capabilities\n\nCPU PSI: {}\n{}\nHost /proc/stat: {}\nProcess /proc/<pid>/stat: {}\nTask /proc/<tgid>/task/<tid>/schedstat: {}\n{}\nMemory PSI: {}\n{}\nHost /proc/meminfo: {}\nHost /proc/vmstat: {}\nI/O PSI: {}\n{}\nHost /proc/diskstats: {}\nProcess /proc/<pid>/io: {}\nCgroup v2: {}\n{}\n",
            cpu_psi.as_str(),
            cpu_psi.explanation(),
            cpu.host_cpu.as_str(),
            cpu.process_stat.as_str(),
            cpu.process_schedstat.as_str(),
            cpu.process_schedstat.explanation(),
            memory_psi.as_str(),
            memory_psi.explanation(),
            memory.meminfo.as_str(),
            memory.vmstat.as_str(),
            io_psi.as_str(),
            io_psi.explanation(),
            io.diskstats.as_str(),
            io.process_io.as_str(),
            cgroup.as_str(),
            cgroup_capability_explanation(cgroup),
        )),
        OutputFormat::Json => to_json(&CapabilitiesJson {
            schema_version: 2,
            tool_version: env!("CARGO_PKG_VERSION"),
            status: "observed",
            capabilities: CapabilitiesJsonValue {
                cpu_psi: CapabilityJson {
                    state: cpu_psi.as_str(),
                    message: cpu_psi.explanation(),
                },
                host_cpu: cpu.host_cpu.as_str(),
                process_stat: cpu.process_stat.as_str(),
                process_schedstat: CapabilityJson {
                    state: cpu.process_schedstat.as_str(),
                    message: cpu.process_schedstat.explanation(),
                },
                memory_psi: CapabilityJson {
                    state: memory_psi.as_str(),
                    message: memory_psi.explanation(),
                },
                meminfo: memory.meminfo.as_str(),
                vmstat: memory.vmstat.as_str(),
                io_psi: CapabilityJson {
                    state: io_psi.as_str(),
                    message: io_psi.explanation(),
                },
                diskstats: io.diskstats.as_str(),
                process_io: io.process_io.as_str(),
                cgroup_v2: CapabilityJson {
                    state: cgroup.as_str(),
                    message: cgroup_capability_explanation(cgroup),
                },
            },
        }),
    }
}

/// Every analyzer's result for one hunt observation, computed exactly once
/// so text and JSON renderers (and future presentation surfaces) never
/// re-derive a diagnosis — see docs/architecture.md's presentation-purity
/// rule.
pub(crate) struct HuntAnalyses {
    pub(crate) cpu: AnalysisResult,
    pub(crate) memory: Option<crate::analysis::MemoryAnalysisResult>,
    pub(crate) io: Option<crate::analysis::IoAnalysisResult>,
    pub(crate) cgroup: Option<crate::analysis::CgroupAnalysisResult>,
    pub(crate) process_scopes: Vec<crate::analysis::ProcessScope>,
}

pub(crate) fn analyze_hunt(result: &HuntObservation) -> HuntAnalyses {
    let cpu = analysis::analyze_cpu(result.psi.as_ref().ok(), result.cpu.as_ref().ok());
    let memory = result.memory.as_ref().map(|memory| {
        analysis::analyze_memory(memory.psi.as_ref().ok(), memory.context.as_ref().ok())
    });
    let io = result.io.as_ref().map(|io| {
        analysis::analyze_io(
            io.psi.as_ref().ok(),
            io.diskstats.as_ref().ok(),
            io.processes.as_ref().ok(),
        )
    });
    let cgroup = result
        .cgroup
        .as_ref()
        .and_then(|cgroup| cgroup.observation.as_ref().ok())
        .map(|observation| analysis::analyze_cgroups(Some(observation)));
    let cpu_pressure = cpu.findings.first().and_then(|finding| {
        (finding.kind == AssessmentKind::CpuContention).then_some(finding.resource_confidence)
    });
    let memory_pressure = memory
        .as_ref()
        .and_then(|result| result.findings.first())
        .and_then(|finding| {
            matches!(
                finding.kind,
                crate::analysis::MemoryAssessmentKind::Pressure
                    | crate::analysis::MemoryAssessmentKind::ReclaimPressure
                    | crate::analysis::MemoryAssessmentKind::SwapPressure
                    | crate::analysis::MemoryAssessmentKind::PossibleThrashing
            )
            .then_some(finding.resource_confidence)
        });
    let io_pressure = io
        .as_ref()
        .and_then(|result| result.findings.first())
        .and_then(|finding| {
            (finding.kind == IoAssessmentKind::Pressure).then_some(finding.resource_confidence)
        });
    let process_io = result
        .io
        .as_ref()
        .and_then(|value| value.processes.as_ref().ok());
    let mut process_scopes = vec![analysis::host_process_scope(
        result.cpu.as_ref().ok(),
        process_io,
        cpu_pressure,
        memory_pressure,
        io_pressure,
    )];
    process_scopes.extend(analysis::cgroup_process_scopes(
        result
            .cgroup
            .as_ref()
            .and_then(|value| value.observation.as_ref().ok()),
        result.cpu.as_ref().ok(),
        process_io,
    ));
    HuntAnalyses {
        cpu,
        memory,
        io,
        cgroup,
        process_scopes,
    }
}

fn hunt_text(options: &HuntOptions, result: HuntObservation) -> String {
    let analyses = analyze_hunt(&result);
    let cpu_rank = analyses
        .cpu
        .findings
        .first()
        .map(|finding| text_finding_rank(finding.severity, finding.resource_confidence))
        .unwrap_or((0, 0));
    let memory_rank = analyses
        .memory
        .as_ref()
        .and_then(|memory| {
            memory
                .findings
                .first()
                .map(|finding| text_finding_rank(finding.severity, finding.resource_confidence))
        })
        .unwrap_or((0, 0));
    let io_rank = analyses
        .io
        .as_ref()
        .and_then(|io| {
            io.findings
                .first()
                .map(|finding| text_finding_rank(finding.severity, finding.resource_confidence))
        })
        .unwrap_or((0, 0));
    let chain_text = evidence_chain_hunt_text(&analyses);
    let cpu_output = cpu_hunt_text(options, result.psi, result.cpu, &analyses.cpu);
    let mut outputs = vec![(cpu_rank, 0_u8, cpu_output)];
    if let Some(memory) = result.memory {
        outputs.push((
            memory_rank,
            1,
            memory_hunt_text(options, memory, analyses.memory.as_ref()),
        ));
    }
    if let Some(io) = result.io {
        outputs.push((io_rank, 2, io_hunt_text(options, io, analyses.io.as_ref())));
    }
    if result.cgroup.is_some() {
        let output = cgroup_hunt_text(analyses.cgroup.as_ref());
        if !output.is_empty() {
            outputs.push((cgroup_text_rank(analyses.cgroup.as_ref()), 3, output));
        }
    }
    outputs.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
    let mut text = outputs
        .into_iter()
        .map(|(_, _, output)| output)
        .collect::<Vec<_>>()
        .join("\n");
    if let Some(chain_text) = chain_text {
        if !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&chain_text);
    }
    // Legacy text continues to render the existing finding fields; schema-2
    // JSON carries the canonical complete role collection.
    text.push_str(&process_scope_hunt_text(&analyses.process_scopes));
    text
}

/// Legacy/piped hunt and replay output is intentionally less dense than JSON,
/// but it still exposes every canonical role instead of silently dropping new
/// attribution classes.
fn process_scope_hunt_text(scopes: &[crate::analysis::ProcessScope]) -> String {
    use crate::analysis::{ProcessCandidateAvailability, ProcessRole};
    let Some(scope) = scopes.first() else {
        return "\nProcess roles\n  unavailable\n".into();
    };
    let mut output = String::from("\nProcess roles (host scope)\n");
    for role in [
        ProcessRole::CpuVictim,
        ProcessRole::CpuSuspect,
        ProcessRole::MemoryVictim,
        ProcessRole::MemorySuspect,
        ProcessRole::IoVictim,
        ProcessRole::IoSuspect,
    ] {
        let list = scope.roles.iter().find(|list| list.role == role);
        let title = match role {
            ProcessRole::CpuVictim => "CPU victims",
            ProcessRole::CpuSuspect => "CPU suspects",
            ProcessRole::MemoryVictim => "Memory victims",
            ProcessRole::MemorySuspect => "Memory suspects",
            ProcessRole::IoVictim => "I/O victims",
            ProcessRole::IoSuspect => "I/O suspects",
        };
        match list {
            Some(list) if !list.candidates.is_empty() => {
                let candidates = list
                    .candidates
                    .iter()
                    .map(|candidate| {
                        format!(
                            "{} [{}]: {} ({:?}; {:?})",
                            crate::cpu::sanitized_process_name(&candidate.name),
                            candidate.key.pid,
                            candidate.label,
                            candidate.confidence,
                            candidate.evidence
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                output.push_str(&format!(
                    "  {title}{}: {candidates}\n",
                    if list.completeness == crate::analysis::ProcessRoleCompleteness::Partial {
                        " (partial)"
                    } else {
                        ""
                    }
                ));
            }
            Some(list) => {
                let state = match list.availability {
                    ProcessCandidateAvailability::Available => "no positive candidates",
                    ProcessCandidateAvailability::UnavailableOrIncomplete => {
                        "unavailable or incomplete"
                    }
                    ProcessCandidateAvailability::NotAssessed => "not assessed",
                };
                output.push_str(&format!("  {title}: {state}\n"));
            }
            None => output.push_str(&format!("  {title}: unavailable\n")),
        }
    }
    output
}

fn evidence_chain_hunt_text(analyses: &HuntAnalyses) -> Option<String> {
    let chains = evidence_chains_from_analyses(analyses);
    if chains.is_empty() {
        return None;
    }
    let mut output = String::from("Related evidence\n");
    for chain in chains {
        output.push_str(&format!(
            "{}\nConfidence: {}\nIndependent evidence: {}.\n",
            chain.summary,
            confidence_name(chain.confidence),
            chain_evidence_details(&chain.evidence),
        ));
        for qualifier in chain.qualifiers {
            output.push_str(&format!("  {}\n", qualifier.message));
        }
    }
    Some(output)
}

pub(crate) fn evidence_chains_from_analyses(
    analyses: &HuntAnalyses,
) -> Vec<crate::analysis::EvidenceChain> {
    let memory = analyses
        .memory
        .as_ref()
        .and_then(|memory| memory.findings.first());
    let io = analyses.io.as_ref().and_then(|io| io.findings.first());
    let cgroup_findings: &[crate::analysis::CgroupFinding] = analyses
        .cgroup
        .as_ref()
        .map(|cgroup| cgroup.findings.as_slice())
        .unwrap_or(&[]);
    analysis::analyze_evidence_chains(memory, io, cgroup_findings)
}

pub(crate) fn chain_evidence_details(evidence: &crate::analysis::ChainEvidence) -> String {
    let mut parts = Vec::new();
    if let Some(path) = &evidence.path {
        parts.push(format!("cgroup {path}"));
    }
    parts.push(format!(
        "memory PSI some {:.2}%",
        evidence.memory_psi_some_fraction * 100.0
    ));
    parts.push(format!(
        "I/O PSI some {:.2}%",
        evidence.io_psi_some_fraction * 100.0
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

fn cgroup_text_rank(analysis: Option<&crate::analysis::CgroupAnalysisResult>) -> (u8, u8) {
    let Some(analysis) = analysis else {
        return (0, 0);
    };
    analysis
        .findings
        .iter()
        .map(|finding| text_finding_rank(finding.severity, finding.resource_confidence))
        .max()
        .unwrap_or((0, 0))
}

fn cgroup_hunt_text(analysis: Option<&crate::analysis::CgroupAnalysisResult>) -> String {
    let Some(analysis) = analysis else {
        return "Scoped cgroup findings\nCgroup v2 assessment unavailable.\n".into();
    };
    let pressured: Vec<_> = analysis
        .findings
        .iter()
        .filter(|finding| finding.kind == CgroupAssessmentKind::Pressure)
        .take(10)
        .collect();
    if pressured.is_empty() {
        return "Scoped cgroup findings\nNo scoped cgroup pressure findings are prominent; healthy, unavailable, and short-window groups are omitted from this bounded text summary.\n".into();
    }
    let mut output = String::from("Scoped cgroup findings\n");
    for finding in pressured {
        output.push_str(&format!(
            "- {} · {} · severity {} · confidence {}",
            finding.path,
            finding.summary,
            severity_name(finding.severity),
            confidence_name(finding.resource_confidence)
        ));
        if let Some(mechanism_confidence) = finding.mechanism_confidence {
            output.push_str(&format!(
                " · mechanism confidence {}",
                confidence_name(mechanism_confidence)
            ));
        }
        output.push('\n');
        if let Some(unit) = &finding.systemd_unit_candidate {
            output.push_str(&format!(
                "  systemd path candidate: {unit} (not authoritative)\n"
            ));
        }
        if !finding.members.is_empty() {
            output.push_str(&format!(
                "  stable members: {}\n",
                finding
                    .members
                    .iter()
                    .map(|member| member.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        output.push_str(&cgroup_controller_context(finding));
    }
    output.push_str("Scoped findings are not host-causality claims; overlapping ancestor and child scopes are not summed.\n");
    output
}

fn cgroup_controller_context(finding: &crate::analysis::CgroupFinding) -> String {
    let evidence = &finding.evidence;
    let mut lines = Vec::new();
    if let Some(cpu) = &evidence.cpu.value {
        let mut context = format!(
            "CPU usage +{}",
            human_duration_from_duration(Duration::from_micros(cpu.usage_usec.unwrap_or(0),))
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
        "  controller context: unavailable or incomplete\n".to_owned()
    } else {
        format!(
            "  controller context: {} (scoped context only; not causal proof)\n",
            lines.join("; ")
        )
    }
}

fn cpu_hunt_text(
    options: &HuntOptions,
    psi: Result<CpuPsiObservation, crate::psi::CpuPsiError>,
    cpu: Result<CpuProcessObservation, crate::cpu::CpuError>,
    analysis: &AnalysisResult,
) -> String {
    match (psi, cpu) {
        (Ok(observation), Ok(cpu)) => finding_text(
            analysis,
            options.duration_ms,
            observation.interval.elapsed,
            Some(cpu.elapsed),
        ),
        (Err(error), Ok(cpu)) => format!(
            "CPU assessment unavailable\nVerdict: unavailable (no exact CPU PSI interval)\nCapability: CPU PSI {} — {}\nRetained context: host CPU {:.1}% busy across {} logical CPUs; {} stable process CPU interval(s); {} scheduler-delay candidate(s) ({}).\nLimitations:\n  CPU/process context was collected but cannot establish CPU contention without exact-interval PSI.\nTiming: requested {}; CPU/process measured {}\n",
            error.capability().as_str(),
            error.explanation(),
            cpu.host.utilization_fraction * 100.0,
            cpu.host.cpu_count,
            cpu.processes.len(),
            cpu.scheduler_delay_candidates.len(),
            cpu.schedstat_capability.as_str(),
            human_duration(options.duration_ms),
            human_duration_from_duration(cpu.elapsed),
        ),
        (Err(error), Err(_)) => format!(
            "CPU assessment unavailable\nVerdict: unavailable (no exact CPU PSI interval)\nCapability: CPU PSI {} — {}\nLimitations:\n  CPU/process context was also unavailable; no diagnosis was produced.\nTiming: requested {}\n",
            error.capability().as_str(),
            error.explanation(),
            human_duration(options.duration_ms),
        ),
        (Ok(psi), Err(error)) => {
            let mut output =
                finding_text(analysis, options.duration_ms, psi.interval.elapsed, None);
            output.push_str(&format!(
                "CPU/process telemetry: unavailable — {}\n",
                error.explanation()
            ));
            output
        }
    }
}

pub(crate) fn text_finding_rank(
    severity: crate::analysis::Severity,
    confidence: crate::analysis::Confidence,
) -> (u8, u8) {
    let severity = match severity {
        crate::analysis::Severity::None => 0,
        crate::analysis::Severity::Low => 1,
        crate::analysis::Severity::Moderate => 2,
        crate::analysis::Severity::High => 3,
        crate::analysis::Severity::Severe => 4,
    };
    let confidence = match confidence {
        crate::analysis::Confidence::Low => 0,
        crate::analysis::Confidence::Medium => 1,
        crate::analysis::Confidence::High => 2,
    };
    (severity, confidence)
}

fn memory_hunt_text(
    options: &HuntOptions,
    memory: MemoryHuntObservation,
    analysis: Option<&crate::analysis::MemoryAnalysisResult>,
) -> String {
    let analysis = analysis.expect("memory analysis is precomputed whenever memory is Some");
    match (memory.psi, memory.context) {
        (Ok(psi), Ok(context)) => {
            memory_finding_text(analysis, options.duration_ms, &psi, Some(&context))
        }
        (Ok(psi), Err(_)) => memory_finding_text(analysis, options.duration_ms, &psi, None),
        (Err(error), Ok(context)) => {
            let occupancy = context.end_meminfo.as_ref().map_or_else(
                || "unavailable".to_owned(),
                |meminfo| {
                    format!(
                        "{:.1}% occupied ({} available)",
                        (1.0 - meminfo.mem_available_bytes as f64 / meminfo.mem_total_bytes as f64)
                            * 100.0,
                        human_bytes(meminfo.mem_available_bytes)
                    )
                },
            );
            format!(
                "Memory assessment unavailable\nVerdict: unavailable (no exact memory PSI interval)\nCapability: memory PSI {} — {}\nRetained context: {occupancy}; meminfo {}; vmstat {}.\nContext and limitations:\n  Occupancy and VM counters cannot establish harmful memory pressure without exact-interval memory PSI.\nTiming: requested {}; memory context measured {}\n",
                error.capability().as_str(),
                memory_psi_error_explanation(error),
                context.meminfo_capability.as_str(),
                context.vmstat_capability.as_str(),
                human_duration(options.duration_ms),
                human_duration_from_duration(context.elapsed),
            )
        }
        (Err(error), Err(_)) => format!(
            "Memory assessment unavailable\nVerdict: unavailable (no exact memory PSI interval)\nCapability: memory PSI {} — {}\nContext and limitations:\n  Memory context was also unavailable; no memory diagnosis was produced.\nTiming: requested {}\n",
            error.capability().as_str(),
            memory_psi_error_explanation(error),
            human_duration(options.duration_ms),
        ),
    }
}

fn memory_finding_text(
    analysis: &crate::analysis::MemoryAnalysisResult,
    requested_duration_ms: u64,
    psi: &MemoryPsiObservation,
    context: Option<&MemoryContextObservation>,
) -> String {
    let Some(finding) = analysis.findings.first() else {
        return format!(
            "Memory assessment unavailable\nVerdict: unavailable\nTiming: requested {}\n",
            human_duration(requested_duration_ms)
        );
    };
    let verdict = match finding.kind {
        crate::analysis::MemoryAssessmentKind::NoHarmfulPressure => "no harmful pressure",
        crate::analysis::MemoryAssessmentKind::Pressure => "active pressure",
        crate::analysis::MemoryAssessmentKind::ReclaimPressure => "reclaim pressure",
        crate::analysis::MemoryAssessmentKind::SwapPressure => "swap pressure",
        crate::analysis::MemoryAssessmentKind::PossibleThrashing => "possible thrashing",
        crate::analysis::MemoryAssessmentKind::InsufficientObservation => {
            "insufficient observation"
        }
    };
    let mechanism_confidence = finding.mechanism_confidence.map_or_else(
        || "unavailable".to_string(),
        |confidence| confidence_name(confidence).to_string(),
    );
    let mut output = format!(
        "{}\nVerdict: {verdict} · severity {} · pressure confidence {} · mechanism confidence {mechanism_confidence}\nEvidence: memory PSI some {:.2}% over exact {} interval ({} cumulative stalled time)",
        finding.summary,
        severity_name(finding.severity),
        confidence_name(finding.resource_confidence),
        finding.evidence.psi_some_fraction * 100.0,
        human_duration_from_duration(psi.interval.elapsed),
        human_duration_from_duration(Duration::from_micros(
            finding.evidence.psi_some_total_delta_us
        )),
    );
    if let (Some(fraction), Some(total)) = (
        finding.evidence.psi_full_fraction,
        finding.evidence.psi_full_total_delta_us,
    ) {
        output.push_str(&format!(
            "; full {:.2}% ({} all-non-idle-task stall)",
            fraction * 100.0,
            human_duration_from_duration(Duration::from_micros(total))
        ));
    } else {
        output.push_str("; full unavailable or excluded");
    }
    output.push('\n');
    if let (Some(occupancy), Some(available), Some(total)) = (
        finding.evidence.memory_occupancy_fraction,
        finding.evidence.memory_available_bytes,
        finding.evidence.memory_total_bytes,
    ) {
        output.push_str(&format!(
            "Memory context: {:.1}% occupied; {} available of {} total",
            occupancy * 100.0,
            human_bytes(available),
            human_bytes(total),
        ));
        if let Some(swap_used) = finding.evidence.swap_used_bytes {
            output.push_str(&format!("; {} swap allocated", human_bytes(swap_used)));
        }
        output.push('\n');
    } else {
        output.push_str("Memory context: unavailable or incomplete\n");
    }
    let vm_delta =
        |counter| context.and_then(|context| context.vmstat_deltas.get(&counter).copied());
    output.push_str(&format!(
        "VM interval context: direct scan/steal {}/{} pages; swap in/out {}/{} pages; major faults {}\n",
        optional_counter(vm_delta(VmstatCounter::ScanDirect)),
        optional_counter(vm_delta(VmstatCounter::StealDirect)),
        optional_counter(vm_delta(VmstatCounter::SwapIn)),
        optional_counter(vm_delta(VmstatCounter::SwapOut)),
        optional_counter(vm_delta(VmstatCounter::MajorPageFaults)),
    ));
    output.push_str("Attribution: unavailable (host-wide evidence only)\n");
    if !finding.qualifiers.is_empty() {
        output.push_str("Context and limitations:\n");
        for qualifier in &finding.qualifiers {
            output.push_str(&format!("  {}\n", qualifier.message));
        }
    }
    output.push_str(&format!(
        "Timing: requested {}; memory PSI measured {}{}\n",
        human_duration(requested_duration_ms),
        human_duration_from_duration(psi.interval.elapsed),
        context.map_or_else(String::new, |context| format!(
            "; memory context measured {}",
            human_duration_from_duration(context.elapsed)
        )),
    ));
    output
}

fn memory_psi_error_explanation(error: crate::psi::MemoryPsiError) -> &'static str {
    match error {
        crate::psi::MemoryPsiError::Unsupported => {
            "The kernel does not expose /proc/pressure/memory."
        }
        crate::psi::MemoryPsiError::PermissionDenied => {
            "Permission was denied while reading memory PSI."
        }
        crate::psi::MemoryPsiError::Unreadable => "Memory PSI could not be read.",
        crate::psi::MemoryPsiError::Malformed => {
            "Memory PSI was readable but did not match the expected kernel format."
        }
        crate::psi::MemoryPsiError::CounterRegressed => {
            "Memory PSI `some` cumulative total decreased during the observation."
        }
        crate::psi::MemoryPsiError::EmptyInterval => {
            "Memory PSI snapshots did not have a measurable interval."
        }
        crate::psi::MemoryPsiError::DeltaExceedsElapsed => {
            "Memory PSI `some` cumulative delta exceeded the measured interval."
        }
        crate::psi::MemoryPsiError::FullExceedsSome => {
            "Memory PSI `full` exceeded `some` and was rejected as inconsistent."
        }
    }
}

fn io_hunt_text(
    options: &HuntOptions,
    io: IoHuntObservation,
    analysis: Option<&crate::analysis::IoAnalysisResult>,
) -> String {
    match (io.psi, io.diskstats, io.processes) {
        (Ok(psi), diskstats, processes) => io_finding_text(
            analysis.expect("io analysis is precomputed whenever io is Some"),
            options.duration_ms,
            &psi,
            diskstats.as_ref().ok(),
            processes.as_ref().ok(),
        ),
        (Err(error), diskstats, processes) => format!(
            "I/O assessment unavailable\nVerdict: unavailable (no exact I/O PSI interval)\nCapability: I/O PSI {} — {}\nRetained context: diskstats {}; process I/O {}.\nContext and limitations:\n  Disk and process I/O activity cannot establish block-I/O pressure without exact-interval I/O PSI.\nTiming: requested {}{}{}\n",
            error.capability().as_str(),
            io_psi_error_explanation(error),
            diskstats
                .as_ref()
                .map_or("failed", |value| value.capability.as_str()),
            processes
                .as_ref()
                .map_or("failed", |value| value.capability.as_str()),
            human_duration(options.duration_ms),
            diskstats.as_ref().map_or_else(
                |_| String::new(),
                |value| format!(
                    "; diskstats measured {}",
                    human_duration_from_duration(value.elapsed)
                )
            ),
            processes.as_ref().map_or_else(
                |_| String::new(),
                |value| format!(
                    "; process I/O measured {}",
                    human_duration_from_duration(value.elapsed)
                )
            ),
        ),
    }
}

fn io_finding_text(
    analysis: &crate::analysis::IoAnalysisResult,
    requested_duration_ms: u64,
    psi: &IoPsiObservation,
    diskstats: Option<&crate::io::DiskstatsObservation>,
    processes: Option<&ProcessIoObservation>,
) -> String {
    let Some(finding) = analysis.findings.first() else {
        return format!(
            "I/O assessment unavailable\nVerdict: unavailable\nTiming: requested {}\n",
            human_duration(requested_duration_ms)
        );
    };
    let verdict = match finding.kind {
        IoAssessmentKind::NoMeaningfulContention => "no meaningful block-I/O pressure",
        IoAssessmentKind::Pressure => "block-I/O pressure",
        IoAssessmentKind::InsufficientObservation => "insufficient observation",
    };
    let mut output = format!(
        "{}\nVerdict: {verdict} · severity {} · I/O confidence {}\nEvidence: I/O PSI some {:.2}% over exact {} interval ({} cumulative stalled time)",
        finding.summary,
        severity_name(finding.severity),
        confidence_name(finding.resource_confidence),
        finding.evidence.psi_some_fraction * 100.0,
        human_duration_from_duration(psi.interval.elapsed),
        human_duration_from_duration(Duration::from_micros(
            finding.evidence.psi_some_total_delta_us
        )),
    );
    if let (Some(fraction), Some(total)) = (
        finding.evidence.psi_full_fraction,
        finding.evidence.psi_full_total_delta_us,
    ) {
        output.push_str(&format!(
            "; full {:.2}% ({} all-non-idle-task stall)",
            fraction * 100.0,
            human_duration_from_duration(Duration::from_micros(total)),
        ));
    } else {
        output.push_str("; full unavailable or excluded");
    }
    output.push('\n');
    if finding.kind == IoAssessmentKind::Pressure {
        if finding.device_candidates.is_empty() {
            output.push_str(
                "Device activity candidates: unavailable or no positive stable activity\n",
            );
        } else {
            output.push_str(
                "Device activity candidates (same window only; not mapped to workloads):\n",
            );
            for (index, candidate) in finding.device_candidates.iter().enumerate() {
                output.push_str(&format!(
                    "  {}. {} ({}:{}) — read/write {} / {} 512-byte sectors; I/O time {}; in-flight {} ({}; same-window activity only)\n",
                    index + 1,
                    terminal_name(&candidate.name),
                    candidate.key.major,
                    candidate.key.minor,
                    optional_counter(candidate.read_sectors_512),
                    optional_counter(candidate.write_sectors_512),
                    candidate.io_ticks_ms.map_or_else(|| "unavailable".to_owned(), |value| human_duration_from_duration(Duration::from_millis(value))),
                    candidate.end_in_flight,
                    confidence_name(candidate.confidence),
                ));
            }
        }
        if finding.process_suspects.is_empty() {
            output.push_str(
                "Process I/O accounting candidates: unavailable or no positive stable read/charged-write activity\n",
            );
        } else {
            output.push_str("Process I/O accounting candidates (same window only; not proven causal or device-mapped):\n");
            for (index, candidate) in finding.process_suspects.iter().enumerate() {
                output.push_str(&format!(
                    "  {}. {} [{}] — {} read + {} charged write; {} cancelled write ({}; same-window accounting only)\n",
                    index + 1,
                    terminal_name(&candidate.name),
                    candidate.key.pid,
                    optional_bytes(candidate.read_bytes),
                    optional_bytes(candidate.write_bytes),
                    optional_bytes(candidate.cancelled_write_bytes),
                    confidence_name(candidate.confidence),
                ));
            }
        }
        output.push_str("Affected workloads: unavailable (this telemetry does not identify I/O stall victims or map processes to devices)\n");
    } else {
        output.push_str(
            "Device and process activity candidates: not ranked without an I/O pressure finding\n",
        );
        output.push_str("Affected workloads: not assessed without an I/O pressure finding\n");
    }
    if !finding.qualifiers.is_empty() {
        output.push_str("Context and limitations:\n");
        for qualifier in &finding.qualifiers {
            output.push_str(&format!("  {}\n", qualifier.message));
        }
    }
    output.push_str(&format!(
        "Timing: requested {}; I/O PSI measured {}{}{}\n",
        human_duration(requested_duration_ms),
        human_duration_from_duration(psi.interval.elapsed),
        diskstats.map_or_else(String::new, |value| format!(
            "; diskstats measured {}",
            human_duration_from_duration(value.elapsed)
        )),
        processes.map_or_else(String::new, |value| format!(
            "; process I/O measured {}",
            human_duration_from_duration(value.elapsed)
        )),
    ));
    output
}

fn io_psi_error_explanation(error: crate::psi::IoPsiError) -> &'static str {
    match error {
        crate::psi::IoPsiError::Unsupported => "The kernel does not expose /proc/pressure/io.",
        crate::psi::IoPsiError::PermissionDenied => "Permission was denied while reading I/O PSI.",
        crate::psi::IoPsiError::Unreadable => "I/O PSI could not be read.",
        crate::psi::IoPsiError::Malformed => {
            "I/O PSI was readable but did not match the expected kernel format."
        }
        crate::psi::IoPsiError::CounterRegressed => {
            "I/O PSI `some` cumulative total decreased during the observation."
        }
        crate::psi::IoPsiError::EmptyInterval => {
            "I/O PSI snapshots did not have a measurable interval."
        }
        crate::psi::IoPsiError::DeltaExceedsElapsed => {
            "I/O PSI `some` cumulative delta exceeded the measured interval."
        }
        crate::psi::IoPsiError::FullExceedsSome => {
            "I/O PSI `full` exceeded `some` and was rejected as inconsistent."
        }
    }
}

fn io_error_capability(error: crate::psi::IoPsiError) -> IoPsiCapability {
    match error {
        crate::psi::IoPsiError::Unsupported => IoPsiCapability::Unsupported,
        crate::psi::IoPsiError::PermissionDenied => IoPsiCapability::PermissionDenied,
        crate::psi::IoPsiError::Unreadable
        | crate::psi::IoPsiError::Malformed
        | crate::psi::IoPsiError::FullExceedsSome => IoPsiCapability::Failed,
        crate::psi::IoPsiError::CounterRegressed
        | crate::psi::IoPsiError::EmptyInterval
        | crate::psi::IoPsiError::DeltaExceedsElapsed => IoPsiCapability::Available,
    }
}

fn optional_counter(value: Option<u64>) -> String {
    value.map_or_else(|| "unavailable".to_owned(), |value| value.to_string())
}

fn optional_bytes(value: Option<u64>) -> String {
    value.map_or_else(|| "unavailable".to_owned(), human_bytes)
}

pub(crate) fn human_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    let bytes = bytes as f64;
    if bytes >= GIB {
        format!("{:.2} GiB", bytes / GIB)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes / MIB)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes / KIB)
    } else {
        format!("{} B", bytes as u64)
    }
}

fn finding_text(
    analysis: &AnalysisResult,
    requested_duration_ms: u64,
    psi_elapsed: Duration,
    cpu_elapsed: Option<Duration>,
) -> String {
    let Some(finding) = analysis.findings.first() else {
        return format!(
            "CPU assessment unavailable\nVerdict: unavailable\nTiming: requested {}\n",
            human_duration(requested_duration_ms)
        );
    };
    let verdict = match finding.kind {
        AssessmentKind::CpuContention => "CPU scheduling contention observed",
        AssessmentKind::CpuNoMeaningfulContention => {
            "No meaningful CPU scheduling contention observed"
        }
        AssessmentKind::InsufficientObservation => {
            "CPU assessment is inconclusive (short observation)"
        }
    };
    let mut output = format!(
        "{verdict}\nVerdict: {} · severity {} · CPU confidence {}\nEvidence: CPU PSI some {:.2}% over exact {} interval ({} cumulative stalled time)\n",
        match finding.kind {
            AssessmentKind::CpuContention => "contention",
            AssessmentKind::CpuNoMeaningfulContention => "no meaningful contention",
            AssessmentKind::InsufficientObservation => "insufficient observation",
        },
        severity_name(finding.severity),
        confidence_name(finding.resource_confidence),
        finding.evidence.psi_some_fraction * 100.0,
        human_duration_from_duration(psi_elapsed),
        human_duration_from_duration(Duration::from_micros(finding.evidence.psi_total_delta_us)),
    );

    let cpu_context_available = cpu_elapsed.is_some();
    let victim_attribution_limited = finding
        .qualifiers
        .iter()
        .any(|qualifier| qualifier.kind == "victim_attribution_limited");
    let suspect_attribution_limited = finding
        .qualifiers
        .iter()
        .any(|qualifier| qualifier.kind == "suspect_attribution_limited");

    if !cpu_context_available {
        output.push_str("Victim candidates: unavailable\nSuspect candidates: unavailable\n");
    } else if finding.kind == AssessmentKind::InsufficientObservation {
        output.push_str(
            "Victim candidates: not assessed for a short observation\nSuspect candidates: not assessed for a short observation\n",
        );
    } else if finding.kind == AssessmentKind::CpuNoMeaningfulContention {
        output.push_str(
            "Victim candidates: not ranked without a contention finding\nSuspect candidates: not ranked without a contention finding\n",
        );
    } else {
        if !finding.victims.is_empty() {
            output.push_str("Victim candidates (observed runnable delay; not confirmed harm):\n");
            for (index, victim) in finding.victims.iter().enumerate() {
                output.push_str(&format!(
                    "  {}. {} [{}] — {} delay ({}; observed runnable-delay candidate)\n",
                    index + 1,
                    terminal_name(&victim.name),
                    victim.key.pid,
                    human_duration_from_duration(Duration::from_nanos(victim.runnable_wait_ns)),
                    confidence_name(victim.confidence),
                ));
            }
        } else if victim_attribution_limited {
            output.push_str(
                "Victim candidates: unavailable or incomplete (see context and limitations)\n",
            );
        } else {
            output.push_str("Victim candidates: no positive stable runnable-delay candidates\n");
        }
        if !finding.suspects.is_empty() {
            output.push_str("Suspect candidates (same window only; not proven causal):\n");
            for (index, suspect) in finding.suspects.iter().enumerate() {
                output.push_str(&format!(
                    "  {}. {} [{}] — {:.1}% of one CPU ({}; {})\n",
                    index + 1,
                    terminal_name(&suspect.name),
                    suspect.key.pid,
                    suspect.cpu_fraction_of_one * 100.0,
                    confidence_name(suspect.confidence),
                    suspect_role(suspect.label),
                ));
            }
        } else if suspect_attribution_limited {
            output.push_str(
                "Suspect candidates: unavailable or incomplete (see context and limitations)\n",
            );
        } else {
            output.push_str("Suspect candidates: no consumers above 25% of one CPU\n");
        }
    }
    if !finding.qualifiers.is_empty() {
        output.push_str("Context and limitations:\n");
        for qualifier in &finding.qualifiers {
            output.push_str(&format!("  {}\n", qualifier.message));
        }
    }
    output.push_str(&format!(
        "Timing: requested {}; PSI measured {}{}\n",
        human_duration(requested_duration_ms),
        human_duration_from_duration(psi_elapsed),
        cpu_elapsed.map_or_else(String::new, |elapsed| format!(
            "; CPU/process measured {}",
            human_duration_from_duration(elapsed)
        )),
    ));
    output
}

pub(crate) fn suspect_role(label: &str) -> &'static str {
    match label {
        "leading_concurrent_cpu_consumer" => "leading concurrent CPU consumer",
        _ => "concurrent CPU consumer",
    }
}

pub(crate) fn terminal_name(name: &str) -> String {
    const MAX_CHARS: usize = 48;
    let mut rendered = String::new();
    for character in name.chars().take(MAX_CHARS) {
        if character.is_control() {
            rendered.push('\u{fffd}');
        } else {
            rendered.push(character);
        }
    }
    if name.chars().count() > MAX_CHARS {
        rendered.push('…');
    }
    if rendered.is_empty() {
        "<unnamed>".to_owned()
    } else {
        rendered
    }
}

fn hunt_json(options: &HuntOptions, result: HuntObservation) -> Result<String, serde_json::Error> {
    let cpu = cpu_json_parts(result.psi, result.cpu);
    let memory = memory_json_parts(result.memory.as_ref());
    let io = io_json_parts(result.io.as_ref());
    let cgroup = cgroup_json_parts(result.cgroup.as_ref());
    let status = if cpu.complete && memory.complete && io.complete && cgroup.complete {
        "observed"
    } else {
        "incomplete"
    };
    let evidence_chains = analysis::analyze_evidence_chains(
        memory.analysis.findings.first(),
        io.analysis.findings.first(),
        &cgroup.analysis.findings,
    );
    let findings = analysis::ranked_findings_with_io(cpu.analysis, memory.analysis, io.analysis);
    let mut process_scopes = vec![analysis::host_process_scope(
        cpu.cpu.as_ref(),
        io.processes.as_ref(),
        findings.iter().find_map(|finding| match finding {
            crate::analysis::Finding::Cpu(value) if value.kind == AssessmentKind::CpuContention => {
                Some(value.resource_confidence)
            }
            _ => None,
        }),
        findings.iter().find_map(|finding| match finding {
            crate::analysis::Finding::Memory(value)
                if matches!(
                    value.kind,
                    crate::analysis::MemoryAssessmentKind::Pressure
                        | crate::analysis::MemoryAssessmentKind::ReclaimPressure
                        | crate::analysis::MemoryAssessmentKind::SwapPressure
                        | crate::analysis::MemoryAssessmentKind::PossibleThrashing
                ) =>
            {
                Some(value.resource_confidence)
            }
            _ => None,
        }),
        findings.iter().find_map(|finding| match finding {
            crate::analysis::Finding::Io(value) if value.kind == IoAssessmentKind::Pressure => {
                Some(value.resource_confidence)
            }
            _ => None,
        }),
    )];
    process_scopes.extend(analysis::cgroup_process_scopes(
        cgroup.observation.as_ref(),
        cpu.cpu.as_ref(),
        io.processes.as_ref(),
    ));
    let mut qualifiers = cpu.qualifiers;
    qualifiers.extend(memory.qualifiers);
    qualifiers.extend(io.qualifiers);
    let observation = if cpu.psi.is_some()
        || cpu.cpu.is_some()
        || memory.psi.is_some()
        || memory.context.is_some()
        || io.psi.is_some()
        || io.diskstats_observation.is_some()
        || io.processes.is_some()
        || cgroup.observation.is_some()
    {
        Some(ObservationJson::from_parts(
            cpu.psi,
            cpu.cpu,
            memory.psi,
            memory.context,
            io.psi,
            io.diskstats_observation,
            io.processes,
            cgroup.observation,
        ))
    } else {
        None
    };
    to_json(&HuntJson {
        schema_version: 2,
        tool_version: env!("CARGO_PKG_VERSION"),
        status,
        requested_observation: RequestedObservation {
            duration_ms: options.duration_ms,
        },
        observation,
        capabilities: CapabilitiesJsonValue {
            cpu_psi: CapabilityJson {
                state: cpu.psi_state,
                message: cpu.psi_message,
            },
            host_cpu: cpu.host_cpu,
            process_stat: cpu.process_stat,
            process_schedstat: CapabilityJson {
                state: cpu.process_schedstat,
                message: cpu.process_schedstat_message,
            },
            memory_psi: CapabilityJson {
                state: memory.psi_state,
                message: memory.psi_message,
            },
            meminfo: memory.meminfo,
            vmstat: memory.vmstat,
            io_psi: CapabilityJson {
                state: io.psi_state,
                message: io.psi_message,
            },
            diskstats: io.diskstats,
            process_io: io.process_io,
            cgroup_v2: CapabilityJson {
                state: cgroup.state,
                message: cgroup.message,
            },
        },
        findings,
        evidence_chains,
        cgroup_findings: cgroup.analysis.findings,
        process_scopes,
        qualifiers,
    })
}

struct CgroupJsonParts {
    observation: Option<CgroupObservation>,
    state: &'static str,
    message: &'static str,
    analysis: crate::analysis::CgroupAnalysisResult,
    complete: bool,
}
fn cgroup_json_parts(cgroup: Option<&CgroupHuntObservation>) -> CgroupJsonParts {
    match cgroup {
        None => CgroupJsonParts {
            observation: None,
            state: "not_observed",
            message: "cgroup telemetry was not included in this injected observation.",
            analysis: Default::default(),
            complete: true,
        },
        Some(CgroupHuntObservation {
            observation: Ok(value),
        }) => {
            let capability = cgroup_capability_from_observation(value);
            CgroupJsonParts {
                observation: Some(value.clone()),
                state: capability.as_str(),
                message: cgroup_capability_explanation(capability),
                analysis: analysis::analyze_cgroups(Some(value)),
                complete: capability == CgroupCapability::Available,
            }
        }
        Some(CgroupHuntObservation {
            observation: Err(error),
        }) => {
            let capability = match error {
                crate::cgroup::CgroupError::Unsupported => CgroupCapability::Unsupported,
                crate::cgroup::CgroupError::PermissionDenied => CgroupCapability::PermissionDenied,
                _ => CgroupCapability::Failed,
            };
            CgroupJsonParts {
                observation: None,
                state: capability.as_str(),
                message: cgroup_capability_explanation(capability),
                analysis: Default::default(),
                complete: false,
            }
        }
    }
}

struct IoJsonParts {
    psi: Option<IoPsiObservation>,
    diskstats_observation: Option<crate::io::DiskstatsObservation>,
    processes: Option<ProcessIoObservation>,
    psi_state: &'static str,
    psi_message: &'static str,
    diskstats: &'static str,
    process_io: &'static str,
    analysis: crate::analysis::IoAnalysisResult,
    qualifiers: Vec<QualifierJson<'static>>,
    complete: bool,
}

fn io_json_parts(io: Option<&IoHuntObservation>) -> IoJsonParts {
    let Some(io) = io else {
        return IoJsonParts {
            psi: None,
            diskstats_observation: None,
            processes: None,
            psi_state: "not_observed",
            psi_message: "I/O telemetry was not included in this injected observation.",
            diskstats: "not_observed",
            process_io: "not_observed",
            analysis: crate::analysis::IoAnalysisResult::default(),
            qualifiers: vec![],
            complete: true,
        };
    };
    let analysis = analysis::analyze_io(
        io.psi.as_ref().ok(),
        io.diskstats.as_ref().ok(),
        io.processes.as_ref().ok(),
    );
    let (psi, psi_state, psi_message, psi_complete) = match &io.psi {
        Ok(psi) => {
            let capability = match psi.interval.full {
                IoPsiFullInterval::Available(_) => IoPsiCapability::Available,
                _ => IoPsiCapability::Partial,
            };
            (
                Some(*psi),
                capability.as_str(),
                psi.interval.full.explanation(),
                capability == IoPsiCapability::Available,
            )
        }
        Err(error) => (
            None,
            io_error_capability(*error).as_str(),
            io_psi_error_explanation(*error),
            false,
        ),
    };
    let (diskstats, diskstats_capability, diskstats_complete) = match &io.diskstats {
        Ok(value) => (
            Some(value.clone()),
            value.capability.as_str(),
            value.capability == IoCapability::Available,
        ),
        Err(error) => (None, diskstats_error_capability(*error).as_str(), false),
    };
    let (processes, process_io_capability, processes_complete) = match &io.processes {
        Ok(value) => (
            Some(value.clone()),
            value.capability.as_str(),
            value.capability == IoCapability::Available,
        ),
        Err(error) => (None, diskstats_error_capability(*error).as_str(), false),
    };
    let qualifiers = analysis
        .qualifiers
        .iter()
        .map(|qualifier| QualifierJson {
            kind: qualifier.kind,
            message: qualifier.message,
        })
        .collect();
    IoJsonParts {
        psi,
        diskstats_observation: diskstats,
        processes,
        psi_state,
        psi_message,
        diskstats: diskstats_capability,
        process_io: process_io_capability,
        analysis,
        qualifiers,
        complete: psi_complete && diskstats_complete && processes_complete,
    }
}

fn diskstats_error_capability(error: DiskstatsError) -> IoCapability {
    match error {
        DiskstatsError::Unsupported => IoCapability::Unsupported,
        DiskstatsError::PermissionDenied => IoCapability::PermissionDenied,
        DiskstatsError::Unreadable | DiskstatsError::Malformed | DiskstatsError::EmptyInterval => {
            IoCapability::Failed
        }
    }
}

struct CpuJsonParts {
    psi: Option<CpuPsiObservation>,
    cpu: Option<CpuProcessObservation>,
    psi_state: &'static str,
    psi_message: &'static str,
    host_cpu: &'static str,
    process_stat: &'static str,
    process_schedstat: &'static str,
    process_schedstat_message: &'static str,
    analysis: AnalysisResult,
    qualifiers: Vec<QualifierJson<'static>>,
    complete: bool,
}

fn cpu_json_parts(
    psi: Result<CpuPsiObservation, crate::psi::CpuPsiError>,
    cpu: Result<CpuProcessObservation, crate::cpu::CpuError>,
) -> CpuJsonParts {
    let analysis = analysis::analyze_cpu(psi.as_ref().ok(), cpu.as_ref().ok());
    match (psi, cpu) {
        (Ok(psi), Ok(cpu)) => {
            let process_stat = crate::cpu::process_capability(&cpu.collection_issues).as_str();
            let process_schedstat = cpu.schedstat_capability;
            CpuJsonParts {
                psi: Some(psi),
                cpu: Some(cpu),
                psi_state: "available",
                psi_message: CpuPsiCapability::Available.explanation(),
                host_cpu: "available",
                process_stat,
                process_schedstat: process_schedstat.as_str(),
                process_schedstat_message: process_schedstat.explanation(),
                analysis,
                qualifiers: vec![],
                complete: true,
            }
        }
        (Err(error), Ok(cpu)) => {
            let process_stat = crate::cpu::process_capability(&cpu.collection_issues).as_str();
            let process_schedstat = cpu.schedstat_capability;
            CpuJsonParts {
                psi: None,
                cpu: Some(cpu),
                psi_state: error.capability().as_str(),
                psi_message: error.explanation(),
                host_cpu: "available",
                process_stat,
                process_schedstat: process_schedstat.as_str(),
                process_schedstat_message: process_schedstat.explanation(),
                analysis,
                qualifiers: vec![QualifierJson {
                    kind: "capability_limit",
                    message: "CPU PSI was unavailable; host and process CPU evidence is retained without a diagnosis.",
                }],
                complete: false,
            }
        }
        (Ok(psi), Err(error)) => CpuJsonParts {
            psi: Some(psi),
            cpu: None,
            psi_state: "available",
            psi_message: CpuPsiCapability::Available.explanation(),
            host_cpu: "failed",
            process_stat: "failed",
            process_schedstat: "failed",
            process_schedstat_message: "CPU process telemetry was unavailable.",
            analysis,
            qualifiers: vec![QualifierJson {
                kind: "collection_limit",
                message: error.explanation(),
            }],
            complete: false,
        },
        (Err(error), Err(cpu_error)) => CpuJsonParts {
            psi: None,
            cpu: None,
            psi_state: error.capability().as_str(),
            psi_message: error.explanation(),
            host_cpu: "failed",
            process_stat: "failed",
            process_schedstat: "failed",
            process_schedstat_message: "CPU process telemetry was unavailable.",
            analysis,
            qualifiers: vec![QualifierJson {
                kind: "capability_limit",
                message: cpu_error.explanation(),
            }],
            complete: false,
        },
    }
}

struct MemoryJsonParts {
    psi: Option<MemoryPsiObservation>,
    context: Option<MemoryContextObservation>,
    psi_state: &'static str,
    psi_message: &'static str,
    meminfo: &'static str,
    vmstat: &'static str,
    analysis: crate::analysis::MemoryAnalysisResult,
    qualifiers: Vec<QualifierJson<'static>>,
    complete: bool,
}

fn memory_json_parts(memory: Option<&MemoryHuntObservation>) -> MemoryJsonParts {
    let Some(memory) = memory else {
        return MemoryJsonParts {
            psi: None,
            context: None,
            psi_state: "not_observed",
            psi_message: "Memory telemetry was not included in this injected observation.",
            meminfo: "not_observed",
            vmstat: "not_observed",
            analysis: crate::analysis::MemoryAnalysisResult::default(),
            qualifiers: vec![],
            complete: true,
        };
    };
    let analysis = analysis::analyze_memory(memory.psi.as_ref().ok(), memory.context.as_ref().ok());
    let (psi, psi_state, psi_message, psi_complete) = match &memory.psi {
        Ok(psi) => {
            let capability = match psi.interval.full {
                MemoryPsiFullInterval::Available(_) => MemoryPsiCapability::Available,
                _ => MemoryPsiCapability::Partial,
            };
            (
                Some(*psi),
                capability.as_str(),
                psi.interval.full.explanation(),
                capability == MemoryPsiCapability::Available,
            )
        }
        Err(error) => (
            None,
            error.capability().as_str(),
            memory_psi_error_explanation(*error),
            false,
        ),
    };
    let (context, meminfo, vmstat, context_complete) = match &memory.context {
        Ok(context) => (
            Some(context.clone()),
            context.meminfo_capability.as_str(),
            context.vmstat_capability.as_str(),
            context.meminfo_capability == MemoryContextCapability::Available
                && context.vmstat_capability == MemoryContextCapability::Available,
        ),
        Err(_) => (None, "failed", "failed", false),
    };
    let qualifiers = analysis
        .qualifiers
        .iter()
        .map(|qualifier| QualifierJson {
            kind: qualifier.kind,
            message: qualifier.message,
        })
        .collect();
    MemoryJsonParts {
        psi,
        context,
        psi_state,
        psi_message,
        meminfo,
        vmstat,
        analysis,
        qualifiers,
        complete: psi_complete && context_complete,
    }
}

fn to_json<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    Ok(format!("{}\n", serde_json::to_string_pretty(value)?))
}

#[derive(Serialize)]
struct CapabilitiesJson<'a> {
    schema_version: u8,
    tool_version: &'a str,
    status: &'a str,
    capabilities: CapabilitiesJsonValue<'a>,
}

#[derive(Serialize)]
struct HuntJson<'a> {
    schema_version: u8,
    tool_version: &'a str,
    status: &'a str,
    requested_observation: RequestedObservation,
    observation: Option<ObservationJson>,
    capabilities: CapabilitiesJsonValue<'a>,
    findings: Vec<crate::analysis::Finding>,
    evidence_chains: Vec<crate::analysis::EvidenceChain>,
    cgroup_findings: Vec<crate::analysis::CgroupFinding>,
    process_scopes: Vec<crate::analysis::ProcessScope>,
    qualifiers: Vec<QualifierJson<'a>>,
}

#[derive(Serialize)]
struct RequestedObservation {
    duration_ms: u64,
}

#[derive(Serialize)]
struct ObservationJson {
    psi_duration_us: Option<u128>,
    cpu_psi: Option<CpuPsiJson>,
    cpu_duration_us: Option<u128>,
    host_cpu: Option<crate::cpu::HostCpuInterval>,
    loadavg: Option<crate::cpu::LoadAverageRaw>,
    loadavg_availability: Option<crate::cpu::LoadAverageAvailability>,
    clock_ticks_per_second: Option<u64>,
    processes: Option<Vec<crate::cpu::ProcessCpuInterval>>,
    process_collection_issues: Option<crate::cpu::ProcessCollectionIssues>,
    scheduler_delay_candidates: Option<Vec<crate::cpu::ProcessSchedulerDelayInterval>>,
    schedstat_collection_issues: Option<crate::cpu::SchedstatCollectionIssues>,
    process_resource_evidence: Option<Vec<crate::cpu::ProcessResourceInterval>>,
    task_stat_collection_issues: Option<crate::cpu::TaskStatCollectionIssues>,
    taskstats: Option<Vec<crate::taskstats::TaskstatsInterval>>,
    taskstats_collection_issues: Option<crate::taskstats::TaskstatsCollectionIssues>,
    taskstats_capability: Option<crate::taskstats::TaskstatsCapability>,
    delay_accounting: Option<crate::taskstats::DelayAccountingState>,
    process_resource_capability: Option<crate::cpu::ProcessResourceCapability>,
    task_stat_capability: Option<crate::cpu::TaskStatCapability>,
    memory_psi_duration_us: Option<u128>,
    memory_psi: Option<MemoryPsiJson>,
    memory_context_duration_us: Option<u128>,
    memory_context: Option<MemoryContextObservation>,
    io_psi_duration_us: Option<u128>,
    io_psi: Option<IoPsiJson>,
    diskstats_duration_us: Option<u128>,
    diskstats: Option<crate::io::DiskstatsObservation>,
    process_io_duration_us: Option<u128>,
    process_io: Option<ProcessIoObservation>,
    cgroup_duration_us: Option<u128>,
    cgroup: Option<CgroupObservation>,
}

impl ObservationJson {
    #[allow(clippy::too_many_arguments)]
    fn from_parts(
        psi: Option<CpuPsiObservation>,
        cpu: Option<CpuProcessObservation>,
        memory_psi: Option<MemoryPsiObservation>,
        memory_context: Option<MemoryContextObservation>,
        io_psi: Option<IoPsiObservation>,
        diskstats: Option<crate::io::DiskstatsObservation>,
        process_io: Option<ProcessIoObservation>,
        cgroup: Option<CgroupObservation>,
    ) -> Self {
        let (psi_duration_us, cpu_psi) = match psi {
            Some(observation) => (
                Some(observation.interval.elapsed.as_micros()),
                Some(CpuPsiJson {
                    some_fraction: observation.interval.some_fraction,
                    some_percent: observation.interval.some_fraction * 100.0,
                    total_delta_us: observation.interval.total_delta_us,
                    avg10_percent: observation.end.avg10_percent,
                    avg60_percent: observation.end.avg60_percent,
                    avg300_percent: observation.end.avg300_percent,
                }),
            ),
            None => (None, None),
        };
        let (memory_psi_duration_us, memory_psi) = match memory_psi {
            Some(observation) => {
                let (full_fraction, full_total_delta_us, full_state) = match observation
                    .interval
                    .full
                {
                    MemoryPsiFullInterval::Available(interval) => (
                        Some(interval.fraction),
                        Some(interval.total_delta_us),
                        "available",
                    ),
                    MemoryPsiFullInterval::Missing => (None, None, "missing"),
                    MemoryPsiFullInterval::CounterRegressed => (None, None, "counter_regressed"),
                    MemoryPsiFullInterval::DeltaExceedsElapsed => {
                        (None, None, "delta_exceeds_elapsed")
                    }
                    MemoryPsiFullInterval::ExceedsSome => (None, None, "exceeds_some"),
                };
                (
                    Some(observation.interval.elapsed.as_micros()),
                    Some(MemoryPsiJson {
                        some_fraction: observation.interval.some.fraction,
                        some_percent: observation.interval.some.fraction * 100.0,
                        some_total_delta_us: observation.interval.some.total_delta_us,
                        full_fraction,
                        full_percent: full_fraction.map(|fraction| fraction * 100.0),
                        full_total_delta_us,
                        full_state,
                        some_avg10_percent: observation.end.some.avg10_percent,
                        some_avg60_percent: observation.end.some.avg60_percent,
                        some_avg300_percent: observation.end.some.avg300_percent,
                        full_avg10_percent: observation.end.full.map(|line| line.avg10_percent),
                        full_avg60_percent: observation.end.full.map(|line| line.avg60_percent),
                        full_avg300_percent: observation.end.full.map(|line| line.avg300_percent),
                    }),
                )
            }
            None => (None, None),
        };
        let memory_context_duration_us = memory_context
            .as_ref()
            .map(|context| context.elapsed.as_micros());
        let (io_psi_duration_us, io_psi) = match io_psi {
            Some(observation) => {
                let (full_fraction, full_total_delta_us, full_state) = match observation
                    .interval
                    .full
                {
                    IoPsiFullInterval::Available(interval) => (
                        Some(interval.fraction),
                        Some(interval.total_delta_us),
                        "available",
                    ),
                    IoPsiFullInterval::Missing => (None, None, "missing"),
                    IoPsiFullInterval::CounterRegressed => (None, None, "counter_regressed"),
                    IoPsiFullInterval::DeltaExceedsElapsed => (None, None, "delta_exceeds_elapsed"),
                    IoPsiFullInterval::ExceedsSome => (None, None, "exceeds_some"),
                };
                (
                    Some(observation.interval.elapsed.as_micros()),
                    Some(IoPsiJson {
                        some_fraction: observation.interval.some.fraction,
                        some_percent: observation.interval.some.fraction * 100.0,
                        some_total_delta_us: observation.interval.some.total_delta_us,
                        full_fraction,
                        full_percent: full_fraction.map(|fraction| fraction * 100.0),
                        full_total_delta_us,
                        full_state,
                        some_avg10_percent: observation.end.some.avg10_percent,
                        some_avg60_percent: observation.end.some.avg60_percent,
                        some_avg300_percent: observation.end.some.avg300_percent,
                        full_avg10_percent: observation.end.full.map(|line| line.avg10_percent),
                        full_avg60_percent: observation.end.full.map(|line| line.avg60_percent),
                        full_avg300_percent: observation.end.full.map(|line| line.avg300_percent),
                    }),
                )
            }
            None => (None, None),
        };
        let diskstats_duration_us = diskstats.as_ref().map(|value| value.elapsed.as_micros());
        let process_io_duration_us = process_io.as_ref().map(|value| value.elapsed.as_micros());
        let cgroup_duration_us = cgroup.as_ref().map(|value| value.elapsed.as_micros());
        match cpu {
            Some(cpu) => {
                let process_resource_capability = crate::cpu::process_resource_capability(&cpu);
                let task_stat_capability = crate::cpu::task_stat_capability(&cpu);
                Self {
                    psi_duration_us,
                    cpu_psi,
                    cpu_duration_us: Some(cpu.elapsed.as_micros()),
                    host_cpu: Some(cpu.host),
                    loadavg: cpu.load,
                    loadavg_availability: Some(cpu.load_availability),
                    clock_ticks_per_second: Some(cpu.clock_ticks_per_second),
                    processes: Some(cpu.processes),
                    process_collection_issues: Some(cpu.collection_issues),
                    scheduler_delay_candidates: Some(cpu.scheduler_delay_candidates),
                    schedstat_collection_issues: Some(cpu.schedstat_collection_issues),
                    process_resource_evidence: Some(cpu.process_resource_evidence),
                    task_stat_collection_issues: Some(cpu.task_stat_collection_issues),
                    taskstats: Some(cpu.taskstats),
                    taskstats_collection_issues: Some(cpu.taskstats_collection_issues),
                    taskstats_capability: Some(cpu.taskstats_capability),
                    delay_accounting: Some(cpu.delay_accounting),
                    process_resource_capability: Some(process_resource_capability),
                    task_stat_capability: Some(task_stat_capability),
                    memory_psi_duration_us,
                    memory_psi,
                    memory_context_duration_us,
                    memory_context,
                    io_psi_duration_us,
                    io_psi,
                    diskstats_duration_us,
                    diskstats,
                    process_io_duration_us,
                    process_io,
                    cgroup_duration_us,
                    cgroup,
                }
            }
            None => Self {
                psi_duration_us,
                cpu_psi,
                cpu_duration_us: None,
                host_cpu: None,
                loadavg: None,
                loadavg_availability: None,
                clock_ticks_per_second: None,
                processes: None,
                process_collection_issues: None,
                scheduler_delay_candidates: None,
                schedstat_collection_issues: None,
                process_resource_evidence: None,
                task_stat_collection_issues: None,
                taskstats: None,
                taskstats_collection_issues: None,
                taskstats_capability: None,
                delay_accounting: None,
                process_resource_capability: None,
                task_stat_capability: None,
                memory_psi_duration_us,
                memory_psi,
                memory_context_duration_us,
                memory_context,
                io_psi_duration_us,
                io_psi,
                diskstats_duration_us,
                diskstats,
                process_io_duration_us,
                process_io,
                cgroup_duration_us,
                cgroup,
            },
        }
    }
}

#[derive(Serialize)]
struct CpuPsiJson {
    some_fraction: f64,
    some_percent: f64,
    total_delta_us: u64,
    avg10_percent: f64,
    avg60_percent: f64,
    avg300_percent: f64,
}

#[derive(Serialize)]
struct MemoryPsiJson {
    some_fraction: f64,
    some_percent: f64,
    some_total_delta_us: u64,
    full_fraction: Option<f64>,
    full_percent: Option<f64>,
    full_total_delta_us: Option<u64>,
    full_state: &'static str,
    some_avg10_percent: f64,
    some_avg60_percent: f64,
    some_avg300_percent: f64,
    full_avg10_percent: Option<f64>,
    full_avg60_percent: Option<f64>,
    full_avg300_percent: Option<f64>,
}

#[derive(Serialize)]
struct IoPsiJson {
    some_fraction: f64,
    some_percent: f64,
    some_total_delta_us: u64,
    full_fraction: Option<f64>,
    full_percent: Option<f64>,
    full_total_delta_us: Option<u64>,
    full_state: &'static str,
    some_avg10_percent: f64,
    some_avg60_percent: f64,
    some_avg300_percent: f64,
    full_avg10_percent: Option<f64>,
    full_avg60_percent: Option<f64>,
    full_avg300_percent: Option<f64>,
}

#[derive(Serialize)]
struct CapabilitiesJsonValue<'a> {
    cpu_psi: CapabilityJson<'a>,
    host_cpu: &'a str,
    process_stat: &'a str,
    process_schedstat: CapabilityJson<'a>,
    memory_psi: CapabilityJson<'a>,
    meminfo: &'a str,
    vmstat: &'a str,
    io_psi: CapabilityJson<'a>,
    diskstats: &'a str,
    process_io: &'a str,
    cgroup_v2: CapabilityJson<'a>,
}

#[derive(Serialize)]
struct CapabilityJson<'a> {
    state: &'a str,
    message: &'a str,
}

#[derive(Serialize)]
struct QualifierJson<'a> {
    kind: &'a str,
    message: &'a str,
}

pub(crate) fn human_duration(duration_ms: u64) -> String {
    human_duration_from_duration(Duration::from_millis(duration_ms))
}

pub(crate) fn human_duration_from_duration(duration: Duration) -> String {
    if duration.is_zero() {
        return "0ms".to_owned();
    }
    let nanoseconds = duration.as_nanos();
    if nanoseconds != 0 && nanoseconds < 1_000 {
        return format!("{nanoseconds}ns");
    }
    if nanoseconds != 0 && nanoseconds < 1_000_000 {
        return decimal_duration(nanoseconds / 1_000, nanoseconds % 1_000, "µs");
    }
    if nanoseconds < 1_000_000_000 {
        return decimal_duration(
            nanoseconds / 1_000_000,
            (nanoseconds % 1_000_000) / 1_000,
            "ms",
        );
    }
    let milliseconds = duration.as_millis();
    if milliseconds % 60_000 == 0 {
        format!("{}m", milliseconds / 60_000)
    } else if milliseconds % 1_000 == 0 {
        format!("{}s", milliseconds / 1_000)
    } else if milliseconds >= 1_000 {
        let seconds = milliseconds / 1_000;
        let fractional_milliseconds = milliseconds % 1_000;
        let fraction = format!("{fractional_milliseconds:03}")
            .trim_end_matches('0')
            .to_owned();
        format!("{seconds}.{fraction}s")
    } else {
        format!("{milliseconds}ms")
    }
}

fn decimal_duration(whole: u128, fractional: u128, unit: &str) -> String {
    if fractional == 0 {
        return format!("{whole}{unit}");
    }
    let fraction = format!("{fractional:03}").trim_end_matches('0').to_owned();
    format!("{whole}.{fraction}{unit}")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::cgroup::{
        CgroupCollectionIssues, CgroupCpuInterval, CgroupFileState, CgroupInterval,
        CgroupMemoryEventsRaw, CgroupMemoryStatRaw, CgroupPsiInterval, CgroupPsiIntervalState,
        CgroupResource,
    };
    use crate::cpu::{
        CpuProcessObservation, HostCpuInterval, LoadAverageAvailability, LoadAverageRaw,
        ProcessCollectionIssues, ProcessCpuInterval, ProcessKey, ProcessSchedulerDelayInterval,
    };
    use crate::io::{
        BlockDeviceKey, DiskstatsInterval, DiskstatsIntervalIssues, DiskstatsObservation,
        ProcessIoCollectionIssues, ProcessIoInterval,
    };
    use crate::memory::{MeminfoRaw, VmstatIntervalIssues};
    use crate::psi::{
        CpuPsiInterval, CpuPsiRaw, IoPsiInterval, IoPsiLine, IoPsiLineInterval, IoPsiRaw,
        MemoryPsiInterval, MemoryPsiLine, MemoryPsiLineInterval, MemoryPsiRaw,
    };

    fn render_hunt<F>(options: &HuntOptions, observe: F) -> String
    where
        F: FnOnce(Duration) -> HuntObservation,
    {
        super::hunt(options, observe).expect("hunt render")
    }

    #[allow(clippy::too_many_arguments)]
    fn render_capabilities(
        options: &CapabilitiesOptions,
        cpu_psi: CpuPsiCapability,
        cpu: CpuTelemetryCapabilities,
        memory_psi: MemoryPsiCapability,
        memory: MemoryContextCapabilities,
        io_psi: IoPsiCapability,
        io: IoCapabilities,
        cgroup: CgroupCapability,
    ) -> String {
        super::capabilities(
            options, cpu_psi, cpu, memory_psi, memory, io_psi, io, cgroup,
        )
        .expect("capabilities render")
    }

    fn observation() -> CpuPsiObservation {
        CpuPsiObservation {
            requested: Duration::from_secs(1),
            interval: CpuPsiInterval {
                elapsed: Duration::from_millis(1_250),
                total_delta_us: 250_000,
                some_fraction: 0.2,
            },
            start: CpuPsiRaw {
                avg10_percent: 0.0,
                avg60_percent: 0.0,
                avg300_percent: 0.0,
                total_us: 1,
            },
            end: CpuPsiRaw {
                avg10_percent: 1.2,
                avg60_percent: 0.5,
                avg300_percent: 0.1,
                total_us: 250_001,
            },
        }
    }

    fn hunt_observation() -> HuntObservation {
        HuntObservation {
            psi: Ok(observation()),
            cpu: Ok(CpuProcessObservation {
                elapsed: Duration::from_millis(1_250),
                clock_ticks_per_second: 100,
                host: HostCpuInterval {
                    total_ticks: 250,
                    busy_ticks: 200,
                    idle_ticks: 50,
                    utilization_fraction: 0.8,
                    cpu_count: 4,
                },
                load: Some(LoadAverageRaw {
                    avg1: 1.0,
                    avg5: 0.5,
                    avg15: 0.25,
                    runnable_tasks: 2,
                    total_tasks: 100,
                    last_pid: 1,
                }),
                load_availability: LoadAverageAvailability::Available,
                processes: vec![ProcessCpuInterval {
                    key: ProcessKey {
                        pid: 9,
                        start_time_ticks: 1,
                    },
                    name: "consumer".into(),
                    state: 'R',
                    cpu_ticks: 50,
                    cpu_fraction_of_one: 0.4,
                }],
                process_resource_evidence: Vec::new(),
                collection_issues: ProcessCollectionIssues::default(),
                scheduler_delay_candidates: Vec::new(),
                schedstat_collection_issues: crate::cpu::SchedstatCollectionIssues::default(),
                task_stat_collection_issues: crate::cpu::TaskStatCollectionIssues::default(),
                schedstat_capability: crate::cpu::SchedstatCapability::Unsupported,
                taskstats: Vec::new(),
                taskstats_collection_issues: Default::default(),
                taskstats_capability: Default::default(),
                delay_accounting: Default::default(),
            }),
            memory: None,
            io: None,
            cgroup: None,
        }
    }

    fn memory_hunt_observation(
        some_fraction: f64,
        full_fraction: Option<f64>,
        context_available: bool,
    ) -> MemoryHuntObservation {
        let elapsed = Duration::from_secs(10);
        let elapsed_us = elapsed.as_micros() as f64;
        let some_delta = (some_fraction * elapsed_us) as u64;
        let full_delta = full_fraction.map(|fraction| (fraction * elapsed_us) as u64);
        let line = MemoryPsiLine {
            avg10_percent: 0.0,
            avg60_percent: 0.0,
            avg300_percent: 0.0,
            total_us: 0,
        };
        let psi = MemoryPsiObservation {
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
        };
        let context = if context_available {
            let mut deltas = std::collections::BTreeMap::new();
            for counter in VmstatCounter::ALL {
                deltas.insert(counter, 0);
            }
            deltas.insert(VmstatCounter::ScanDirect, 100);
            deltas.insert(VmstatCounter::StealDirect, 80);
            Ok(MemoryContextObservation {
                elapsed,
                end_meminfo: Some(MeminfoRaw {
                    mem_total_bytes: 1_000_000,
                    mem_available_bytes: 50_000,
                    swap_total_bytes: 100_000,
                    swap_free_bytes: 100_000,
                    cached_bytes: Some(300_000),
                    sreclaimable_bytes: Some(10_000),
                    anon_pages_bytes: Some(500_000),
                }),
                meminfo_capability: MemoryContextCapability::Available,
                vmstat_capability: MemoryContextCapability::Available,
                vmstat_deltas: deltas,
                vmstat_issues: VmstatIntervalIssues::default(),
            })
        } else {
            Err(crate::memory::MemoryContextError::Unreadable)
        };
        MemoryHuntObservation {
            psi: Ok(psi),
            context,
        }
    }

    fn io_hunt_observation(some_fraction: f64) -> IoHuntObservation {
        let elapsed = Duration::from_secs(10);
        let some_total = (some_fraction * elapsed.as_micros() as f64) as u64;
        let line = IoPsiLine {
            avg10_percent: 0.0,
            avg60_percent: 0.0,
            avg300_percent: 0.0,
            total_us: 0,
        };
        IoHuntObservation {
            psi: Ok(IoPsiObservation {
                requested: elapsed,
                interval: IoPsiInterval {
                    elapsed,
                    some: IoPsiLineInterval {
                        total_delta_us: some_total,
                        fraction: some_fraction,
                    },
                    full: IoPsiFullInterval::Available(IoPsiLineInterval {
                        total_delta_us: some_total / 4,
                        fraction: some_fraction / 4.0,
                    }),
                },
                start: IoPsiRaw {
                    some: line,
                    full: Some(line),
                },
                end: IoPsiRaw {
                    some: IoPsiLine {
                        total_us: some_total,
                        ..line
                    },
                    full: Some(IoPsiLine {
                        total_us: some_total / 4,
                        ..line
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
                    io_ticks_ms: Some(500),
                    weighted_io_ticks_ms: Some(700),
                    end_in_flight: 2,
                }],
                issues: DiskstatsIntervalIssues::default(),
            }),
            processes: Ok(ProcessIoObservation {
                elapsed,
                capability: IoCapability::Available,
                processes: vec![ProcessIoInterval {
                    key: ProcessKey {
                        pid: 42,
                        start_time_ticks: 1,
                    },
                    name: "writer".into(),
                    read_bytes: Some(1_024),
                    write_bytes: Some(8_192),
                    cancelled_write_bytes: Some(0),
                    rchar: None,
                    wchar: None,
                }],
                issues: ProcessIoCollectionIssues::default(),
                regressed: vec![],
            }),
        }
    }

    fn cgroup_resource<T>(value: Option<T>, state: CgroupFileState) -> CgroupResource<T> {
        CgroupResource { state, value }
    }

    fn scoped_cgroup_observation(partial: bool) -> CgroupHuntObservation {
        let elapsed = Duration::from_secs(10);
        CgroupHuntObservation {
            observation: Ok(CgroupObservation {
                elapsed,
                members: vec![],
                issues: CgroupCollectionIssues {
                    process_limit_reached: partial,
                    ..CgroupCollectionIssues::default()
                },
                groups: vec![CgroupInterval {
                    path: "/workload.service".into(),
                    cpu: cgroup_resource(
                        Some(CgroupCpuInterval {
                            usage_usec: Some(2_000_000),
                            user_usec: None,
                            system_usec: None,
                            nr_periods: None,
                            nr_throttled: None,
                            throttled_usec: Some(250_000),
                        }),
                        CgroupFileState::Available,
                    ),
                    memory_current_end: cgroup_resource(Some(4_096), CgroupFileState::Available),
                    memory_events: cgroup_resource(None, CgroupFileState::Missing),
                    memory_stat: cgroup_resource(None, CgroupFileState::Missing),
                    io: cgroup_resource(None, CgroupFileState::Missing),
                    cpu_pressure: cgroup_resource(
                        Some(CgroupPsiInterval {
                            elapsed: Some(elapsed),
                            some_total_usec: Some(2_000_000),
                            full_total_usec: None,
                            state: CgroupPsiIntervalState::Available,
                        }),
                        CgroupFileState::Available,
                    ),
                    memory_pressure: cgroup_resource(None, CgroupFileState::Missing),
                    io_pressure: cgroup_resource(None, CgroupFileState::Missing),
                    systemd_unit_candidate: Some("workload.service".into()),
                }],
            }),
        }
    }

    #[test]
    fn cgroup_partiality_controls_json_status_and_scoped_text_uses_controller_context() {
        let mut observation = hunt_observation();
        observation.psi.as_mut().unwrap().interval.some_fraction = 0.005;
        observation.cgroup = Some(scoped_cgroup_observation(true));
        let text = render_hunt(
            &HuntOptions {
                duration_ms: 1_000,
                output: OutputFormat::Text,
                verbose: false,
                no_color: false,
            },
            |_| observation,
        );
        assert!(text.starts_with("Scoped cgroup findings"));
        assert!(text.contains("Scoped CPU quota-throttle pressure"));
        assert!(text.contains("mechanism confidence low"));
        assert!(text.contains("controller context: CPU usage +2s; throttled +250ms"));
        assert!(text.contains("scoped context only; not causal proof"));

        let mut observation = hunt_observation();
        observation.cgroup = Some(scoped_cgroup_observation(true));
        let json: serde_json::Value = serde_json::from_str(&render_hunt(
            &HuntOptions {
                duration_ms: 1_000,
                output: OutputFormat::Json,
                verbose: false,
                no_color: false,
            },
            |_| observation,
        ))
        .unwrap();
        assert_eq!(json["capabilities"]["cgroup_v2"]["state"], "partial");
        assert_eq!(json["status"], "incomplete");
        assert_eq!(
            json["cgroup_findings"][0]["evidence"]["cpu"]["value"]["usage_usec"],
            2_000_000
        );
        assert_eq!(
            json["cgroup_findings"][0]["mechanism"],
            "cpu_quota_throttle"
        );
        assert_eq!(json["cgroup_findings"][0]["mechanism_confidence"], "low");
        assert_eq!(json["process_scopes"][1]["scope"]["scope"], "cgroup");
        assert_eq!(
            json["process_scopes"][1]["scope"]["path"],
            "/workload.service"
        );
        assert_eq!(json["process_scopes"][1]["roles"][0]["role"], "cpu_victim");
    }

    #[test]
    fn io_renderer_keeps_psi_pressure_independent_of_context_and_never_claims_mapping() {
        let mut observation = hunt_observation();
        observation.io = Some(io_hunt_observation(0.08));
        let text = render_hunt(
            &HuntOptions {
                duration_ms: 10_000,
                output: OutputFormat::Text,
                verbose: false,
                no_color: false,
            },
            |_| observation,
        );
        assert!(text.contains("Block-I/O pressure observed"));
        assert!(
            text.contains("Device activity candidates (same window only; not mapped to workloads)")
        );
        assert!(text.contains("not proven causal or device-mapped"));
        assert!(text.contains("Affected workloads: unavailable"));

        let mut healthy = hunt_observation();
        healthy.io = Some(io_hunt_observation(0.005));
        let text = render_hunt(
            &HuntOptions {
                duration_ms: 10_000,
                output: OutputFormat::Text,
                verbose: false,
                no_color: false,
            },
            |_| healthy,
        );
        assert!(text.contains("No meaningful block-I/O pressure observed"));
        assert!(text.contains("activity counters do not override that verdict"));
        assert!(text.contains("not ranked without an I/O pressure finding"));
    }

    #[test]
    fn io_json_retains_valid_psi_finding_when_context_is_missing() {
        let mut observation = hunt_observation();
        let mut io = io_hunt_observation(0.08);
        io.diskstats = Err(DiskstatsError::Unreadable);
        io.processes = Err(DiskstatsError::PermissionDenied);
        observation.io = Some(io);
        let json: serde_json::Value = serde_json::from_str(&render_hunt(
            &HuntOptions {
                duration_ms: 10_000,
                output: OutputFormat::Json,
                verbose: false,
                no_color: false,
            },
            |_| observation,
        ))
        .unwrap();
        let finding = json["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|finding| finding["resource"] == "io")
            .unwrap();
        assert_eq!(finding["kind"], "io_pressure");
        assert_eq!(json["capabilities"]["diskstats"], "failed");
        assert_eq!(json["capabilities"]["process_io"], "permission_denied");
        assert_eq!(json["status"], "incomplete");
    }

    #[test]
    fn hunt_renders_interval_pressure_with_a_diagnosis() {
        let output = render_hunt(
            &HuntOptions {
                duration_ms: 1_000,
                output: OutputFormat::Text,
                verbose: false,
                no_color: false,
            },
            |_| hunt_observation(),
        );
        assert!(output.contains("CPU scheduling contention observed"));
        assert!(output.contains("Verdict: contention · severity high · CPU confidence medium"));
        assert!(output.contains("CPU PSI some 20.00% over exact 1.25s interval"));
        assert!(output.contains("same window; this correlation does not prove causality"));
        assert!(output.contains(
            "Victim candidates: unavailable or incomplete (see context and limitations)"
        ));
        assert!(
            output.contains("Timing: requested 1s; PSI measured 1.25s; CPU/process measured 1.25s")
        );
        assert!(!output.contains("Top process CPU consumers during interval"));
    }

    #[test]
    fn contention_json_is_typed_and_cpu_failure_retains_psi_finding() {
        let json: serde_json::Value = serde_json::from_str(&render_hunt(
            &HuntOptions {
                duration_ms: 1_000,
                output: OutputFormat::Json,
                verbose: false,
                no_color: false,
            },
            |_| hunt_observation(),
        ))
        .unwrap();
        let finding = &json["findings"][0];
        assert_eq!(finding["kind"], "cpu_scheduling_contention");
        assert_eq!(finding["resource"], "cpu");
        assert!(
            finding["severity"].is_string()
                && finding["resource_confidence"].is_string()
                && finding["evidence"].is_object()
                && finding["victims"].is_array()
                && finding["suspects"].is_array()
                && finding["qualifiers"].is_array()
        );
        let partial: serde_json::Value = serde_json::from_str(&render_hunt(
            &HuntOptions {
                duration_ms: 1_000,
                output: OutputFormat::Json,
                verbose: false,
                no_color: false,
            },
            |_| HuntObservation {
                psi: Ok(observation()),
                cpu: Err(crate::cpu::CpuError::Unreadable),
                memory: None,
                io: None,
                cgroup: None,
            },
        ))
        .unwrap();
        assert_eq!(partial["status"], "incomplete");
        assert_eq!(partial["findings"][0]["kind"], "cpu_scheduling_contention");
        assert!(partial["findings"][0]["evidence"]["host_utilization_fraction"].is_null());
        assert!(partial["qualifiers"][0]["kind"].is_string());

        let partial_text = render_hunt(
            &HuntOptions {
                duration_ms: 1_000,
                output: OutputFormat::Text,
                verbose: false,
                no_color: false,
            },
            |_| HuntObservation {
                psi: Ok(observation()),
                cpu: Err(crate::cpu::CpuError::Unreadable),
                memory: None,
                io: None,
                cgroup: None,
            },
        );
        assert!(partial_text.contains("CPU interval context is unavailable"));
        assert!(partial_text.contains("CPU/process telemetry: unavailable"));
        assert!(partial_text.contains("Victim candidates: unavailable"));
        assert!(partial_text.contains("Suspect candidates: unavailable"));
        assert!(!partial_text.contains("none observed"));
    }

    #[test]
    fn hunt_json_contains_typed_cpu_psi_evidence() {
        let output = render_hunt(
            &HuntOptions {
                duration_ms: 1_000,
                output: OutputFormat::Json,
                verbose: false,
                no_color: false,
            },
            |_| hunt_observation(),
        );
        let json: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(json["status"], "observed");
        assert_eq!(json["observation"]["cpu_psi"]["total_delta_us"], 250_000);
        assert!(json["findings"].is_array());
    }

    #[test]
    fn memory_finding_is_ranked_and_rendered_with_host_wide_limits() {
        let mut observation = hunt_observation();
        let cpu_psi = observation.psi.as_mut().unwrap();
        cpu_psi.interval.some_fraction = 0.005;
        cpu_psi.interval.total_delta_us = 50_000;
        observation.memory = Some(memory_hunt_observation(0.08, Some(0.01), true));
        let text = render_hunt(
            &HuntOptions {
                duration_ms: 10_000,
                output: OutputFormat::Text,
                verbose: false,
                no_color: false,
            },
            |_| observation,
        );
        assert!(
            text.starts_with("Memory pressure observed with correlated direct reclaim activity")
        );
        assert!(text.contains("Verdict: reclaim pressure · severity moderate"));
        assert!(text.contains("Attribution: unavailable (host-wide evidence only)"));
        assert!(text.contains("occupancy is context and is not itself evidence"));

        let mut observation = hunt_observation();
        let cpu_psi = observation.psi.as_mut().unwrap();
        cpu_psi.interval.some_fraction = 0.005;
        cpu_psi.interval.total_delta_us = 50_000;
        observation.memory = Some(memory_hunt_observation(0.08, Some(0.01), true));
        let json: serde_json::Value = serde_json::from_str(&render_hunt(
            &HuntOptions {
                duration_ms: 10_000,
                output: OutputFormat::Json,
                verbose: false,
                no_color: false,
            },
            |_| observation,
        ))
        .unwrap();
        assert_eq!(json["findings"][0]["resource"], "memory");
        assert_eq!(json["findings"][0]["kind"], "memory_reclaim_pressure");
        assert_eq!(json["observation"]["memory_psi"]["full_state"], "available");
        assert_eq!(json["capabilities"]["memory_psi"]["state"], "available");
        assert!(json["observation"]["memory_context"]["elapsed"].is_null());
    }

    #[test]
    fn memory_partial_and_missing_telemetry_never_create_a_false_negative() {
        let mut partial = hunt_observation();
        partial.memory = Some(memory_hunt_observation(0.08, None, false));
        let json: serde_json::Value = serde_json::from_str(&render_hunt(
            &HuntOptions {
                duration_ms: 10_000,
                output: OutputFormat::Json,
                verbose: false,
                no_color: false,
            },
            |_| partial,
        ))
        .unwrap();
        let memory_finding = json["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|finding| finding["resource"] == "memory")
            .unwrap();
        assert_eq!(memory_finding["kind"], "memory_pressure");
        assert_eq!(json["capabilities"]["memory_psi"]["state"], "partial");
        assert_eq!(json["status"], "incomplete");

        let mut missing = hunt_observation();
        missing.memory = Some(MemoryHuntObservation {
            psi: Err(crate::psi::MemoryPsiError::PermissionDenied),
            context: memory_hunt_observation(0.0, Some(0.0), true).context,
        });
        let json: serde_json::Value = serde_json::from_str(&render_hunt(
            &HuntOptions {
                duration_ms: 10_000,
                output: OutputFormat::Json,
                verbose: false,
                no_color: false,
            },
            |_| missing,
        ))
        .unwrap();
        assert!(
            json["findings"]
                .as_array()
                .unwrap()
                .iter()
                .all(|finding| finding["resource"] != "memory")
        );
        assert_eq!(
            json["capabilities"]["memory_psi"]["state"],
            "permission_denied"
        );
        assert_eq!(json["status"], "incomplete");
    }

    fn chain_hunt_observation(memory_has_context: bool, io_pressured: bool) -> HuntObservation {
        let mut observation = hunt_observation();
        let cpu_psi = observation.psi.as_mut().unwrap();
        cpu_psi.interval.some_fraction = 0.005;
        cpu_psi.interval.total_delta_us = 50_000;
        observation.memory = Some(memory_hunt_observation(
            0.08,
            Some(0.01),
            memory_has_context,
        ));
        observation.io = Some(io_hunt_observation(if io_pressured { 0.08 } else { 0.005 }));
        observation
    }

    #[test]
    fn evidence_chain_is_rendered_only_when_independent_mechanism_supports_it() {
        let text = render_hunt(
            &HuntOptions {
                duration_ms: 10_000,
                output: OutputFormat::Text,
                verbose: false,
                no_color: false,
            },
            |_| chain_hunt_observation(true, true),
        );
        let related = text
            .split_once("Related evidence\n")
            .map(|(prefix, related)| {
                assert!(prefix.contains("reclaim pressure"));
                assert!(prefix.contains("block-I/O pressure"));
                format!("Related evidence\n{related}")
            })
            .expect("related evidence section");
        assert_eq!(
            related,
            include_str!("../tests/fixtures/render/evidence-chain.txt")
        );
        assert!(
            !related
                .lines()
                .nth(1)
                .unwrap()
                .to_lowercase()
                .contains("cause")
        );
        assert!(related.contains("does not prove"));

        let json: serde_json::Value = serde_json::from_str(&render_hunt(
            &HuntOptions {
                duration_ms: 10_000,
                output: OutputFormat::Json,
                verbose: false,
                no_color: false,
            },
            |_| chain_hunt_observation(true, true),
        ))
        .unwrap();
        let chain = &json["evidence_chains"][0];
        assert_eq!(chain["kind"], "memory_mechanism_consistent_with_io");
        assert_eq!(chain["relation"], "consistent_with");
        assert_eq!(chain["confidence"], "low");
        assert_eq!(chain["from"]["resource"], "memory");
        assert_eq!(chain["from"]["kind"], "memory_reclaim_pressure");
        assert_eq!(chain["to"]["resource"], "io");
        assert_eq!(chain["to"]["kind"], "io_pressure");
        assert_eq!(chain["evidence"]["scan_direct_pages"], 100);
        assert!(
            chain["qualifiers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|qualifier| qualifier["kind"] == "chain_not_causal")
        );

        let coincident: serde_json::Value = serde_json::from_str(&render_hunt(
            &HuntOptions {
                duration_ms: 10_000,
                output: OutputFormat::Json,
                verbose: false,
                no_color: false,
            },
            |_| chain_hunt_observation(false, true),
        ))
        .unwrap();
        assert_eq!(coincident["evidence_chains"].as_array().unwrap().len(), 0);
        assert!(
            !render_hunt(
                &HuntOptions {
                    duration_ms: 10_000,
                    output: OutputFormat::Text,
                    verbose: false,
                    no_color: false,
                },
                |_| chain_hunt_observation(false, true),
            )
            .contains("Related evidence")
        );

        let io_healthy: serde_json::Value = serde_json::from_str(&render_hunt(
            &HuntOptions {
                duration_ms: 10_000,
                output: OutputFormat::Json,
                verbose: false,
                no_color: false,
            },
            |_| chain_hunt_observation(true, false),
        ))
        .unwrap();
        assert_eq!(io_healthy["evidence_chains"].as_array().unwrap().len(), 0);

        let cpu_only: serde_json::Value = serde_json::from_str(&render_hunt(
            &HuntOptions {
                duration_ms: 1_000,
                output: OutputFormat::Json,
                verbose: false,
                no_color: false,
            },
            |_| hunt_observation(),
        ))
        .unwrap();
        assert_eq!(cpu_only["evidence_chains"].as_array().unwrap().len(), 0);
    }

    fn scoped_memory_io_cgroup_observation(
        events: Option<CgroupMemoryEventsRaw>,
        io_pressured: bool,
    ) -> CgroupHuntObservation {
        let elapsed = Duration::from_secs(10);
        let memory_psi = cgroup_resource(
            Some(CgroupPsiInterval {
                elapsed: Some(elapsed),
                some_total_usec: Some(800_000),
                full_total_usec: None,
                state: CgroupPsiIntervalState::Available,
            }),
            CgroupFileState::Available,
        );
        let io_psi = cgroup_resource(
            Some(CgroupPsiInterval {
                elapsed: Some(elapsed),
                some_total_usec: Some(if io_pressured { 800_000 } else { 5_000 }),
                full_total_usec: None,
                state: CgroupPsiIntervalState::Available,
            }),
            CgroupFileState::Available,
        );
        CgroupHuntObservation {
            observation: Ok(CgroupObservation {
                elapsed,
                members: vec![],
                issues: CgroupCollectionIssues::default(),
                groups: vec![CgroupInterval {
                    path: "/workload.service".into(),
                    cpu: cgroup_resource(None, CgroupFileState::Missing),
                    memory_current_end: cgroup_resource(None, CgroupFileState::Missing),
                    memory_events: match events {
                        Some(value) => cgroup_resource(Some(value), CgroupFileState::Available),
                        None => cgroup_resource(None, CgroupFileState::Missing),
                    },
                    memory_stat: cgroup_resource(None, CgroupFileState::Missing),
                    io: cgroup_resource(None, CgroupFileState::Missing),
                    cpu_pressure: cgroup_resource(None, CgroupFileState::Missing),
                    memory_pressure: memory_psi,
                    io_pressure: io_psi,
                    systemd_unit_candidate: Some("workload.service".into()),
                }],
            }),
        }
    }

    fn reclaim_events() -> CgroupMemoryEventsRaw {
        CgroupMemoryEventsRaw {
            low: Some(0),
            high: Some(3),
            max: Some(0),
            oom: Some(0),
            oom_kill: Some(0),
            oom_group_kill: Some(0),
        }
    }

    fn cgroup_chain_hunt_observation() -> HuntObservation {
        let mut observation = hunt_observation();
        observation.psi.as_mut().unwrap().interval.some_fraction = 0.005;
        observation.psi.as_mut().unwrap().interval.total_delta_us = 50_000;
        observation.cgroup = Some(scoped_memory_io_cgroup_observation(
            Some(reclaim_events()),
            true,
        ));
        observation
    }

    #[test]
    fn same_cgroup_evidence_chain_is_rendered_without_host_linking() {
        let text = render_hunt(
            &HuntOptions {
                duration_ms: 10_000,
                output: OutputFormat::Text,
                verbose: false,
                no_color: false,
            },
            |_| cgroup_chain_hunt_observation(),
        );
        let related = text
            .split_once("Related evidence\n")
            .map(|(_, related)| format!("Related evidence\n{related}"))
            .expect("related evidence section");
        assert_eq!(
            related,
            include_str!("../tests/fixtures/render/evidence-chain-cgroup.txt")
        );
        assert!(
            !related
                .lines()
                .nth(1)
                .unwrap()
                .to_lowercase()
                .contains("cause")
        );

        let json: serde_json::Value = serde_json::from_str(&render_hunt(
            &HuntOptions {
                duration_ms: 10_000,
                output: OutputFormat::Json,
                verbose: false,
                no_color: false,
            },
            |_| cgroup_chain_hunt_observation(),
        ))
        .unwrap();
        let chains = json["evidence_chains"].as_array().unwrap();
        assert_eq!(chains.len(), 1);
        let chain = &chains[0];
        assert_eq!(chain["kind"], "cgroup_memory_consistent_with_io");
        assert_eq!(chain["relation"], "consistent_with");
        assert_eq!(chain["confidence"], "low");
        assert_eq!(chain["from"]["resource"], "cgroup_memory");
        assert_eq!(chain["from"]["path"], "/workload.service");
        assert_eq!(chain["to"]["resource"], "cgroup_io");
        assert_eq!(chain["to"]["path"], "/workload.service");
        assert_eq!(chain["evidence"]["path"], "/workload.service");
        assert_eq!(chain["evidence"]["high_events"], 3);
        assert!(chain["evidence"]["scan_direct_pages"].is_null());
        assert!(
            chain["qualifiers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|qualifier| qualifier["kind"] == "same_cgroup_scope_only")
        );

        let mut coincident = hunt_observation();
        coincident.cgroup = Some(scoped_memory_io_cgroup_observation(None, true));
        let coincident_json: serde_json::Value = serde_json::from_str(&render_hunt(
            &HuntOptions {
                duration_ms: 10_000,
                output: OutputFormat::Json,
                verbose: false,
                no_color: false,
            },
            |_| coincident,
        ))
        .unwrap();
        assert_eq!(
            coincident_json["evidence_chains"].as_array().unwrap().len(),
            0
        );

        let mut combined = chain_hunt_observation(true, true);
        combined.cgroup = Some(scoped_memory_io_cgroup_observation(
            Some(reclaim_events()),
            true,
        ));
        let combined_json: serde_json::Value = serde_json::from_str(&render_hunt(
            &HuntOptions {
                duration_ms: 10_000,
                output: OutputFormat::Json,
                verbose: false,
                no_color: false,
            },
            |_| combined,
        ))
        .unwrap();
        let combined_chains = combined_json["evidence_chains"].as_array().unwrap();
        assert_eq!(combined_chains.len(), 2);
        assert_eq!(
            combined_chains[0]["kind"],
            "memory_mechanism_consistent_with_io"
        );
        assert_eq!(
            combined_chains[1]["kind"],
            "cgroup_memory_consistent_with_io"
        );
        assert_ne!(
            combined_chains[0]["from"]["resource"],
            combined_chains[1]["from"]["resource"]
        );
    }

    #[test]
    fn same_cgroup_memory_stat_chain_is_rendered_without_limit_events() {
        let mut observation = hunt_observation();
        observation.psi.as_mut().unwrap().interval.some_fraction = 0.005;
        observation.psi.as_mut().unwrap().interval.total_delta_us = 50_000;
        let mut cgroup = scoped_memory_io_cgroup_observation(None, true);
        if let Ok(value) = cgroup.observation.as_mut() {
            value.groups[0].memory_stat = cgroup_resource(
                Some(CgroupMemoryStatRaw {
                    pgscan_direct: Some(12),
                    pgsteal_direct: Some(8),
                    pswpin: Some(0),
                    pswpout: Some(0),
                }),
                CgroupFileState::Available,
            );
        }
        observation.cgroup = Some(cgroup);
        let json: serde_json::Value = serde_json::from_str(&render_hunt(
            &HuntOptions {
                duration_ms: 10_000,
                output: OutputFormat::Json,
                verbose: false,
                no_color: false,
            },
            |_| observation,
        ))
        .unwrap();
        let chain = &json["evidence_chains"][0];
        assert_eq!(chain["kind"], "cgroup_memory_consistent_with_io");
        assert_eq!(chain["evidence"]["scan_direct_pages"], 12);
        assert_eq!(chain["evidence"]["steal_direct_pages"], 8);
        assert!(chain["evidence"].get("high_events").is_none());
        let memory = json["cgroup_findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|finding| finding["resource"] == "memory")
            .expect("memory finding");
        assert_eq!(memory["mechanism"], "reclaim");
        assert_eq!(memory["mechanism_confidence"], "low");
        assert!(
            memory["summary"]
                .as_str()
                .unwrap()
                .contains("reclaim pressure")
        );
        let text = render_hunt(
            &HuntOptions {
                duration_ms: 10_000,
                output: OutputFormat::Text,
                verbose: false,
                no_color: false,
            },
            |_| {
                let mut observation = hunt_observation();
                observation.psi.as_mut().unwrap().interval.some_fraction = 0.005;
                observation.psi.as_mut().unwrap().interval.total_delta_us = 50_000;
                let mut cgroup = scoped_memory_io_cgroup_observation(None, true);
                if let Ok(value) = cgroup.observation.as_mut() {
                    value.groups[0].memory_stat = cgroup_resource(
                        Some(CgroupMemoryStatRaw {
                            pgscan_direct: Some(12),
                            pgsteal_direct: Some(8),
                            pswpin: Some(0),
                            pswpout: Some(0),
                        }),
                        CgroupFileState::Available,
                    );
                }
                observation.cgroup = Some(cgroup);
                observation
            },
        );
        assert!(text.contains("Scoped memory reclaim pressure"));
        assert!(text.contains("mechanism confidence low"));
        assert!(text.contains("12 direct-reclaim scan pages"));
        assert!(
            !text
                .split_once("Related evidence\n")
                .unwrap()
                .1
                .lines()
                .next()
                .unwrap()
                .to_lowercase()
                .contains("cause")
        );
    }

    #[test]
    fn scoped_possible_thrashing_label_is_rendered_without_claiming_causality() {
        let elapsed = Duration::from_secs(5);
        let json: serde_json::Value = serde_json::from_str(&render_hunt(
            &HuntOptions {
                duration_ms: 5_000,
                output: OutputFormat::Json,
                verbose: false,
                no_color: false,
            },
            |_| {
                let mut observation = hunt_observation();
                observation.psi.as_mut().unwrap().interval.some_fraction = 0.005;
                observation.psi.as_mut().unwrap().interval.total_delta_us = 25_000;
                let mut cgroup = scoped_memory_io_cgroup_observation(None, false);
                if let Ok(value) = cgroup.observation.as_mut() {
                    value.elapsed = elapsed;
                    value.groups[0].memory_pressure = cgroup_resource(
                        Some(CgroupPsiInterval {
                            elapsed: Some(elapsed),
                            some_total_usec: Some(1_000_000),
                            full_total_usec: Some(100_000),
                            state: CgroupPsiIntervalState::Available,
                        }),
                        CgroupFileState::Available,
                    );
                    value.groups[0].memory_stat = cgroup_resource(
                        Some(CgroupMemoryStatRaw {
                            pgscan_direct: Some(5_120),
                            pgsteal_direct: Some(5_120),
                            pswpin: Some(5_120),
                            pswpout: Some(5_120),
                        }),
                        CgroupFileState::Available,
                    );
                }
                observation.cgroup = Some(cgroup);
                observation
            },
        ))
        .unwrap();
        let memory = json["cgroup_findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|finding| finding["resource"] == "memory")
            .expect("memory finding");
        assert_eq!(memory["kind"], "pressure");
        assert_eq!(memory["mechanism"], "possible_thrashing");
        assert_eq!(memory["mechanism_confidence"], "medium");
        assert!(
            memory["summary"]
                .as_str()
                .unwrap()
                .contains("possible thrashing")
        );
        assert!(
            !memory["summary"]
                .as_str()
                .unwrap()
                .to_lowercase()
                .contains("cause")
        );

        let text = render_hunt(
            &HuntOptions {
                duration_ms: 5_000,
                output: OutputFormat::Text,
                verbose: false,
                no_color: false,
            },
            |_| {
                let mut observation = hunt_observation();
                observation.psi.as_mut().unwrap().interval.some_fraction = 0.005;
                observation.psi.as_mut().unwrap().interval.total_delta_us = 25_000;
                let mut cgroup = scoped_memory_io_cgroup_observation(None, false);
                if let Ok(value) = cgroup.observation.as_mut() {
                    value.elapsed = elapsed;
                    value.groups[0].memory_pressure = cgroup_resource(
                        Some(CgroupPsiInterval {
                            elapsed: Some(elapsed),
                            some_total_usec: Some(1_000_000),
                            full_total_usec: Some(100_000),
                            state: CgroupPsiIntervalState::Available,
                        }),
                        CgroupFileState::Available,
                    );
                    value.groups[0].memory_stat = cgroup_resource(
                        Some(CgroupMemoryStatRaw {
                            pgscan_direct: Some(5_120),
                            pgsteal_direct: Some(5_120),
                            pswpin: Some(5_120),
                            pswpout: Some(5_120),
                        }),
                        CgroupFileState::Available,
                    );
                }
                observation.cgroup = Some(cgroup);
                observation
            },
        );
        assert!(text.contains("possible thrashing"));
        assert!(text.contains("mechanism confidence medium"));
        assert!(!text.to_lowercase().contains("caused"));
    }

    #[test]
    fn memory_partial_capability_message_describes_an_invalid_full_interval() {
        let mut observation = hunt_observation();
        let mut memory = memory_hunt_observation(0.08, Some(0.01), true);
        memory.psi.as_mut().unwrap().interval.full = MemoryPsiFullInterval::CounterRegressed;
        observation.memory = Some(memory);

        let json: serde_json::Value = serde_json::from_str(&render_hunt(
            &HuntOptions {
                duration_ms: 10_000,
                output: OutputFormat::Json,
                verbose: false,
                no_color: false,
            },
            |_| observation,
        ))
        .unwrap();

        assert_eq!(json["capabilities"]["memory_psi"]["state"], "partial");
        assert!(
            json["capabilities"]["memory_psi"]["message"]
                .as_str()
                .unwrap()
                .contains("cumulative total decreased")
        );
        assert!(json["observation"]["memory_psi"]["some_fraction"].is_number());
        assert_eq!(
            json["observation"]["memory_psi"]["full_state"],
            "counter_regressed"
        );
    }

    #[test]
    fn hunt_reports_unavailable_cpu_psi_explicitly() {
        let output = render_hunt(
            &HuntOptions {
                duration_ms: 1_000,
                output: OutputFormat::Text,
                verbose: false,
                no_color: false,
            },
            |_| HuntObservation {
                psi: Err(crate::psi::CpuPsiError::Malformed),
                cpu: Err(crate::cpu::CpuError::Malformed),
                memory: None,
                io: None,
                cgroup: None,
            },
        );
        assert!(output.contains("Capability: CPU PSI failed"));
        assert!(output.contains("did not match the expected kernel format"));
    }

    #[test]
    fn psi_failure_retains_scheduler_delay_text_context() {
        let output = render_hunt(
            &HuntOptions {
                duration_ms: 1_000,
                output: OutputFormat::Text,
                verbose: false,
                no_color: false,
            },
            |_| HuntObservation {
                psi: Err(crate::psi::CpuPsiError::Malformed),
                cpu: hunt_observation().cpu,
                memory: None,
                io: None,
                cgroup: None,
            },
        );
        assert!(output.contains("CPU assessment unavailable"));
        assert!(output.contains("CPU/process context was collected"));
        assert!(output.contains("Retained context: host CPU"));
        assert!(output.contains("scheduler-delay candidate(s)"));
    }

    #[test]
    fn attribution_absence_is_distinguished_from_complete_empty_results() {
        let mut complete = hunt_observation();
        let cpu = complete.cpu.as_mut().unwrap();
        cpu.processes.clear();
        cpu.schedstat_capability = crate::cpu::SchedstatCapability::Available;
        let complete_text = render_hunt(
            &HuntOptions {
                duration_ms: 1_000,
                output: OutputFormat::Text,
                verbose: false,
                no_color: false,
            },
            |_| complete,
        );
        assert!(complete_text.contains("no positive stable runnable-delay candidates"));
        assert!(complete_text.contains("no consumers above 25% of one CPU"));

        let mut retained_partial = hunt_observation();
        retained_partial
            .cpu
            .as_mut()
            .unwrap()
            .collection_issues
            .appeared = 1;
        let retained_partial_text = render_hunt(
            &HuntOptions {
                duration_ms: 1_000,
                output: OutputFormat::Text,
                verbose: false,
                no_color: false,
            },
            |_| retained_partial,
        );
        assert!(retained_partial_text.contains("consumer [9]"));
        assert!(retained_partial_text.contains("Process collection is partial"));

        let mut empty_partial = hunt_observation();
        let cpu = empty_partial.cpu.as_mut().unwrap();
        cpu.processes.clear();
        cpu.collection_issues.appeared = 1;
        let empty_partial_text = render_hunt(
            &HuntOptions {
                duration_ms: 1_000,
                output: OutputFormat::Text,
                verbose: false,
                no_color: false,
            },
            |_| empty_partial,
        );
        assert!(empty_partial_text.contains("Suspect candidates: unavailable or incomplete"));

        let mut retained_scheduler_partial = hunt_observation();
        let cpu = retained_scheduler_partial.cpu.as_mut().unwrap();
        cpu.schedstat_capability = crate::cpu::SchedstatCapability::Partial;
        cpu.scheduler_delay_candidates
            .push(ProcessSchedulerDelayInterval {
                key: ProcessKey {
                    pid: 9,
                    start_time_ticks: 1,
                },
                name: "consumer".into(),
                task_count: 1,
                running_ns: 1_000,
                runnable_wait_ns: 250_000,
                runnable_delay_fraction: 0.0002,
                timeslices: 1,
            });
        let retained_scheduler_text = render_hunt(
            &HuntOptions {
                duration_ms: 1_000,
                output: OutputFormat::Text,
                verbose: false,
                no_color: false,
            },
            |_| retained_scheduler_partial,
        );
        assert!(retained_scheduler_text.contains("consumer [9] — 250µs delay"));
        assert!(retained_scheduler_text.contains("Scheduler accounting is unavailable or partial"));
    }

    #[test]
    fn suppressed_attribution_is_not_rendered_as_negative_evidence() {
        let mut no_contention = hunt_observation();
        let psi = no_contention.psi.as_mut().unwrap();
        psi.interval.some_fraction = 0.005;
        psi.interval.total_delta_us = 6_250;
        let cpu = no_contention.cpu.as_mut().unwrap();
        cpu.schedstat_capability = crate::cpu::SchedstatCapability::Available;
        cpu.scheduler_delay_candidates
            .push(ProcessSchedulerDelayInterval {
                key: ProcessKey {
                    pid: 9,
                    start_time_ticks: 1,
                },
                name: "consumer".into(),
                task_count: 1,
                running_ns: 1_000,
                runnable_wait_ns: 250_000,
                runnable_delay_fraction: 0.0002,
                timeslices: 1,
            });
        let no_contention_text = render_hunt(
            &HuntOptions {
                duration_ms: 1_000,
                output: OutputFormat::Text,
                verbose: false,
                no_color: false,
            },
            |_| no_contention,
        );
        assert!(no_contention_text.contains("not ranked without a contention finding"));
        assert!(!no_contention_text.contains("no consumers above 25%"));
        assert!(!no_contention_text.contains("no positive stable runnable-delay"));

        let mut short = hunt_observation();
        let psi = short.psi.as_mut().unwrap();
        psi.requested = Duration::from_millis(100);
        psi.interval.elapsed = Duration::from_millis(100);
        short.cpu.as_mut().unwrap().elapsed = Duration::from_millis(100);
        let short_text = render_hunt(
            &HuntOptions {
                duration_ms: 100,
                output: OutputFormat::Text,
                verbose: false,
                no_color: false,
            },
            |_| short,
        );
        assert!(short_text.contains("not assessed for a short observation"));
        assert!(!short_text.contains("no consumers above 25%"));
    }

    #[test]
    fn submillisecond_durations_preserve_precision() {
        assert_eq!(human_duration_from_duration(Duration::ZERO), "0ms");
        assert_eq!(
            human_duration_from_duration(Duration::from_nanos(999)),
            "999ns"
        );
        assert_eq!(
            human_duration_from_duration(Duration::from_nanos(1_500)),
            "1.5µs"
        );
        assert_eq!(
            human_duration_from_duration(Duration::from_micros(999)),
            "999µs"
        );
        assert_eq!(
            human_duration_from_duration(Duration::from_micros(1_500)),
            "1.5ms"
        );
        assert_eq!(
            human_duration_from_duration(Duration::from_micros(1_999)),
            "1.999ms"
        );
    }

    #[test]
    fn concise_text_output_matches_the_fixed_contention_fixture() {
        let observation = CpuPsiObservation {
            requested: Duration::from_secs(10),
            interval: CpuPsiInterval {
                elapsed: Duration::from_secs(10),
                total_delta_us: 2_000_000,
                some_fraction: 0.2,
            },
            start: CpuPsiRaw {
                avg10_percent: 0.0,
                avg60_percent: 0.0,
                avg300_percent: 0.0,
                total_us: 1,
            },
            end: CpuPsiRaw {
                avg10_percent: 0.0,
                avg60_percent: 0.0,
                avg300_percent: 0.0,
                total_us: 2_000_001,
            },
        };
        let cpu = CpuProcessObservation {
            elapsed: Duration::from_secs(10),
            clock_ticks_per_second: 100,
            host: HostCpuInterval {
                total_ticks: 1_000,
                busy_ticks: 950,
                idle_ticks: 50,
                utilization_fraction: 0.95,
                cpu_count: 8,
            },
            load: Some(LoadAverageRaw {
                avg1: 9.0,
                avg5: 8.0,
                avg15: 7.0,
                runnable_tasks: 9,
                total_tasks: 100,
                last_pid: 20,
            }),
            load_availability: LoadAverageAvailability::Available,
            processes: vec![
                ProcessCpuInterval {
                    key: ProcessKey {
                        pid: 20,
                        start_time_ticks: 1,
                    },
                    name: "build\u{1b}[31m".into(),
                    state: 'R',
                    cpu_ticks: 80,
                    cpu_fraction_of_one: 0.8,
                },
                ProcessCpuInterval {
                    key: ProcessKey {
                        pid: 21,
                        start_time_ticks: 1,
                    },
                    name: "worker".into(),
                    state: 'R',
                    cpu_ticks: 30,
                    cpu_fraction_of_one: 0.3,
                },
            ],
            process_resource_evidence: Vec::new(),
            collection_issues: ProcessCollectionIssues::default(),
            scheduler_delay_candidates: vec![ProcessSchedulerDelayInterval {
                key: ProcessKey {
                    pid: 21,
                    start_time_ticks: 1,
                },
                name: "worker\nnext".into(),
                task_count: 1,
                running_ns: 0,
                runnable_wait_ns: 500_000_000,
                runnable_delay_fraction: 0.05,
                timeslices: 1,
            }],
            schedstat_collection_issues: crate::cpu::SchedstatCollectionIssues::default(),
            task_stat_collection_issues: crate::cpu::TaskStatCollectionIssues::default(),
            schedstat_capability: crate::cpu::SchedstatCapability::Available,
            taskstats: Vec::new(),
            taskstats_collection_issues: Default::default(),
            taskstats_capability: Default::default(),
            delay_accounting: Default::default(),
        };
        let output = render_hunt(
            &HuntOptions {
                duration_ms: 10_000,
                output: OutputFormat::Text,
                verbose: false,
                no_color: false,
            },
            |_| HuntObservation {
                psi: Ok(observation),
                cpu: Ok(cpu),
                memory: None,
                io: None,
                cgroup: None,
            },
        );
        assert_eq!(
            output,
            include_str!("../tests/fixtures/render/cpu-contention.txt")
        );
        assert!(!output.contains('\u{1b}'));
        assert!(!output.contains("worker\nnext"));
    }

    /// The fixed multi-section (CPU + memory + I/O + cgroup) observation
    /// shared by the legacy and compact-report full-baseline goldens
    /// (`hunt-legacy-full.txt`, `hunt-compact-full.txt`), so the two are a
    /// true side-by-side comparison of the same diagnosis.
    pub(crate) fn hunt_legacy_full_fixture_observation() -> HuntObservation {
        let observation = CpuPsiObservation {
            requested: Duration::from_secs(10),
            interval: CpuPsiInterval {
                elapsed: Duration::from_secs(10),
                total_delta_us: 2_000_000,
                some_fraction: 0.2,
            },
            start: CpuPsiRaw {
                avg10_percent: 0.0,
                avg60_percent: 0.0,
                avg300_percent: 0.0,
                total_us: 1,
            },
            end: CpuPsiRaw {
                avg10_percent: 0.0,
                avg60_percent: 0.0,
                avg300_percent: 0.0,
                total_us: 2_000_001,
            },
        };
        let cpu = CpuProcessObservation {
            elapsed: Duration::from_secs(10),
            clock_ticks_per_second: 100,
            host: HostCpuInterval {
                total_ticks: 1_000,
                busy_ticks: 950,
                idle_ticks: 50,
                utilization_fraction: 0.95,
                cpu_count: 8,
            },
            load: Some(LoadAverageRaw {
                avg1: 9.0,
                avg5: 8.0,
                avg15: 7.0,
                runnable_tasks: 9,
                total_tasks: 100,
                last_pid: 20,
            }),
            load_availability: LoadAverageAvailability::Available,
            processes: vec![
                ProcessCpuInterval {
                    key: ProcessKey {
                        pid: 20,
                        start_time_ticks: 1,
                    },
                    name: "build".into(),
                    state: 'R',
                    cpu_ticks: 80,
                    cpu_fraction_of_one: 0.8,
                },
                ProcessCpuInterval {
                    key: ProcessKey {
                        pid: 21,
                        start_time_ticks: 1,
                    },
                    name: "worker".into(),
                    state: 'R',
                    cpu_ticks: 30,
                    cpu_fraction_of_one: 0.3,
                },
            ],
            process_resource_evidence: Vec::new(),
            collection_issues: ProcessCollectionIssues::default(),
            scheduler_delay_candidates: vec![ProcessSchedulerDelayInterval {
                key: ProcessKey {
                    pid: 21,
                    start_time_ticks: 1,
                },
                name: "worker".into(),
                task_count: 1,
                running_ns: 0,
                runnable_wait_ns: 500_000_000,
                runnable_delay_fraction: 0.05,
                timeslices: 1,
            }],
            schedstat_collection_issues: crate::cpu::SchedstatCollectionIssues::default(),
            task_stat_collection_issues: crate::cpu::TaskStatCollectionIssues::default(),
            schedstat_capability: crate::cpu::SchedstatCapability::Available,
            taskstats: Vec::new(),
            taskstats_collection_issues: Default::default(),
            taskstats_capability: Default::default(),
            delay_accounting: Default::default(),
        };
        HuntObservation {
            psi: Ok(observation),
            cpu: Ok(cpu),
            memory: Some(memory_hunt_observation(0.08, Some(0.01), true)),
            io: Some(io_hunt_observation(0.08)),
            cgroup: Some(scoped_memory_io_cgroup_observation(
                Some(reclaim_events()),
                true,
            )),
        }
    }

    #[test]
    fn concise_text_output_matches_the_fixed_multi_section_fixture() {
        let output = render_hunt(
            &HuntOptions {
                duration_ms: 10_000,
                output: OutputFormat::Text,
                verbose: false,
                no_color: false,
            },
            |_| hunt_legacy_full_fixture_observation(),
        );
        assert_eq!(
            output,
            include_str!("../tests/fixtures/render/hunt-legacy-full.txt")
        );
        assert!(!output.contains('\u{1b}'));
    }

    #[test]
    fn capabilities_report_the_cpu_psi_state() {
        for capability in [
            CpuPsiCapability::Available,
            CpuPsiCapability::Unsupported,
            CpuPsiCapability::PermissionDenied,
            CpuPsiCapability::Failed,
        ] {
            let output = render_capabilities(
                &CapabilitiesOptions {
                    output: OutputFormat::Text,
                },
                capability,
                CpuTelemetryCapabilities {
                    host_cpu: crate::cpu::CollectorCapability::Available,
                    process_stat: crate::cpu::CollectorCapability::Available,
                    process_schedstat: crate::cpu::SchedstatCapability::Unsupported,
                },
                MemoryPsiCapability::Available,
                MemoryContextCapabilities {
                    meminfo: MemoryContextCapability::Available,
                    vmstat: MemoryContextCapability::Available,
                },
                IoPsiCapability::Available,
                IoCapabilities {
                    diskstats: IoCapability::Available,
                    process_io: IoCapability::Available,
                },
                CgroupCapability::Available,
            );
            assert!(output.contains(&format!("CPU PSI: {}", capability.as_str())));
            assert!(output.contains(capability.explanation()));
            assert!(output.contains("I/O PSI: available"));
        }
    }
}
