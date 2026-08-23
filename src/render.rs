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
use crate::cli::{
    CapabilitiesOptions, Detail, HuntOptions, OutputFormat, RedactOptions, ReplayOptions,
};
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
use crate::ui::{self, ColorUse, StatusWord, Style};

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
            detail: options.detail,
            color: options.color,
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
        OutputFormat::Text => {
            let color = ColorUse::resolve_stdout(options.color);
            Ok(match options.detail {
                Detail::Compact => hunt_text_compact(options, result, color),
                Detail::Verbose => hunt_text(options, result),
            })
        }
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
            schema_version: 1,
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

fn hunt_text(options: &HuntOptions, result: HuntObservation) -> String {
    let cpu_rank = analysis::analyze_cpu(result.psi.as_ref().ok(), result.cpu.as_ref().ok())
        .findings
        .first()
        .map(|finding| text_finding_rank(finding.severity, finding.resource_confidence))
        .unwrap_or((0, 0));
    let memory_rank = result
        .memory
        .as_ref()
        .and_then(|memory| {
            analysis::analyze_memory(memory.psi.as_ref().ok(), memory.context.as_ref().ok())
                .findings
                .first()
                .map(|finding| text_finding_rank(finding.severity, finding.resource_confidence))
        })
        .unwrap_or((0, 0));
    let io_rank = result
        .io
        .as_ref()
        .and_then(|io| {
            analysis::analyze_io(
                io.psi.as_ref().ok(),
                io.diskstats.as_ref().ok(),
                io.processes.as_ref().ok(),
            )
            .findings
            .first()
            .map(|finding| text_finding_rank(finding.severity, finding.resource_confidence))
        })
        .unwrap_or((0, 0));
    let chain_text = evidence_chain_hunt_text(&result);
    let cpu_output = cpu_hunt_text(options, result.psi, result.cpu);
    let mut outputs = vec![(cpu_rank, 0_u8, cpu_output)];
    if let Some(memory) = result.memory {
        outputs.push((memory_rank, 1, memory_hunt_text(options, memory)));
    }
    if let Some(io) = result.io {
        outputs.push((io_rank, 2, io_hunt_text(options, io)));
    }
    if let Some(cgroup) = result.cgroup.as_ref() {
        let output = cgroup_hunt_text(cgroup);
        if !output.is_empty() {
            outputs.push((cgroup_text_rank(cgroup), 3, output));
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
    text
}

// Compact renderer -----------------------------------------------------------
//
// The compact renderer is verdict-first: a one-line verdict, a per-resource
// status table carrying the deciding PSI evidence, short candidate lists for
// pressured resources, and a pointer to `--verbose`/`--json` for the full
// explanation. It re-formats the same analyzer findings as the verbose
// renderer; it never recomputes a diagnosis and drops only prose, never an
// evidence class.

#[derive(Debug, Clone)]
struct CompactCpu {
    finding: Option<crate::analysis::CpuFinding>,
    psi_capability: Option<&'static str>,
}

#[derive(Debug, Clone)]
struct CompactMemory {
    finding: Option<crate::analysis::MemoryFinding>,
    psi_capability: Option<&'static str>,
}

#[derive(Debug, Clone)]
struct CompactIo {
    finding: Option<crate::analysis::IoFinding>,
    psi_capability: Option<&'static str>,
}

fn compact_analyses(
    result: &HuntObservation,
) -> (CompactCpu, Option<CompactMemory>, Option<CompactIo>) {
    let cpu = match result.psi {
        Ok(ref psi) => CompactCpu {
            finding: analysis::analyze_cpu(Some(psi), result.cpu.as_ref().ok())
                .findings
                .into_iter()
                .next(),
            psi_capability: None,
        },
        Err(ref error) => CompactCpu {
            finding: None,
            psi_capability: Some(error.capability().as_str()),
        },
    };
    let memory = result.memory.as_ref().map(|memory| match memory.psi {
        Ok(ref psi) => CompactMemory {
            finding: analysis::analyze_memory(Some(psi), memory.context.as_ref().ok())
                .findings
                .into_iter()
                .next(),
            psi_capability: None,
        },
        Err(ref error) => CompactMemory {
            finding: None,
            psi_capability: Some(error.capability().as_str()),
        },
    });
    let io = result.io.as_ref().map(|io| match io.psi {
        Ok(ref psi) => CompactIo {
            finding: analysis::analyze_io(
                Some(psi),
                io.diskstats.as_ref().ok(),
                io.processes.as_ref().ok(),
            )
            .findings
            .into_iter()
            .next(),
            psi_capability: None,
        },
        Err(ref error) => CompactIo {
            finding: None,
            psi_capability: Some(error.capability().as_str()),
        },
    });
    (cpu, memory, io)
}

fn hunt_text_compact(options: &HuntOptions, result: HuntObservation, color: ColorUse) -> String {
    let (cpu, memory, io) = compact_analyses(&result);

    let mut output = String::new();
    output.push_str(&ui::paint(
        &format!(
            "stallhunt {} · observed {}",
            env!("CARGO_PKG_VERSION"),
            human_duration(options.duration_ms)
        ),
        Style::Dim,
        color,
    ));
    output.push('\n');
    output.push_str(&compact_verdict_line(
        &cpu,
        memory.as_ref(),
        io.as_ref(),
        color,
    ));
    output.push('\n');
    output.push_str(&compact_resource_table(
        &cpu,
        memory.as_ref(),
        io.as_ref(),
        color,
    ));
    output.push('\n');

    for block in compact_pressure_blocks(&cpu, memory.as_ref(), io.as_ref(), color) {
        output.push_str(&block);
        output.push('\n');
    }
    let cgroup_section = compact_cgroup_section(result.cgroup.as_ref(), color);
    if !cgroup_section.is_empty() {
        output.push_str(&cgroup_section);
        output.push('\n');
    }
    let chain_section = compact_chain_section(&result);
    if !chain_section.is_empty() {
        output.push_str(&chain_section);
        output.push('\n');
    }
    let timing_line = compact_timing_line(&result, color);
    if !timing_line.is_empty() {
        output.push_str(&timing_line);
    }
    output.push_str(&ui::paint(
        "Use --verbose for full evidence, qualifiers, and timings · --json for machine-readable output",
        Style::Dim,
        color,
    ));
    output.push('\n');
    output
}

/// One pressured finding headline: `<name> · <severity> · confidence <c>`.
fn compact_finding_header(
    name: &str,
    severity: crate::analysis::Severity,
    confidence: crate::analysis::Confidence,
    color: ColorUse,
) -> String {
    format!(
        "{} · {} · confidence {}",
        name,
        paint_severity(severity, color),
        confidence_name(confidence)
    )
}

fn paint_severity(severity: crate::analysis::Severity, color: ColorUse) -> String {
    ui::paint(severity_name(severity), ui::severity_style(severity), color)
}

const fn compact_cpu_name(kind: crate::analysis::AssessmentKind) -> &'static str {
    match kind {
        crate::analysis::AssessmentKind::CpuContention => "CPU scheduling contention",
        crate::analysis::AssessmentKind::CpuNoMeaningfulContention => "no CPU contention",
        crate::analysis::AssessmentKind::InsufficientObservation => "CPU observation too short",
    }
}

const fn compact_memory_name(kind: crate::analysis::MemoryAssessmentKind) -> &'static str {
    match kind {
        crate::analysis::MemoryAssessmentKind::NoHarmfulPressure => "no harmful memory pressure",
        crate::analysis::MemoryAssessmentKind::Pressure => "Memory pressure",
        crate::analysis::MemoryAssessmentKind::ReclaimPressure => "Memory reclaim pressure",
        crate::analysis::MemoryAssessmentKind::SwapPressure => "Memory swap pressure",
        crate::analysis::MemoryAssessmentKind::PossibleThrashing => "Possible memory thrashing",
        crate::analysis::MemoryAssessmentKind::InsufficientObservation => {
            "memory observation too short"
        }
    }
}

const fn compact_memory_is_pressure(kind: crate::analysis::MemoryAssessmentKind) -> bool {
    matches!(
        kind,
        crate::analysis::MemoryAssessmentKind::Pressure
            | crate::analysis::MemoryAssessmentKind::ReclaimPressure
            | crate::analysis::MemoryAssessmentKind::SwapPressure
            | crate::analysis::MemoryAssessmentKind::PossibleThrashing
    )
}

struct VerdictCandidate {
    severity_rank: u8,
    confidence_rank: u8,
    resource_rank: u8,
    name: &'static str,
    severity: crate::analysis::Severity,
    confidence: crate::analysis::Confidence,
}

fn compact_verdict_line(
    cpu: &CompactCpu,
    memory: Option<&CompactMemory>,
    io: Option<&CompactIo>,
    color: ColorUse,
) -> String {
    let mut candidates: Vec<VerdictCandidate> = Vec::new();
    let mut any_insufficient = false;
    let mut available = 0_u32;

    if let Some(finding) = cpu.finding.as_ref() {
        available += 1;
        if finding.kind == crate::analysis::AssessmentKind::CpuContention {
            candidates.push(compact_candidate(
                0,
                compact_cpu_name(finding.kind),
                finding.severity,
                finding.resource_confidence,
            ));
        } else if finding.kind == crate::analysis::AssessmentKind::InsufficientObservation {
            any_insufficient = true;
        }
    }
    if let Some(finding) = memory.and_then(|memory| memory.finding.as_ref()) {
        available += 1;
        if compact_memory_is_pressure(finding.kind) {
            candidates.push(compact_candidate(
                1,
                compact_memory_name(finding.kind),
                finding.severity,
                finding.resource_confidence,
            ));
        } else if finding.kind == crate::analysis::MemoryAssessmentKind::InsufficientObservation {
            any_insufficient = true;
        }
    }
    if let Some(finding) = io.and_then(|io| io.finding.as_ref()) {
        available += 1;
        if finding.kind == crate::analysis::IoAssessmentKind::Pressure {
            candidates.push(compact_candidate(
                2,
                "Block-I/O pressure",
                finding.severity,
                finding.resource_confidence,
            ));
        } else if finding.kind == crate::analysis::IoAssessmentKind::InsufficientObservation {
            any_insufficient = true;
        }
    }

    let headline = if let Some(top) = candidates.iter().max_by(|left, right| {
        left.severity_rank
            .cmp(&right.severity_rank)
            .then_with(|| left.confidence_rank.cmp(&right.confidence_rank))
            .then_with(|| right.resource_rank.cmp(&left.resource_rank))
    }) {
        format!(
            "{} — {} (confidence {})",
            top.name,
            paint_severity(top.severity, color),
            confidence_name(top.confidence)
        )
    } else if any_insufficient {
        "inconclusive — observation window shorter than 1s".to_owned()
    } else if available == 0 {
        "no diagnosis — telemetry unavailable".to_owned()
    } else if cpu.psi_capability.is_some()
        || memory.is_some_and(|memory| memory.psi_capability.is_some())
        || io.is_some_and(|io| io.psi_capability.is_some())
    {
        "no meaningful contention detected · some telemetry unavailable".to_owned()
    } else {
        "no meaningful contention detected".to_owned()
    };
    format!("Verdict: {headline}")
}

fn compact_candidate(
    resource_rank: u8,
    name: &'static str,
    severity: crate::analysis::Severity,
    confidence: crate::analysis::Confidence,
) -> VerdictCandidate {
    let (severity_rank, confidence_rank) = text_finding_rank(severity, confidence);
    VerdictCandidate {
        severity_rank,
        confidence_rank,
        resource_rank,
        name,
        severity,
        confidence,
    }
}

enum CompactStatus {
    Pressure(crate::analysis::Severity),
    Ok,
    ShortWindow,
    Unavailable,
}

impl CompactStatus {
    fn word_width(&self) -> usize {
        match self {
            Self::Pressure(_) => "pressure".len(),
            Self::Ok => StatusWord::Ok.label().len(),
            Self::ShortWindow => "short window".len(),
            Self::Unavailable => StatusWord::Unavailable.label().len(),
        }
    }

    fn paint(&self, color: ColorUse) -> String {
        match self {
            Self::Pressure(severity) => ui::paint("pressure", ui::severity_style(*severity), color),
            Self::Ok => ui::paint(
                StatusWord::Ok.label(),
                ui::status_style(StatusWord::Ok),
                color,
            ),
            Self::ShortWindow => ui::paint(
                "short window",
                ui::status_style(StatusWord::Unconfirmed),
                color,
            ),
            Self::Unavailable => ui::paint(
                StatusWord::Unavailable.label(),
                ui::status_style(StatusWord::Unavailable),
                color,
            ),
        }
    }
}

#[allow(clippy::type_complexity)]
fn compact_resource_table(
    cpu: &CompactCpu,
    memory: Option<&CompactMemory>,
    io: Option<&CompactIo>,
    color: ColorUse,
) -> String {
    // (label, status, severity, detail)
    let mut rows: Vec<(
        String,
        CompactStatus,
        Option<crate::analysis::Severity>,
        String,
    )> = Vec::new();
    if let Some(finding) = cpu.finding.as_ref() {
        rows.push(compact_cpu_row(finding, color));
    } else {
        rows.push(compact_unavailable_row(
            "CPU",
            cpu.psi_capability.unwrap_or("failed"),
            color,
        ));
    }
    if let Some(memory) = memory {
        if let Some(finding) = memory.finding.as_ref() {
            rows.push(compact_memory_row(finding, color));
        } else {
            rows.push(compact_unavailable_row(
                "Memory",
                memory.psi_capability.unwrap_or("failed"),
                color,
            ));
        }
    }
    if let Some(io) = io {
        if let Some(finding) = io.finding.as_ref() {
            rows.push(compact_io_row(finding, color));
        } else {
            rows.push(compact_unavailable_row(
                "I/O",
                io.psi_capability.unwrap_or("failed"),
                color,
            ));
        }
    }
    let status_width = rows
        .iter()
        .map(|(_, status, _, _)| status.word_width())
        .max()
        .unwrap_or(0)
        + 1;
    let severity_width = "moderate".len() + 1;
    let mut output = String::new();
    for (label, status, severity, detail) in rows {
        let severity_text = severity.map(|severity| paint_severity(severity, color));
        output.push_str(&format!(
            "  {:<8} {:<status_width$} {:<severity_width$} {}\n",
            label,
            status.paint(color),
            severity_text.unwrap_or_default(),
            detail,
        ));
    }
    output
}

#[allow(clippy::type_complexity)]
fn compact_unavailable_row(
    label: &str,
    capability: &'static str,
    color: ColorUse,
) -> (
    String,
    CompactStatus,
    Option<crate::analysis::Severity>,
    String,
) {
    (
        label.to_owned(),
        CompactStatus::Unavailable,
        None,
        ui::paint(&format!("(PSI {capability})"), Style::Dim, color),
    )
}

#[allow(clippy::type_complexity)]
fn compact_cpu_row(
    finding: &crate::analysis::CpuFinding,
    color: ColorUse,
) -> (
    String,
    CompactStatus,
    Option<crate::analysis::Severity>,
    String,
) {
    let is_pressure = finding.kind == crate::analysis::AssessmentKind::CpuContention;
    (
        "CPU".to_owned(),
        compact_status_for(
            is_pressure,
            finding.kind == crate::analysis::AssessmentKind::InsufficientObservation,
            finding.severity,
        ),
        pressure_severity(is_pressure, finding.severity),
        compact_psi_detail(
            finding.evidence.psi_some_fraction,
            finding.evidence.psi_total_delta_us,
            finding.evidence.psi_window_us,
            color,
        ),
    )
}

#[allow(clippy::type_complexity)]
fn compact_memory_row(
    finding: &crate::analysis::MemoryFinding,
    color: ColorUse,
) -> (
    String,
    CompactStatus,
    Option<crate::analysis::Severity>,
    String,
) {
    let is_pressure = compact_memory_is_pressure(finding.kind);
    let mut detail = compact_psi_detail(
        finding.evidence.psi_some_fraction,
        finding.evidence.psi_some_total_delta_us,
        finding.evidence.psi_window_us,
        color,
    );
    if let Some(occupancy) = finding.evidence.memory_occupancy_fraction {
        detail.push_str(&format!(" · {:.0}% used", occupancy * 100.0));
    }
    if let Some(swap) = finding.evidence.swap_used_bytes.filter(|swap| *swap > 0) {
        detail.push_str(&format!(" · {} swap used", human_bytes(swap)));
    }
    (
        "Memory".to_owned(),
        compact_status_for(
            is_pressure,
            finding.kind == crate::analysis::MemoryAssessmentKind::InsufficientObservation,
            finding.severity,
        ),
        pressure_severity(is_pressure, finding.severity),
        detail,
    )
}

#[allow(clippy::type_complexity)]
fn compact_io_row(
    finding: &crate::analysis::IoFinding,
    color: ColorUse,
) -> (
    String,
    CompactStatus,
    Option<crate::analysis::Severity>,
    String,
) {
    let is_pressure = finding.kind == crate::analysis::IoAssessmentKind::Pressure;
    (
        "I/O".to_owned(),
        compact_status_for(
            is_pressure,
            finding.kind == crate::analysis::IoAssessmentKind::InsufficientObservation,
            finding.severity,
        ),
        pressure_severity(is_pressure, finding.severity),
        compact_psi_detail(
            finding.evidence.psi_some_fraction,
            finding.evidence.psi_some_total_delta_us,
            finding.evidence.psi_window_us,
            color,
        ),
    )
}

fn compact_status_for(
    is_pressure: bool,
    is_insufficient: bool,
    severity: crate::analysis::Severity,
) -> CompactStatus {
    if is_pressure {
        CompactStatus::Pressure(severity)
    } else if is_insufficient {
        CompactStatus::ShortWindow
    } else {
        CompactStatus::Ok
    }
}

const fn pressure_severity(
    is_pressure: bool,
    severity: crate::analysis::Severity,
) -> Option<crate::analysis::Severity> {
    if is_pressure { Some(severity) } else { None }
}

fn compact_psi_detail(
    some_fraction: f64,
    total_delta_us: u64,
    window_us: u128,
    color: ColorUse,
) -> String {
    let stalled = ui::paint(
        &human_duration_from_duration(Duration::from_micros(total_delta_us)),
        Style::Dim,
        color,
    );
    format!(
        "PSI some {:.2}% · {} stalled / {}",
        some_fraction * 100.0,
        stalled,
        human_duration_from_duration(Duration::from_micros(
            u64::try_from(window_us).unwrap_or(u64::MAX)
        ))
    )
}

fn compact_pressure_blocks(
    cpu: &CompactCpu,
    memory: Option<&CompactMemory>,
    io: Option<&CompactIo>,
    color: ColorUse,
) -> Vec<String> {
    let mut blocks = Vec::new();
    if let Some(finding) = cpu.finding.as_ref() {
        if finding.kind == crate::analysis::AssessmentKind::CpuContention {
            blocks.push(compact_cpu_block(finding, color));
        }
    }
    if let Some(finding) = memory.and_then(|memory| memory.finding.as_ref()) {
        if compact_memory_is_pressure(finding.kind) {
            blocks.push(compact_memory_block(finding, color));
        }
    }
    if let Some(finding) = io.and_then(|io| io.finding.as_ref()) {
        if finding.kind == crate::analysis::IoAssessmentKind::Pressure {
            blocks.push(compact_io_block(finding, color));
        }
    }
    blocks
}

/// Pad `name [pid]` columns so compact candidate lists align.
fn aligned_candidates(entries: &[(String, String)]) -> String {
    let width = entries
        .iter()
        .map(|(name, _)| name.chars().count())
        .max()
        .unwrap_or(0);
    entries
        .iter()
        .map(|(name, value)| format!("    {:<width$}  {}\n", name, value, width = width))
        .collect()
}

fn compact_cpu_block(finding: &crate::analysis::CpuFinding, color: ColorUse) -> String {
    let mut output = compact_finding_header(
        compact_cpu_name(finding.kind),
        finding.severity,
        finding.resource_confidence,
        color,
    );
    output.push('\n');
    if !finding.victims.is_empty() {
        output.push_str("  Victims — observed runnable delay, not confirmed harm:\n");
        let victims: Vec<_> = finding
            .victims
            .iter()
            .take(3)
            .map(|victim| {
                (
                    format!("{} [{}]", terminal_name(&victim.name), victim.key.pid),
                    format!(
                        "{} delayed",
                        human_duration_from_duration(Duration::from_nanos(victim.runnable_wait_ns))
                    ),
                )
            })
            .collect();
        output.push_str(&aligned_candidates(&victims));
    }
    if !finding.suspects.is_empty() {
        output.push_str("  Suspects — same window only, not proven causal:\n");
        let suspects: Vec<_> = finding
            .suspects
            .iter()
            .take(3)
            .map(|suspect| {
                (
                    format!("{} [{}]", terminal_name(&suspect.name), suspect.key.pid),
                    format!("{:.1}% of one CPU", suspect.cpu_fraction_of_one * 100.0),
                )
            })
            .collect();
        output.push_str(&aligned_candidates(&suspects));
    }
    output
}

fn compact_memory_block(finding: &crate::analysis::MemoryFinding, color: ColorUse) -> String {
    let mut detail = format!(
        "PSI some {:.2}% over {}",
        finding.evidence.psi_some_fraction * 100.0,
        human_duration_from_duration(Duration::from_micros(finding.evidence.psi_window_us as u64))
    );
    if let Some(full) = finding.evidence.psi_full_fraction {
        detail.push_str(&format!(" · full {:.2}% (all tasks stalled)", full * 100.0));
    }
    if let Some(occupancy) = finding.evidence.memory_occupancy_fraction {
        detail.push_str(&format!(" · {:.0}% used", occupancy * 100.0));
    }
    if let Some(confidence) = finding.mechanism_confidence {
        detail.push_str(&format!(
            " · mechanism confidence {}",
            confidence_name(confidence)
        ));
    }
    format!(
        "{}\n  {}\n",
        compact_finding_header(
            compact_memory_name(finding.kind),
            finding.severity,
            finding.resource_confidence,
            color,
        ),
        detail
    )
}

fn compact_io_block(finding: &crate::analysis::IoFinding, color: ColorUse) -> String {
    let mut output = compact_finding_header(
        "Block-I/O pressure",
        finding.severity,
        finding.resource_confidence,
        color,
    );
    output.push('\n');
    if !finding.device_candidates.is_empty() {
        output.push_str("  Devices — same-window activity, not mapped to victims:\n");
        let devices: Vec<_> = finding
            .device_candidates
            .iter()
            .take(3)
            .map(|device| {
                let mut value = String::new();
                if let Some(busy) = device.io_ticks_ms {
                    value.push_str(&format!(
                        "{} busy",
                        human_duration_from_duration(Duration::from_millis(busy))
                    ));
                }
                if let Some(read) = device.read_sectors_512 {
                    let separator = if value.is_empty() { "" } else { " · " };
                    value.push_str(&format!("{}{} read", separator, human_bytes(read * 512)));
                }
                if let Some(write) = device.write_sectors_512 {
                    value.push_str(&format!(" · {} written", human_bytes(write * 512)));
                }
                (terminal_name(&device.name), value)
            })
            .collect();
        output.push_str(&aligned_candidates(&devices));
    }
    if !finding.process_suspects.is_empty() {
        output.push_str("  Processes — same-window accounting, not proven causes:\n");
        let processes: Vec<_> = finding
            .process_suspects
            .iter()
            .take(3)
            .map(|suspect| {
                let mut value = String::new();
                if let Some(read) = suspect.read_bytes {
                    value.push_str(&format!("{} read", human_bytes(read)));
                }
                if let Some(write) = suspect.write_bytes {
                    let separator = if value.is_empty() { "" } else { " · " };
                    value.push_str(&format!(
                        "{}{} charged write",
                        separator,
                        human_bytes(write)
                    ));
                }
                (
                    format!("{} [{}]", terminal_name(&suspect.name), suspect.key.pid),
                    value,
                )
            })
            .collect();
        output.push_str(&aligned_candidates(&processes));
    }
    output
}

fn compact_cgroup_section(cgroup: Option<&CgroupHuntObservation>, color: ColorUse) -> String {
    let Some(cgroup) = cgroup else {
        return String::new();
    };
    let Ok(observation) = &cgroup.observation else {
        // Unavailability stays visible in compact mode too; the per-resource
        // PSI rows above only cover host resources.
        let capability = match &cgroup.observation {
            Err(crate::cgroup::CgroupError::Unsupported) => "unsupported",
            Err(crate::cgroup::CgroupError::PermissionDenied) => "permission_denied",
            Err(_) => "failed",
            Ok(_) => unreachable!("guarded by the Ok arm"),
        };
        return format!(
            "{}\n",
            ui::paint(
                &format!("Scoped cgroups: unavailable ({capability})"),
                Style::Dim,
                color,
            )
        );
    };
    let pressured: Vec<_> = analysis::analyze_cgroups(Some(observation))
        .findings
        .into_iter()
        .filter(|finding| finding.kind == crate::analysis::CgroupAssessmentKind::Pressure)
        .collect();
    if pressured.is_empty() {
        return format!(
            "{}\n",
            ui::paint(
                "Scoped cgroups: no pressure in the bounded selection",
                Style::Dim,
                color,
            )
        );
    }
    let shown = pressured.len().min(3);
    let mut output = String::from("Scoped cgroup pressure");
    if pressured.len() > shown {
        output.push_str(&format!(" · {} more", pressured.len() - shown));
    }
    output.push('\n');
    for finding in pressured.iter().take(shown) {
        let mut resource = cgroup_resource_label(finding.resource).to_owned();
        if let Some(mechanism) = finding.mechanism {
            resource.push_str(&format!(" ({})", cgroup_mechanism_label(mechanism)));
        }
        output.push_str(&format!(
            "  {} · {} {} · PSI some {:.2}%\n",
            finding.path,
            resource,
            paint_severity(finding.severity, color),
            finding.evidence.psi_some_fraction.unwrap_or(0.0) * 100.0
        ));
    }
    output
}

const fn cgroup_resource_label(resource: crate::analysis::CgroupResourceKind) -> &'static str {
    match resource {
        crate::analysis::CgroupResourceKind::Cpu => "cpu",
        crate::analysis::CgroupResourceKind::Memory => "memory",
        crate::analysis::CgroupResourceKind::Io => "io",
    }
}

const fn cgroup_mechanism_label(mechanism: crate::analysis::CgroupMechanism) -> &'static str {
    match mechanism {
        crate::analysis::CgroupMechanism::Reclaim => "reclaim",
        crate::analysis::CgroupMechanism::Swap => "swap",
        crate::analysis::CgroupMechanism::PossibleThrashing => "possible thrashing",
        crate::analysis::CgroupMechanism::CpuQuotaThrottle => "quota throttle",
    }
}

fn compact_chain_section(result: &HuntObservation) -> String {
    let chains = evidence_chains_from_observation(result);
    if chains.is_empty() {
        return String::new();
    }
    let mut output = String::from("Related evidence\n");
    for chain in chains {
        let summary = lowercase_first(trim_sentence(&chain.summary));
        output.push_str(&format!(
            "  {} (confidence {})\n",
            summary,
            confidence_name(chain.confidence)
        ));
    }
    output
}

fn trim_sentence(sentence: &str) -> &str {
    sentence.trim_end_matches('.')
}

fn lowercase_first(text: &str) -> String {
    let mut characters = text.chars();
    match characters.next() {
        Some(first) => first.to_lowercase().collect::<String>() + characters.as_str(),
        None => String::new(),
    }
}

fn compact_timing_line(result: &HuntObservation, color: ColorUse) -> String {
    let mut parts = Vec::new();
    if let Ok(psi) = &result.psi {
        parts.push(format!(
            "PSI {}",
            human_duration_from_duration(psi.interval.elapsed)
        ));
    }
    if let Ok(cpu) = &result.cpu {
        parts.push(format!(
            "CPU/process {}",
            human_duration_from_duration(cpu.elapsed)
        ));
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
    format!(
        "{}\n",
        ui::paint(
            &format!("measured: {}", parts.join(" · ")),
            Style::Dim,
            color
        )
    )
}

fn evidence_chain_hunt_text(result: &HuntObservation) -> Option<String> {
    let chains = evidence_chains_from_observation(result);
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

fn evidence_chains_from_observation(
    result: &HuntObservation,
) -> Vec<crate::analysis::EvidenceChain> {
    let memory = result.memory.as_ref().and_then(|memory| {
        analysis::analyze_memory(memory.psi.as_ref().ok(), memory.context.as_ref().ok())
            .findings
            .into_iter()
            .next()
    });
    let io = result.io.as_ref().and_then(|io| {
        analysis::analyze_io(
            io.psi.as_ref().ok(),
            io.diskstats.as_ref().ok(),
            io.processes.as_ref().ok(),
        )
        .findings
        .into_iter()
        .next()
    });
    let cgroup_findings = result
        .cgroup
        .as_ref()
        .and_then(|cgroup| cgroup.observation.as_ref().ok())
        .map(|observation| analysis::analyze_cgroups(Some(observation)).findings)
        .unwrap_or_default();
    analysis::analyze_evidence_chains(memory.as_ref(), io.as_ref(), &cgroup_findings)
}

fn chain_evidence_details(evidence: &crate::analysis::ChainEvidence) -> String {
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

fn cgroup_text_rank(cgroup: &CgroupHuntObservation) -> (u8, u8) {
    let Ok(observation) = &cgroup.observation else {
        return (0, 0);
    };
    analysis::analyze_cgroups(Some(observation))
        .findings
        .iter()
        .map(|finding| text_finding_rank(finding.severity, finding.resource_confidence))
        .max()
        .unwrap_or((0, 0))
}

fn cgroup_hunt_text(cgroup: &CgroupHuntObservation) -> String {
    let Ok(observation) = &cgroup.observation else {
        return "Scoped cgroup findings\nCgroup v2 assessment unavailable.\n".into();
    };
    let analysis = analysis::analyze_cgroups(Some(observation));
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
) -> String {
    match (psi, cpu) {
        (Ok(observation), Ok(cpu)) => {
            let analysis = analysis::analyze_cpu(Some(&observation), Some(&cpu));
            finding_text(
                &analysis,
                options.duration_ms,
                observation.interval.elapsed,
                Some(cpu.elapsed),
            )
        }
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
            let analysis = analysis::analyze_cpu(Some(&psi), None);
            let mut output =
                finding_text(&analysis, options.duration_ms, psi.interval.elapsed, None);
            output.push_str(&format!(
                "CPU/process telemetry: unavailable — {}\n",
                error.explanation()
            ));
            output
        }
    }
}

fn text_finding_rank(
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

fn memory_hunt_text(options: &HuntOptions, memory: MemoryHuntObservation) -> String {
    match (memory.psi, memory.context) {
        (Ok(psi), Ok(context)) => {
            let analysis = analysis::analyze_memory(Some(&psi), Some(&context));
            memory_finding_text(&analysis, options.duration_ms, &psi, Some(&context))
        }
        (Ok(psi), Err(_)) => {
            let analysis = analysis::analyze_memory(Some(&psi), None);
            memory_finding_text(&analysis, options.duration_ms, &psi, None)
        }
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

fn io_hunt_text(options: &HuntOptions, io: IoHuntObservation) -> String {
    match (io.psi, io.diskstats, io.processes) {
        (Ok(psi), diskstats, processes) => {
            let analysis =
                analysis::analyze_io(Some(&psi), diskstats.as_ref().ok(), processes.as_ref().ok());
            io_finding_text(
                &analysis,
                options.duration_ms,
                &psi,
                diskstats.as_ref().ok(),
                processes.as_ref().ok(),
            )
        }
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

fn human_bytes(bytes: u64) -> String {
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

fn severity_name(severity: crate::analysis::Severity) -> &'static str {
    match severity {
        crate::analysis::Severity::None => "none",
        crate::analysis::Severity::Low => "low",
        crate::analysis::Severity::Moderate => "moderate",
        crate::analysis::Severity::High => "high",
        crate::analysis::Severity::Severe => "severe",
    }
}

fn confidence_name(confidence: crate::analysis::Confidence) -> &'static str {
    match confidence {
        crate::analysis::Confidence::Low => "low",
        crate::analysis::Confidence::Medium => "medium",
        crate::analysis::Confidence::High => "high",
    }
}

fn suspect_role(label: &str) -> &'static str {
    match label {
        "leading_concurrent_cpu_consumer" => "leading concurrent CPU consumer",
        _ => "concurrent CPU consumer",
    }
}

fn terminal_name(name: &str) -> String {
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
        schema_version: 1,
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
            Some(cpu) => Self {
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

fn human_duration(duration_ms: u64) -> String {
    human_duration_from_duration(Duration::from_millis(duration_ms))
}

fn human_duration_from_duration(duration: Duration) -> String {
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
mod tests {
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
    use crate::ui::ColorMode;

    fn render_hunt<F>(options: &HuntOptions, observe: F) -> String
    where
        F: FnOnce(Duration) -> HuntObservation,
    {
        super::hunt(options, observe).expect("hunt render")
    }

    /// Verbose, colorless text options: the pre-redesign renderer retained by
    /// `--verbose`.
    fn hunt_text_options(duration_ms: u64) -> HuntOptions {
        HuntOptions {
            duration_ms,
            output: OutputFormat::Text,
            detail: crate::cli::Detail::Verbose,
            color: ColorMode::Never,
        }
    }

    fn hunt_json_options(duration_ms: u64) -> HuntOptions {
        HuntOptions {
            duration_ms,
            output: OutputFormat::Json,
            detail: crate::cli::Detail::Compact,
            color: ColorMode::Never,
        }
    }

    /// Compact, colorless text options: the new default human output.
    fn hunt_compact_options(duration_ms: u64) -> HuntOptions {
        HuntOptions {
            duration_ms,
            output: OutputFormat::Text,
            detail: crate::cli::Detail::Compact,
            color: ColorMode::Never,
        }
    }

    /// Compact text options with forced color for escape-sequence tests.
    fn hunt_compact_color_options(duration_ms: u64) -> HuntOptions {
        HuntOptions {
            duration_ms,
            output: OutputFormat::Text,
            detail: crate::cli::Detail::Compact,
            color: ColorMode::Auto,
        }
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
                collection_issues: ProcessCollectionIssues::default(),
                scheduler_delay_candidates: Vec::new(),
                schedstat_collection_issues: crate::cpu::SchedstatCollectionIssues::default(),
                schedstat_capability: crate::cpu::SchedstatCapability::Unsupported,
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
        let text = render_hunt(&hunt_text_options(1_000), |_| observation);
        assert!(text.starts_with("Scoped cgroup findings"));
        assert!(text.contains("Scoped CPU quota-throttle pressure"));
        assert!(text.contains("mechanism confidence low"));
        assert!(text.contains("controller context: CPU usage +2s; throttled +250ms"));
        assert!(text.contains("scoped context only; not causal proof"));

        let mut observation = hunt_observation();
        observation.cgroup = Some(scoped_cgroup_observation(true));
        let json: serde_json::Value =
            serde_json::from_str(&render_hunt(&hunt_json_options(1_000), |_| observation)).unwrap();
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
    }

    #[test]
    fn io_renderer_keeps_psi_pressure_independent_of_context_and_never_claims_mapping() {
        let mut observation = hunt_observation();
        observation.io = Some(io_hunt_observation(0.08));
        let text = render_hunt(&hunt_text_options(10_000), |_| observation);
        assert!(text.contains("Block-I/O pressure observed"));
        assert!(
            text.contains("Device activity candidates (same window only; not mapped to workloads)")
        );
        assert!(text.contains("not proven causal or device-mapped"));
        assert!(text.contains("Affected workloads: unavailable"));

        let mut healthy = hunt_observation();
        healthy.io = Some(io_hunt_observation(0.005));
        let text = render_hunt(&hunt_text_options(10_000), |_| healthy);
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
        let json: serde_json::Value =
            serde_json::from_str(&render_hunt(&hunt_json_options(10_000), |_| observation))
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
        let output = render_hunt(&hunt_text_options(1_000), |_| hunt_observation());
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
        let json: serde_json::Value =
            serde_json::from_str(&render_hunt(&hunt_json_options(1_000), |_| {
                hunt_observation()
            }))
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
        let partial: serde_json::Value =
            serde_json::from_str(&render_hunt(&hunt_json_options(1_000), |_| {
                HuntObservation {
                    psi: Ok(observation()),
                    cpu: Err(crate::cpu::CpuError::Unreadable),
                    memory: None,
                    io: None,
                    cgroup: None,
                }
            }))
            .unwrap();
        assert_eq!(partial["status"], "incomplete");
        assert_eq!(partial["findings"][0]["kind"], "cpu_scheduling_contention");
        assert!(partial["findings"][0]["evidence"]["host_utilization_fraction"].is_null());
        assert!(partial["qualifiers"][0]["kind"].is_string());

        let partial_text = render_hunt(&hunt_text_options(1_000), |_| HuntObservation {
            psi: Ok(observation()),
            cpu: Err(crate::cpu::CpuError::Unreadable),
            memory: None,
            io: None,
            cgroup: None,
        });
        assert!(partial_text.contains("CPU interval context is unavailable"));
        assert!(partial_text.contains("CPU/process telemetry: unavailable"));
        assert!(partial_text.contains("Victim candidates: unavailable"));
        assert!(partial_text.contains("Suspect candidates: unavailable"));
        assert!(!partial_text.contains("none observed"));
    }

    #[test]
    fn hunt_json_contains_typed_cpu_psi_evidence() {
        let output = render_hunt(&hunt_json_options(1_000), |_| hunt_observation());
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
        let text = render_hunt(&hunt_text_options(10_000), |_| observation);
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
        let json: serde_json::Value =
            serde_json::from_str(&render_hunt(&hunt_json_options(10_000), |_| observation))
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
        let json: serde_json::Value =
            serde_json::from_str(&render_hunt(&hunt_json_options(10_000), |_| partial)).unwrap();
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
        let json: serde_json::Value =
            serde_json::from_str(&render_hunt(&hunt_json_options(10_000), |_| missing)).unwrap();
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
        let text = render_hunt(&hunt_text_options(10_000), |_| {
            chain_hunt_observation(true, true)
        });
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

        let json: serde_json::Value =
            serde_json::from_str(&render_hunt(&hunt_json_options(10_000), |_| {
                chain_hunt_observation(true, true)
            }))
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

        let coincident: serde_json::Value =
            serde_json::from_str(&render_hunt(&hunt_json_options(10_000), |_| {
                chain_hunt_observation(false, true)
            }))
            .unwrap();
        assert_eq!(coincident["evidence_chains"].as_array().unwrap().len(), 0);
        assert!(
            !render_hunt(&hunt_text_options(10_000), |_| chain_hunt_observation(
                false, true
            ),)
            .contains("Related evidence")
        );

        let io_healthy: serde_json::Value =
            serde_json::from_str(&render_hunt(&hunt_json_options(10_000), |_| {
                chain_hunt_observation(true, false)
            }))
            .unwrap();
        assert_eq!(io_healthy["evidence_chains"].as_array().unwrap().len(), 0);

        let cpu_only: serde_json::Value =
            serde_json::from_str(&render_hunt(&hunt_json_options(1_000), |_| {
                hunt_observation()
            }))
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
        let text = render_hunt(&hunt_text_options(10_000), |_| {
            cgroup_chain_hunt_observation()
        });
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

        let json: serde_json::Value =
            serde_json::from_str(&render_hunt(&hunt_json_options(10_000), |_| {
                cgroup_chain_hunt_observation()
            }))
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
        let coincident_json: serde_json::Value =
            serde_json::from_str(&render_hunt(&hunt_json_options(10_000), |_| coincident)).unwrap();
        assert_eq!(
            coincident_json["evidence_chains"].as_array().unwrap().len(),
            0
        );

        let mut combined = chain_hunt_observation(true, true);
        combined.cgroup = Some(scoped_memory_io_cgroup_observation(
            Some(reclaim_events()),
            true,
        ));
        let combined_json: serde_json::Value =
            serde_json::from_str(&render_hunt(&hunt_json_options(10_000), |_| combined)).unwrap();
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
        let json: serde_json::Value =
            serde_json::from_str(&render_hunt(&hunt_json_options(10_000), |_| observation))
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
        let text = render_hunt(&hunt_text_options(10_000), |_| {
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
        });
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
        let json: serde_json::Value =
            serde_json::from_str(&render_hunt(&hunt_json_options(5_000), |_| {
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
            }))
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

        let text = render_hunt(&hunt_text_options(5_000), |_| {
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
        });
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

        let json: serde_json::Value =
            serde_json::from_str(&render_hunt(&hunt_json_options(10_000), |_| observation))
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
        let output = render_hunt(&hunt_text_options(1_000), |_| HuntObservation {
            psi: Err(crate::psi::CpuPsiError::Malformed),
            cpu: Err(crate::cpu::CpuError::Malformed),
            memory: None,
            io: None,
            cgroup: None,
        });
        assert!(output.contains("Capability: CPU PSI failed"));
        assert!(output.contains("did not match the expected kernel format"));
    }

    #[test]
    fn psi_failure_retains_scheduler_delay_text_context() {
        let output = render_hunt(&hunt_text_options(1_000), |_| HuntObservation {
            psi: Err(crate::psi::CpuPsiError::Malformed),
            cpu: hunt_observation().cpu,
            memory: None,
            io: None,
            cgroup: None,
        });
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
        let complete_text = render_hunt(&hunt_text_options(1_000), |_| complete);
        assert!(complete_text.contains("no positive stable runnable-delay candidates"));
        assert!(complete_text.contains("no consumers above 25% of one CPU"));

        let mut retained_partial = hunt_observation();
        retained_partial
            .cpu
            .as_mut()
            .unwrap()
            .collection_issues
            .appeared = 1;
        let retained_partial_text = render_hunt(&hunt_text_options(1_000), |_| retained_partial);
        assert!(retained_partial_text.contains("consumer [9]"));
        assert!(retained_partial_text.contains("Process collection is partial"));

        let mut empty_partial = hunt_observation();
        let cpu = empty_partial.cpu.as_mut().unwrap();
        cpu.processes.clear();
        cpu.collection_issues.appeared = 1;
        let empty_partial_text = render_hunt(&hunt_text_options(1_000), |_| empty_partial);
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
        let retained_scheduler_text =
            render_hunt(&hunt_text_options(1_000), |_| retained_scheduler_partial);
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
        let no_contention_text = render_hunt(&hunt_text_options(1_000), |_| no_contention);
        assert!(no_contention_text.contains("not ranked without a contention finding"));
        assert!(!no_contention_text.contains("no consumers above 25%"));
        assert!(!no_contention_text.contains("no positive stable runnable-delay"));

        let mut short = hunt_observation();
        let psi = short.psi.as_mut().unwrap();
        psi.requested = Duration::from_millis(100);
        psi.interval.elapsed = Duration::from_millis(100);
        short.cpu.as_mut().unwrap().elapsed = Duration::from_millis(100);
        let short_text = render_hunt(&hunt_text_options(100), |_| short);
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
            schedstat_capability: crate::cpu::SchedstatCapability::Available,
        };
        let output = render_hunt(&hunt_text_options(10_000), |_| HuntObservation {
            psi: Ok(observation),
            cpu: Ok(cpu),
            memory: None,
            io: None,
            cgroup: None,
        });
        assert_eq!(
            output,
            include_str!("../tests/fixtures/render/cpu-contention.txt")
        );
        assert!(!output.contains('\u{1b}'));
        assert!(!output.contains("worker\nnext"));
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

    fn assert_or_update_fixture(actual: &str, path: &str, expected: &str) {
        if std::env::var_os("STALLHUNT_UPDATE_FIXTURES").is_some() {
            let full = format!("tests/fixtures/render/{path}");
            std::fs::write(&full, actual).expect("write fixture");
            return;
        }
        assert_eq!(
            actual, expected,
            "golden fixture mismatch for {path}; inspect the diff and refresh with              STALLHUNT_UPDATE_FIXTURES=1 cargo test if intentional"
        );
    }

    fn compact_psi(elapsed: Duration, some_fraction: f64) -> CpuPsiObservation {
        let total_delta_us = (some_fraction * elapsed.as_micros() as f64) as u64;
        CpuPsiObservation {
            requested: elapsed,
            interval: CpuPsiInterval {
                elapsed,
                total_delta_us,
                some_fraction,
            },
            start: CpuPsiRaw {
                avg10_percent: 0.0,
                avg60_percent: 0.0,
                avg300_percent: 0.0,
                total_us: 0,
            },
            end: CpuPsiRaw {
                avg10_percent: some_fraction * 100.0,
                avg60_percent: 0.0,
                avg300_percent: 0.0,
                total_us: total_delta_us,
            },
        }
    }

    fn compact_cpu_with_candidates() -> CpuProcessObservation {
        CpuProcessObservation {
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
            processes: vec![ProcessCpuInterval {
                key: ProcessKey {
                    pid: 20,
                    start_time_ticks: 1,
                },
                name: "build\u{1b}[31m".into(),
                state: 'R',
                cpu_ticks: 80,
                cpu_fraction_of_one: 0.8,
            }],
            collection_issues: ProcessCollectionIssues::default(),
            scheduler_delay_candidates: vec![ProcessSchedulerDelayInterval {
                key: ProcessKey {
                    pid: 21,
                    start_time_ticks: 1,
                },
                name: "worker".into(),
                task_count: 1,
                running_ns: 0,
                runnable_wait_ns: 1_800_000_000,
                runnable_delay_fraction: 0.18,
                timeslices: 1,
            }],
            schedstat_collection_issues: crate::cpu::SchedstatCollectionIssues::default(),
            schedstat_capability: crate::cpu::SchedstatCapability::Available,
        }
    }

    fn compact_pressured_hunt_observation() -> HuntObservation {
        HuntObservation {
            psi: Ok(compact_psi(Duration::from_secs(10), 0.2)),
            cpu: Ok(compact_cpu_with_candidates()),
            memory: Some(memory_hunt_observation(0.08, Some(0.01), true)),
            io: Some(io_hunt_observation(0.12)),
            cgroup: Some(scoped_cgroup_observation(false)),
        }
    }

    fn compact_healthy_hunt_observation() -> HuntObservation {
        let mut cgroup = scoped_cgroup_observation(false);
        if let Ok(observation) = cgroup.observation.as_mut() {
            if let Some(group) = observation.groups.first_mut() {
                // Keep the healthy fixture actually scoped-healthy: minimal
                // CPU pressure and no throttle time to label.
                group.cpu.value = group.cpu.value.take().map(|mut cpu| {
                    cpu.throttled_usec = None;
                    cpu
                });
                if let Some(psi) = group.cpu_pressure.value.as_mut() {
                    psi.some_total_usec = Some(20_000);
                }
            }
        }
        HuntObservation {
            psi: Ok(compact_psi(Duration::from_secs(10), 0.002)),
            cpu: Ok(compact_cpu_with_candidates()),
            memory: Some(memory_hunt_observation(0.0, Some(0.0), true)),
            io: Some(io_hunt_observation(0.004)),
            cgroup: Some(cgroup),
        }
    }

    #[test]
    fn compact_hunt_text_has_a_golden_healthy_fixture() {
        let output = render_hunt(&hunt_compact_options(10_000), |_| {
            compact_healthy_hunt_observation()
        });
        assert!(!output.contains('\u{1b}'));
        assert!(output.contains("Verdict:"));
        assert_or_update_fixture(
            &output,
            "hunt-compact-healthy.txt",
            include_str!("../tests/fixtures/render/hunt-compact-healthy.txt"),
        );
    }

    #[test]
    fn compact_hunt_text_has_a_golden_pressured_fixture() {
        let output = render_hunt(&hunt_compact_options(10_000), |_| {
            compact_pressured_hunt_observation()
        });
        assert!(!output.contains('\u{1b}'));
        // Correlation language survives compaction.
        assert!(output.contains("not confirmed harm"));
        assert!(output.contains("not proven causal"));
        assert!(output.contains("confidence low"));
        assert_or_update_fixture(
            &output,
            "hunt-compact-contention.txt",
            include_str!("../tests/fixtures/render/hunt-compact-contention.txt"),
        );
    }

    #[test]
    fn compact_hunt_text_keeps_unavailable_and_short_windows_honest() {
        let psi_error = HuntObservation {
            psi: Err(crate::psi::CpuPsiError::PermissionDenied),
            cpu: Err(crate::cpu::CpuError::Unreadable),
            memory: Some(memory_hunt_observation(0.0, None, false)),
            io: Some(io_hunt_observation(0.004)),
            cgroup: Some(CgroupHuntObservation {
                observation: Err(crate::cgroup::CgroupError::Unsupported),
            }),
        };
        let output = render_hunt(&hunt_compact_options(10_000), |_| psi_error);
        assert!(output.contains("Verdict: no meaningful contention detected"));
        assert!(output.contains("unavailable"));
        assert!(output.contains("(PSI permission_denied)"));
        assert!(output.contains("Scoped cgroups: unavailable (unsupported)"));
        assert!(output.contains("Use --verbose"));

        let smoke = HuntObservation {
            psi: Ok(compact_psi(Duration::from_millis(500), 0.05)),
            cpu: Ok(compact_cpu_with_candidates()),
            memory: Some(memory_hunt_observation(0.0, None, false)),
            io: Some(io_hunt_observation(0.004)),
            cgroup: None,
        };
        let output = render_hunt(&hunt_compact_options(500), |_| smoke);
        assert!(output.contains("inconclusive — observation window shorter than 1s"));
        assert!(output.contains("short window"));
    }

    #[test]
    fn compact_hunt_text_color_wraps_severity_words_only() {
        let output = super::hunt_text_compact(
            &hunt_compact_color_options(10_000),
            compact_pressured_hunt_observation(),
            ColorUse::Enabled,
        );
        assert!(output.contains("\u{1b}[91mhigh\u{1b}[0m"));
        assert!(output.contains("\u{1b}[33mmoderate\u{1b}[0m"));
        assert!(output.contains("\u{1b}[2m"));
        // The colored renderer still contains the plain-text labels.
        assert!(output.contains("Verdict: CPU scheduling contention"));
    }
}
