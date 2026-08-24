//! Compact, color-coded, width-aware hunt/replay report.
//!
//! This is the TTY presentation for `hunt`/`replay`, alongside — never
//! instead of — the legacy plain-text renderer in `render.rs`. It consumes
//! the same [`crate::render::HuntAnalyses`] the legacy renderer consumes, so
//! the two can never diverge in diagnosis (docs/architecture.md's
//! presentation-purity rule: this module formats, it does not analyze).
//! When stdout is not a terminal, `main.rs` calls the legacy renderer
//! instead of this one; this module never probes the terminal itself.

use crate::analysis::{
    AssessmentKind, CgroupAssessmentKind, IoAssessmentKind, ProcessCandidateAvailability,
    ProcessRole, ProcessRoleCompleteness, Qualifier,
};
use crate::cli::HuntOptions;
use crate::observe::HuntObservation;
use crate::render::{self, HuntAnalyses};
use crate::style::{self, ReportLayout, SeverityTone};
use unicode_width::UnicodeWidthStr;

const CGROUP_ROW_CAP: usize = 3;
const MAX_TAGS_SHOWN: usize = 4;

pub fn hunt_report(
    options: &HuntOptions,
    analyses: &HuntAnalyses,
    observation: &HuntObservation,
    layout: ReportLayout,
) -> String {
    let mut out = String::new();
    out.push_str(&header_line(options, analyses, layout));
    out.push('\n');
    out.push('\n');

    out.push_str(&cpu_row(observation, analyses, layout));
    if let Some(memory) = &analyses.memory {
        out.push_str(&memory_row(memory, layout));
    }
    if let Some(io) = &analyses.io {
        out.push_str(&io_row(io, layout));
    }
    if let Some(cgroup) = &analyses.cgroup {
        out.push_str(&cgroup_rows(cgroup, layout));
    }
    out.push('\n');
    out.push_str(&process_scope_summary(&analyses.process_scopes, layout));

    let chains = render::evidence_chains_from_analyses(analyses);
    if !chains.is_empty() {
        out.push('\n');
        out.push_str(&related_evidence_line(&chains));
    }

    out.push('\n');
    let all_qualifiers = collect_qualifiers(analyses, &chains);
    if layout.verbose {
        out.push_str(&verbose_context_blocks(analyses, &chains));
    } else {
        out.push_str(&context_line(&all_qualifiers));
    }

    out.push_str(&timing_line(options, observation));
    out
}

fn process_scope_summary(scopes: &[crate::analysis::ProcessScope], layout: ReportLayout) -> String {
    if scopes.is_empty() {
        return " Process roles: unavailable\n".to_owned();
    }
    let mut out = String::new();
    for scope in scopes {
        let label_width = layout.width.saturating_sub(18);
        let label = match &scope.scope {
            crate::analysis::ProcessScopeKind::Host => "host".to_owned(),
            crate::analysis::ProcessScopeKind::Cgroup { path } => {
                let path_width = label_width.saturating_sub("cgroup ".len());
                format!(
                    "cgroup {}",
                    render::terminal_scope_identifier(path, path_width)
                )
            }
        };
        out.push_str(&format!(" Process roles ({label})\n"));
        for role in [
            ProcessRole::CpuVictim,
            ProcessRole::CpuSuspect,
            ProcessRole::MemoryVictim,
            ProcessRole::MemorySuspect,
            ProcessRole::IoVictim,
            ProcessRole::IoSuspect,
        ] {
            let name = match role {
                ProcessRole::CpuVictim => "CPU victims",
                ProcessRole::CpuSuspect => "CPU suspects",
                ProcessRole::MemoryVictim => "Memory victims",
                ProcessRole::MemorySuspect => "Memory suspects",
                ProcessRole::IoVictim => "I/O victims",
                ProcessRole::IoSuspect => "I/O suspects",
            };
            let value = match scope.roles.iter().find(|list| list.role == role) {
                Some(list) if !list.candidates.is_empty() => format!(
                    "{} · {}",
                    list.candidates.len(),
                    render::terminal_name(&list.candidates[0].name)
                ),
                Some(list) => match (list.availability, list.completeness) {
                    (_, ProcessRoleCompleteness::Unavailable)
                    | (ProcessCandidateAvailability::UnavailableOrIncomplete, _) => {
                        "unavailable/incomplete".to_owned()
                    }
                    (ProcessCandidateAvailability::NotAssessed, _) => "not assessed".to_owned(),
                    (_, ProcessRoleCompleteness::Partial) => "none (partial)".to_owned(),
                    _ => "none".to_owned(),
                },
                None => "unavailable".to_owned(),
            };
            out.push_str(&format!("   {name:<15} {value}\n"));
        }
    }
    out
}

fn header_line(options: &HuntOptions, analyses: &HuntAnalyses, layout: ReportLayout) -> String {
    let observed = render::human_duration(options.duration_ms);
    let mut best: Option<(u8, u8, String, SeverityTone, &'static str)> = None;
    let mut consider =
        |rank: (u8, u8), summary: String, tone: SeverityTone, confidence: &'static str| {
            if best.as_ref().is_none_or(|(s, c, ..)| rank > (*s, *c)) {
                best = Some((rank.0, rank.1, summary, tone, confidence));
            }
        };

    if let Some(finding) = analyses.cpu.findings.first() {
        consider(
            render::text_finding_rank(finding.severity, finding.resource_confidence),
            cpu_verdict_phrase(finding.kind).to_owned(),
            style::severity_tone(finding.severity),
            style::confidence_name(finding.resource_confidence),
        );
    }
    if let Some(memory) = &analyses.memory {
        if let Some(finding) = memory.findings.first() {
            consider(
                render::text_finding_rank(finding.severity, finding.resource_confidence),
                finding.summary.clone(),
                style::severity_tone(finding.severity),
                style::confidence_name(finding.resource_confidence),
            );
        }
    }
    if let Some(io) = &analyses.io {
        if let Some(finding) = io.findings.first() {
            consider(
                render::text_finding_rank(finding.severity, finding.resource_confidence),
                finding.summary.clone(),
                style::severity_tone(finding.severity),
                style::confidence_name(finding.resource_confidence),
            );
        }
    }
    if let Some(cgroup) = &analyses.cgroup {
        for finding in cgroup
            .findings
            .iter()
            .filter(|finding| finding.kind == CgroupAssessmentKind::Pressure)
        {
            let severity = style::severity_name(finding.severity);
            let confidence = style::confidence_name(finding.resource_confidence);
            let summary_width = header_summary_width(layout.width, &observed, severity, confidence);
            let separator_width = " · ".width();
            let content_width = summary_width.saturating_sub(separator_width);
            let path_width = content_width / 2;
            let finding_width = content_width.saturating_sub(path_width);
            let path = render::terminal_scope_identifier(&finding.path, path_width);
            let finding_summary =
                render::terminal_scope_identifier(&finding.summary, finding_width);
            let summary = match (path.is_empty(), finding_summary.is_empty()) {
                (false, false) => format!("{path} · {finding_summary}"),
                (false, true) => path,
                (true, false) => finding_summary,
                (true, true) => String::new(),
            };
            consider(
                render::text_finding_rank(finding.severity, finding.resource_confidence),
                summary,
                style::severity_tone(finding.severity),
                confidence,
            );
        }
    }

    match best {
        Some((severity_rank, _, summary, tone, confidence)) if severity_rank > 0 => {
            let severity_word = style::severity_name(severity_from_rank(severity_rank));
            let painted = style::paint(severity_word, tone, layout.color);
            let summary = render::terminal_scope_identifier(
                &summary,
                header_summary_width(layout.width, &observed, severity_word, confidence),
            );
            if header_uses_compact_suffix(layout.width, &observed, severity_word, confidence) {
                format!(
                    "STALLHUNT · observed {observed} · verdict: {summary} [{painted}/{confidence}]"
                )
            } else {
                format!(
                    "STALLHUNT · observed {observed} · verdict: {summary} [{painted}] · confidence {confidence}"
                )
            }
        }
        _ => {
            format!("STALLHUNT · observed {observed} · verdict: no significant contention observed")
        }
    }
}

fn header_summary_width(width: usize, observed: &str, severity: &str, confidence: &str) -> usize {
    let prefix = format!("STALLHUNT · observed {observed} · verdict: ");
    let suffix = if header_uses_compact_suffix(width, observed, severity, confidence) {
        format!(" [{severity}/{confidence}]")
    } else {
        format!(" [{severity}] · confidence {confidence}")
    };
    width.saturating_sub(prefix.width() + suffix.width())
}

fn header_uses_compact_suffix(
    width: usize,
    observed: &str,
    severity: &str,
    confidence: &str,
) -> bool {
    let prefix = format!("STALLHUNT · observed {observed} · verdict: ");
    let suffix = format!(" [{severity}] · confidence {confidence}");
    prefix.width() + suffix.width() >= width
}

fn severity_from_rank(rank: u8) -> crate::analysis::Severity {
    use crate::analysis::Severity;
    match rank {
        0 => Severity::None,
        1 => Severity::Low,
        2 => Severity::Moderate,
        3 => Severity::High,
        _ => Severity::Severe,
    }
}

fn cpu_verdict_phrase(kind: AssessmentKind) -> &'static str {
    match kind {
        AssessmentKind::CpuContention => "CPU scheduling contention observed",
        AssessmentKind::CpuNoMeaningfulContention => "no meaningful CPU scheduling contention",
        AssessmentKind::InsufficientObservation => {
            "CPU assessment inconclusive (short observation)"
        }
    }
}

fn cpu_row(observation: &HuntObservation, analyses: &HuntAnalyses, layout: ReportLayout) -> String {
    match (&observation.psi, &observation.cpu) {
        (Err(error), _) => format!(
            " CPU     unavailable — CPU PSI {} ({})\n",
            error.capability().as_str(),
            error.explanation()
        ),
        (Ok(_), _) => {
            let finding = analyses.cpu.findings.first();
            let Some(finding) = finding else {
                return " CPU     unavailable\n".to_owned();
            };
            let mut row = resource_row(
                "CPU",
                finding.severity,
                finding.evidence.psi_some_fraction,
                cpu_row_phrase(finding.kind),
                layout,
            );
            if finding.kind == AssessmentKind::CpuContention {
                row.push_str(&candidate_block(
                    "victims (observed runnable delay; not confirmed harm)",
                    finding.victims.iter().map(|victim| {
                        format!(
                            "{} [{}]   {} delay          {}",
                            render::terminal_name(&victim.name),
                            victim.key.pid,
                            render::human_duration_from_duration(std::time::Duration::from_nanos(
                                victim.runnable_wait_ns
                            )),
                            style::confidence_name(victim.confidence),
                        )
                    }),
                ));
                row.push_str(&candidate_block(
                    "suspects (same window only; not proven causal)",
                    finding.suspects.iter().map(|suspect| {
                        format!(
                            "{} [{}]   {:.1}% of one CPU     {}   {}",
                            render::terminal_name(&suspect.name),
                            suspect.key.pid,
                            suspect.cpu_fraction_of_one * 100.0,
                            style::confidence_name(suspect.confidence),
                            render::suspect_role(suspect.label),
                        )
                    }),
                ));
            }
            row
        }
    }
}

fn cpu_row_phrase(kind: AssessmentKind) -> &'static str {
    match kind {
        AssessmentKind::CpuContention => "contention observed",
        AssessmentKind::CpuNoMeaningfulContention => "no meaningful contention",
        AssessmentKind::InsufficientObservation => "insufficient observation",
    }
}

fn memory_row(memory: &crate::analysis::MemoryAnalysisResult, layout: ReportLayout) -> String {
    let Some(finding) = memory.findings.first() else {
        return " Memory  unavailable\n".to_owned();
    };
    resource_row(
        "Memory",
        finding.severity,
        finding.evidence.psi_some_fraction,
        memory_row_phrase(finding.kind),
        layout,
    )
}

fn memory_row_phrase(kind: crate::analysis::MemoryAssessmentKind) -> &'static str {
    use crate::analysis::MemoryAssessmentKind;
    match kind {
        MemoryAssessmentKind::NoHarmfulPressure => "no harmful pressure",
        MemoryAssessmentKind::Pressure => "active pressure",
        MemoryAssessmentKind::ReclaimPressure => "reclaim pressure",
        MemoryAssessmentKind::SwapPressure => "swap pressure",
        MemoryAssessmentKind::PossibleThrashing => "possible thrashing",
        MemoryAssessmentKind::InsufficientObservation => "insufficient observation",
    }
}

fn io_row(io: &crate::analysis::IoAnalysisResult, layout: ReportLayout) -> String {
    let Some(finding) = io.findings.first() else {
        return " I/O     unavailable\n".to_owned();
    };
    let mut row = resource_row(
        "I/O",
        finding.severity,
        finding.evidence.psi_some_fraction,
        io_row_phrase(finding.kind),
        layout,
    );
    if finding.kind == IoAssessmentKind::Pressure {
        row.push_str(&candidate_block(
            "device activity (same window only; not mapped to workloads)",
            finding.device_candidates.iter().map(|candidate| {
                format!(
                    "{} ({}:{})   {}",
                    render::terminal_name(&candidate.name),
                    candidate.key.major,
                    candidate.key.minor,
                    style::confidence_name(candidate.confidence),
                )
            }),
        ));
        row.push_str(&candidate_block(
            "process suspects (same window only; not proven causal)",
            finding.process_suspects.iter().map(|candidate| {
                format!(
                    "{} [{}]   {}",
                    render::terminal_name(&candidate.name),
                    candidate.key.pid,
                    style::confidence_name(candidate.confidence),
                )
            }),
        ));
    }
    row
}

fn io_row_phrase(kind: IoAssessmentKind) -> &'static str {
    match kind {
        IoAssessmentKind::NoMeaningfulContention => "no meaningful pressure",
        IoAssessmentKind::Pressure => "block-I/O pressure",
        IoAssessmentKind::InsufficientObservation => "insufficient observation",
    }
}

fn cgroup_rows(cgroup: &crate::analysis::CgroupAnalysisResult, layout: ReportLayout) -> String {
    let pressured: Vec<_> = cgroup
        .findings
        .iter()
        .filter(|finding| finding.kind == CgroupAssessmentKind::Pressure)
        .collect();
    if pressured.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    for finding in pressured.iter().take(CGROUP_ROW_CAP) {
        let resource = match finding.resource {
            crate::analysis::CgroupResourceKind::Cpu => "cpu",
            crate::analysis::CgroupResourceKind::Memory => "memory",
            crate::analysis::CgroupResourceKind::Io => "io",
        };
        out.push_str(&resource_row("Cgroup", finding.severity, 0.0, "", layout));
        // resource_row always writes a PSI number; overwrite the tail with
        // the cgroup-specific path/resource summary instead.
        out.truncate(out.trim_end_matches('\n').len());
        if let Some(stripped) = out.rfind("PSI some") {
            out.truncate(stripped);
        }
        out.push_str(&format!(
            "{} ({resource}) · scoped pressure\n",
            render::terminal_scope_identifier(&finding.path, layout.width.saturating_sub(30))
        ));
    }
    if pressured.len() > CGROUP_ROW_CAP {
        out.push_str(&format!(
            "          (+{} more scoped finding(s))\n",
            pressured.len() - CGROUP_ROW_CAP
        ));
    }
    out
}

/// One resource summary row: ` <label>  [<severity>]  PSI some X.XX%  <phrase>`.
fn resource_row(
    label: &str,
    severity: crate::analysis::Severity,
    psi_some_fraction: f64,
    phrase: &str,
    layout: ReportLayout,
) -> String {
    let severity_word = style::severity_name(severity);
    let painted = style::paint(severity_word, style::severity_tone(severity), layout.color);
    format!(
        " {:<7} [{painted}]{:pad$}PSI some {:.2}%   {phrase}\n",
        label,
        "",
        psi_some_fraction * 100.0,
        pad = (5_usize.saturating_sub(severity_word.len())).max(1),
    )
}

fn candidate_block<I: Iterator<Item = String>>(heading: &str, items: I) -> String {
    let items: Vec<String> = items.take(3).collect();
    if items.is_empty() {
        return String::new();
    }
    let mut out = format!("   {heading}\n");
    for (index, item) in items.iter().enumerate() {
        out.push_str(&format!("     {}. {item}\n", index + 1));
    }
    out
}

fn related_evidence_line(chains: &[crate::analysis::EvidenceChain]) -> String {
    let Some(top) = chains.first() else {
        return String::new();
    };
    let mut line = format!(
        " Related evidence: {} · confidence {}\n",
        top.summary,
        style::confidence_name(top.confidence)
    );
    if chains.len() > 1 {
        line.push_str(&format!(
            " (+{} more related finding(s))\n",
            chains.len() - 1
        ));
    }
    line
}

fn collect_qualifiers<'a>(
    analyses: &'a HuntAnalyses,
    chains: &'a [crate::analysis::EvidenceChain],
) -> Vec<&'a Qualifier> {
    let mut qualifiers = Vec::new();
    if let Some(finding) = analyses.cpu.findings.first() {
        qualifiers.extend(finding.qualifiers.iter());
    }
    if let Some(memory) = &analyses.memory {
        if let Some(finding) = memory.findings.first() {
            qualifiers.extend(finding.qualifiers.iter());
        }
    }
    if let Some(io) = &analyses.io {
        if let Some(finding) = io.findings.first() {
            qualifiers.extend(finding.qualifiers.iter());
        }
    }
    if let Some(cgroup) = &analyses.cgroup {
        for finding in cgroup
            .findings
            .iter()
            .filter(|finding| finding.kind == CgroupAssessmentKind::Pressure)
            .take(CGROUP_ROW_CAP)
        {
            qualifiers.extend(finding.qualifiers.iter());
        }
    }
    for chain in chains {
        qualifiers.extend(chain.qualifiers.iter());
    }
    qualifiers
}

/// The bounded tag vocabulary (at most 7 category names) keeps this line
/// short regardless of `width`, so it is built directly rather than
/// width-truncated: truncating a line that ends in the `--verbose` hint
/// risked cutting the hint itself off.
fn context_line(qualifiers: &[&Qualifier]) -> String {
    if qualifiers.is_empty() {
        return String::new();
    }
    let mut tags: Vec<&'static str> = qualifiers.iter().map(|q| qualifier_tag(q.kind)).collect();
    tags.sort_unstable();
    tags.dedup();
    let shown: Vec<&str> = tags.iter().take(MAX_TAGS_SHOWN).copied().collect();
    let more = tags.len().saturating_sub(MAX_TAGS_SHOWN);
    let suffix = if more > 0 {
        format!(", +{more} more")
    } else {
        String::new()
    };
    format!(
        " Context: {} caveat{} ({}{}) — use --verbose for full text\n",
        qualifiers.len(),
        if qualifiers.len() == 1 { "" } else { "s" },
        shown.join(", "),
        suffix,
    )
}

fn verbose_context_blocks(
    analyses: &HuntAnalyses,
    chains: &[crate::analysis::EvidenceChain],
) -> String {
    let mut out = String::new();
    let mut section = |title: &str, qualifiers: &[Qualifier]| {
        if qualifiers.is_empty() {
            return;
        }
        out.push_str(&format!(" {title} context and limitations:\n"));
        for qualifier in qualifiers {
            out.push_str(&format!("   {}\n", qualifier.message));
        }
    };
    if let Some(finding) = analyses.cpu.findings.first() {
        section("CPU", &finding.qualifiers);
    }
    if let Some(memory) = &analyses.memory {
        if let Some(finding) = memory.findings.first() {
            section("Memory", &finding.qualifiers);
        }
    }
    if let Some(io) = &analyses.io {
        if let Some(finding) = io.findings.first() {
            section("I/O", &finding.qualifiers);
        }
    }
    if let Some(cgroup) = &analyses.cgroup {
        for finding in cgroup
            .findings
            .iter()
            .filter(|finding| finding.kind == CgroupAssessmentKind::Pressure)
            .take(CGROUP_ROW_CAP)
        {
            section("Cgroup", &finding.qualifiers);
        }
    }
    for chain in chains {
        section("Related evidence", &chain.qualifiers);
    }
    out
}

fn timing_line(options: &HuntOptions, observation: &HuntObservation) -> String {
    let psi_elapsed = observation
        .psi
        .as_ref()
        .ok()
        .map(|psi| psi.interval.elapsed);
    let cpu_elapsed = observation.cpu.as_ref().ok().map(|cpu| cpu.elapsed);
    let mut line = format!(
        " Timing: requested {}",
        render::human_duration(options.duration_ms)
    );
    if let Some(elapsed) = psi_elapsed {
        line.push_str(&format!(
            " · PSI {}",
            render::human_duration_from_duration(elapsed)
        ));
    }
    if let Some(elapsed) = cpu_elapsed {
        line.push_str(&format!(
            " · CPU/process {}",
            render::human_duration_from_duration(elapsed)
        ));
    }
    line.push('\n');
    line
}

/// Bucket a stable `Qualifier.kind` machine key into one of a small set of
/// human-facing caveat categories. Every kind string that currently exists
/// in `src/analysis.rs` is covered explicitly below (verified against a
/// grep of the real source, not an assumed list); `"other"` exists only as
/// a forward-compatible fallback for kinds added later. `report::tests`
/// re-derives the real kind set at test time and asserts none of them fall
/// through to `"other"`, so drift is caught.
fn qualifier_tag(kind: &str) -> &'static str {
    match kind {
        // same-window correlation presented as evidence, never causal proof
        "cgroup_context_not_causality"
        | "cgroup_cpu_quota_throttle_same_window_correlation"
        | "cgroup_memory_mechanism_same_window_correlation"
        | "chain_not_causal"
        | "device_activity_same_window_correlation"
        | "memory_mechanism_same_window_correlation"
        | "process_io_same_window_correlation"
        | "same_window_correlation" => "causality",

        // who is affected / responsible could not be established
        "attribution_unavailable"
        | "no_affected_workload_attribution"
        | "non_unique_attribution"
        | "no_process_attribution"
        | "no_process_device_mapping"
        | "suspect_attribution_limited"
        | "victim_attribution_limited"
        | "systemd_unit_candidate" => "attribution",

        // limited to one cgroup scope, or scope identity is uncertain
        "cgroup_hierarchy_overlaps"
        | "cgroup_membership_changed"
        | "cgroup_memory_mechanism_scoped"
        | "cgroup_path_lifetime_uncertain"
        | "cgroup_scoped_evidence"
        | "same_cgroup_scope_only" => "scope",

        // telemetry was partial, unavailable, or failed to collect
        "cgroup_collection_partial"
        | "cgroup_full_partial"
        | "cgroup_psi_unavailable_or_invalid"
        | "cpu_assessment_unavailable"
        | "cpu_context_unavailable"
        | "diskstats_partial"
        | "diskstats_unavailable"
        | "io_assessment_unavailable"
        | "io_full_nonadditive_subset"
        | "io_full_unavailable"
        | "layered_device_visibility"
        | "memory_assessment_unavailable"
        | "memory_context_partial"
        | "memory_context_unavailable"
        | "memory_full_unavailable"
        | "page_cache_writeback_visibility"
        | "process_io_partial"
        | "process_io_unavailable"
        | "vmstat_partial" => "collection",

        // a named heuristic, not a direct measurement
        "cgroup_possible_thrashing_heuristic" | "possible_thrashing_heuristic" => "heuristic",

        // the observation window was too short or otherwise invalid
        "cgroup_some_exceeds_window"
        | "insufficient_observation"
        | "io_full_interval_invalid"
        | "memory_full_interval_invalid" => "window",

        // supporting context alongside (not itself) the verdict
        "cpu_no_meaningful_contention"
        | "high_occupancy_context"
        | "high_utilization_context"
        | "io_no_meaningful_contention"
        | "kswapd_reclaim_context"
        | "memory_no_harmful_pressure"
        | "runnable_queue_context"
        | "scheduler_delay_context"
        | "swap_allocated_context"
        | "swap_out_context" => "context",

        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::OutputFormat;
    use crate::style::ColorMode;

    fn layout(color: ColorMode, verbose: bool) -> ReportLayout {
        ReportLayout {
            width: 80,
            color,
            verbose,
        }
    }

    fn hunt_options() -> HuntOptions {
        HuntOptions {
            duration_ms: 10_000,
            output: OutputFormat::Text,
            verbose: false,
            no_color: false,
        }
    }

    fn cpu_only_observation() -> HuntObservation {
        // Mirrors the fixed CPU-only observation used by
        // `tests/fixtures/render/cpu-contention.txt` in render.rs, kept
        // independent here since the render.rs test helper builds it as a
        // local (not extracted) value.
        use crate::cpu::*;
        use crate::psi::*;
        use std::time::Duration;
        let psi = CpuPsiObservation {
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
            processes: vec![ProcessCpuInterval {
                key: ProcessKey {
                    pid: 20,
                    start_time_ticks: 1,
                },
                name: "build".into(),
                state: 'R',
                cpu_ticks: 80,
                cpu_fraction_of_one: 0.8,
            }],
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
            psi: Ok(psi),
            cpu: Ok(cpu),
            memory: None,
            io: None,
            cgroup: None,
        }
    }

    fn render(observation: HuntObservation, layout: ReportLayout) -> String {
        let analyses = render::analyze_hunt(&observation);
        hunt_report(&hunt_options(), &analyses, &observation, layout)
    }

    #[test]
    fn compact_plain_matches_fixture() {
        let output = render(cpu_only_observation(), layout(ColorMode::Never, false));
        assert_eq!(
            output,
            include_str!("../tests/fixtures/render/hunt-compact-plain.txt")
        );
        assert!(!output.contains('\u{1b}'));
    }

    #[test]
    fn compact_color_matches_escaped_fixture() {
        let output = render(cpu_only_observation(), layout(ColorMode::Always, false));
        let escaped = output.replace('\u{1b}', "<ESC>");
        assert_eq!(
            escaped,
            include_str!("../tests/fixtures/render/hunt-compact-color.txt")
        );
        assert!(output.contains('\u{1b}'));
    }

    #[test]
    fn compact_verbose_matches_fixture() {
        let output = render(cpu_only_observation(), layout(ColorMode::Never, true));
        assert_eq!(
            output,
            include_str!("../tests/fixtures/render/hunt-compact-verbose.txt")
        );
    }

    #[test]
    fn compact_full_matches_fixture_and_is_shorter_than_legacy() {
        let observation = render::tests::hunt_legacy_full_fixture_observation();
        let output = render(observation, layout(ColorMode::Never, false));
        assert_eq!(
            output,
            include_str!("../tests/fixtures/render/hunt-compact-full.txt")
        );
        let legacy = include_str!("../tests/fixtures/render/hunt-legacy-full.txt");
        assert!(
            output.len() < legacy.len(),
            "compact report ({} bytes) should be shorter than legacy ({} bytes)",
            output.len(),
            legacy.len()
        );
    }

    #[test]
    fn compact_cgroup_verdict_sanitizes_and_budgets_the_entire_header() {
        let observation = render::tests::hunt_legacy_full_fixture_observation();
        let mut analyses = render::analyze_hunt(&observation);
        let finding = analyses
            .cgroup
            .as_mut()
            .and_then(|analysis| analysis.findings.first_mut())
            .expect("fixture has a cgroup finding");
        finding.path = "\u{1b}界/a-very-long-cgroup-path-that-must-not-overflow".into();
        finding.severity = crate::analysis::Severity::Severe;
        finding.resource_confidence = crate::analysis::Confidence::High;

        for width in [60, 80] {
            let line = header_line(
                &hunt_options(),
                &analyses,
                ReportLayout {
                    width,
                    color: ColorMode::Never,
                    verbose: false,
                },
            );
            assert!(!line.contains('\u{1b}'), "{line:?}");
            assert!(line.contains('�'), "{width}: {line}");
            assert!(
                line.width() <= width,
                "{width}: {} cells: {line}",
                line.width()
            );
        }
    }

    #[test]
    fn every_real_qualifier_kind_maps_to_a_known_tag() {
        // Re-derive the qualifier kind set straight from analysis.rs's
        // source at test time, mirroring the extraction used to design the
        // bucket list above, so this test fails if a new kind is added
        // without updating `qualifier_tag`.
        let source =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/analysis.rs"))
                .expect("read analysis.rs");
        let mut kinds = Vec::new();
        for line in source.lines() {
            let Some(start) = line.find("kind:") else {
                continue;
            };
            let rest = line[start + "kind:".len()..].trim_start();
            let Some(rest) = rest.strip_prefix('"') else {
                continue;
            };
            if let Some(end) = rest.find('"') {
                kinds.push(rest[..end].to_owned());
            }
        }
        assert!(!kinds.is_empty(), "expected to find qualifier kind strings");
        let mut fell_to_other = Vec::new();
        for kind in &kinds {
            if qualifier_tag(kind) == "other" {
                fell_to_other.push(kind.clone());
            }
        }
        assert!(
            fell_to_other.is_empty(),
            "qualifier kinds with no explicit bucket: {fell_to_other:?}"
        );
    }

    #[test]
    fn qualifier_tag_is_a_pure_lookup() {
        assert_eq!(qualifier_tag("chain_not_causal"), "causality");
        assert_eq!(qualifier_tag("insufficient_observation"), "window");
        assert_eq!(qualifier_tag("possible_thrashing_heuristic"), "heuristic");
        assert_eq!(qualifier_tag("totally_unknown_kind"), "other");
    }
}
