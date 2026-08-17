use std::time::Duration;

use serde::Serialize;

use crate::analysis::{self, AnalysisResult, AssessmentKind};
use crate::cli::{CapabilitiesOptions, HelpTopic, HuntOptions, OutputFormat};
use crate::cpu::{CpuProcessObservation, CpuTelemetryCapabilities, HuntObservation};
use crate::psi::{CpuPsiCapability, CpuPsiObservation};

const ROOT_HELP: &str = "Linux performance triage that reports evidence-backed bottlenecks.\n\nUSAGE:\n    bottleneck <COMMAND>\n\nCOMMANDS:\n    hunt          Run a bounded diagnosis\n    capabilities  Report available telemetry\n    version       Print version information\n    help          Print this help or help for a command\n\nOPTIONS:\n    -h, --help     Print help\n    -V, --version  Print version information\n";

const HUNT_HELP: &str = "Run a bounded bottleneck diagnosis.\n\nUSAGE:\n    bottleneck hunt [OPTIONS]\n\nOPTIONS:\n    --duration <DURATION>  Observation duration from 100ms to 5m [default: 10s]\n    --json                 Emit machine-readable JSON\n    -h, --help             Print help\n\nDURATION EXAMPLES:\n    500ms  2s  1.5s  1m\n";

const CAPABILITIES_HELP: &str = "Report telemetry availability and permission limitations.\n\nUSAGE:\n    bottleneck capabilities [OPTIONS]\n\nOPTIONS:\n    --json      Emit machine-readable JSON\n    -h, --help  Print help\n";

pub fn help(topic: HelpTopic) -> &'static str {
    match topic {
        HelpTopic::Root => ROOT_HELP,
        HelpTopic::Hunt => HUNT_HELP,
        HelpTopic::Capabilities => CAPABILITIES_HELP,
    }
}

pub fn version() -> String {
    format!("bottleneck {}\n", env!("CARGO_PKG_VERSION"))
}

pub fn hunt<F>(options: &HuntOptions, observe: F) -> String
where
    F: FnOnce(Duration) -> HuntObservation,
{
    let result = observe(Duration::from_millis(options.duration_ms));
    match options.output {
        OutputFormat::Text => hunt_text(options, result),
        OutputFormat::Json => hunt_json(options, result),
    }
}

pub fn capabilities(
    options: &CapabilitiesOptions,
    cpu_psi: CpuPsiCapability,
    cpu: CpuTelemetryCapabilities,
) -> String {
    match options.output {
        OutputFormat::Text => format!(
            "Telemetry capabilities\n\nCPU PSI: {}\n{}\nHost /proc/stat: {}\nProcess /proc/<pid>/stat: {}\nTask /proc/<tgid>/task/<tid>/schedstat: {}\n{}\n",
            cpu_psi.as_str(),
            cpu_psi.explanation(),
            cpu.host_cpu.as_str(),
            cpu.process_stat.as_str(),
            cpu.process_schedstat.as_str(),
            cpu.process_schedstat.explanation(),
        ),
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
            },
        }),
    }
}

fn hunt_text(options: &HuntOptions, result: HuntObservation) -> String {
    match (result.psi, result.cpu) {
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

fn hunt_json(options: &HuntOptions, result: HuntObservation) -> String {
    let requested_observation = RequestedObservation {
        duration_ms: options.duration_ms,
    };
    match (result.psi, result.cpu) {
        (Ok(observation), Ok(cpu)) => {
            let process_stat = crate::cpu::process_capability(&cpu.collection_issues).as_str();
            let process_schedstat = cpu.schedstat_capability;
            let findings = analysis::analyze_cpu(Some(&observation), Some(&cpu)).findings;
            to_json(&HuntJson {
                schema_version: 1,
                tool_version: env!("CARGO_PKG_VERSION"),
                status: "observed",
                requested_observation,
                observation: Some(ObservationJson::from_parts(Some(observation), Some(cpu))),
                capabilities: CapabilitiesJsonValue {
                    cpu_psi: CapabilityJson {
                        state: "available",
                        message: CpuPsiCapability::Available.explanation(),
                    },
                    host_cpu: "available",
                    process_stat,
                    process_schedstat: CapabilityJson {
                        state: process_schedstat.as_str(),
                        message: process_schedstat.explanation(),
                    },
                },
                findings,
                qualifiers: Vec::new(),
            })
        }
        (Err(error), Ok(cpu)) => {
            let process_stat = crate::cpu::process_capability(&cpu.collection_issues).as_str();
            let process_schedstat = cpu.schedstat_capability;
            to_json(&HuntJson {
                schema_version: 1,
                tool_version: env!("CARGO_PKG_VERSION"),
                status: "incomplete",
                requested_observation,
                observation: Some(ObservationJson::from_parts(None, Some(cpu))),
                capabilities: CapabilitiesJsonValue {
                    cpu_psi: CapabilityJson {
                        state: error.capability().as_str(),
                        message: error.explanation(),
                    },
                    host_cpu: "available",
                    process_stat,
                    process_schedstat: CapabilityJson {
                        state: process_schedstat.as_str(),
                        message: process_schedstat.explanation(),
                    },
                },
                findings: Vec::new(),
                qualifiers: vec![QualifierJson {
                    kind: "capability_limit",
                    message: "CPU PSI was unavailable; host and process CPU evidence is retained without a diagnosis.",
                }],
            })
        }
        (Ok(psi), Err(error)) => to_json(&HuntJson {
            schema_version: 1,
            tool_version: env!("CARGO_PKG_VERSION"),
            status: "incomplete",
            requested_observation,
            observation: Some(ObservationJson::from_parts(Some(psi), None)),
            capabilities: CapabilitiesJsonValue {
                cpu_psi: CapabilityJson {
                    state: "available",
                    message: CpuPsiCapability::Available.explanation(),
                },
                host_cpu: "failed",
                process_stat: "failed",
                process_schedstat: CapabilityJson {
                    state: "failed",
                    message: "CPU process telemetry was unavailable.",
                },
            },
            findings: analysis::analyze_cpu(Some(&psi), None).findings,
            qualifiers: vec![QualifierJson {
                kind: "collection_limit",
                message: error.explanation(),
            }],
        }),
        (Err(error), Err(cpu_error)) => to_json(&HuntJson {
            schema_version: 1,
            tool_version: env!("CARGO_PKG_VERSION"),
            status: "incomplete",
            requested_observation,
            observation: None,
            capabilities: CapabilitiesJsonValue {
                cpu_psi: CapabilityJson {
                    state: error.capability().as_str(),
                    message: error.explanation(),
                },
                host_cpu: "failed",
                process_stat: "failed",
                process_schedstat: CapabilityJson {
                    state: "failed",
                    message: "CPU process telemetry was unavailable.",
                },
            },
            findings: Vec::new(),
            qualifiers: vec![QualifierJson {
                kind: "capability_limit",
                message: cpu_error.explanation(),
            }],
        }),
    }
}

fn to_json<T: Serialize>(value: &T) -> String {
    match serde_json::to_string_pretty(value) {
        Ok(json) => format!("{json}\n"),
        Err(_) => "{\"status\":\"serialization_failed\"}\n".to_owned(),
    }
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
    findings: Vec<crate::analysis::CpuFinding>,
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
}

impl ObservationJson {
    fn from_parts(psi: Option<CpuPsiObservation>, cpu: Option<CpuProcessObservation>) -> Self {
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
struct CapabilitiesJsonValue<'a> {
    cpu_psi: CapabilityJson<'a>,
    host_cpu: &'a str,
    process_stat: &'a str,
    process_schedstat: CapabilityJson<'a>,
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
    if milliseconds.is_multiple_of(60_000) {
        format!("{}m", milliseconds / 60_000)
    } else if milliseconds.is_multiple_of(1_000) {
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
    use crate::cpu::{
        CpuProcessObservation, HostCpuInterval, LoadAverageAvailability, LoadAverageRaw,
        ProcessCollectionIssues, ProcessCpuInterval, ProcessKey, ProcessSchedulerDelayInterval,
    };
    use crate::psi::{CpuPsiInterval, CpuPsiRaw};

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
        }
    }

    #[test]
    fn hunt_renders_interval_pressure_with_a_diagnosis() {
        let output = hunt(
            &HuntOptions {
                duration_ms: 1_000,
                output: OutputFormat::Text,
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
        let json: serde_json::Value = serde_json::from_str(&hunt(
            &HuntOptions {
                duration_ms: 1_000,
                output: OutputFormat::Json,
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
        let partial: serde_json::Value = serde_json::from_str(&hunt(
            &HuntOptions {
                duration_ms: 1_000,
                output: OutputFormat::Json,
            },
            |_| HuntObservation {
                psi: Ok(observation()),
                cpu: Err(crate::cpu::CpuError::Unreadable),
            },
        ))
        .unwrap();
        assert_eq!(partial["status"], "incomplete");
        assert_eq!(partial["findings"][0]["kind"], "cpu_scheduling_contention");
        assert!(partial["findings"][0]["evidence"]["host_utilization_fraction"].is_null());
        assert!(partial["qualifiers"][0]["kind"].is_string());

        let partial_text = hunt(
            &HuntOptions {
                duration_ms: 1_000,
                output: OutputFormat::Text,
            },
            |_| HuntObservation {
                psi: Ok(observation()),
                cpu: Err(crate::cpu::CpuError::Unreadable),
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
        let output = hunt(
            &HuntOptions {
                duration_ms: 1_000,
                output: OutputFormat::Json,
            },
            |_| hunt_observation(),
        );
        let json: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(json["status"], "observed");
        assert_eq!(json["observation"]["cpu_psi"]["total_delta_us"], 250_000);
        assert!(json["findings"].is_array());
    }

    #[test]
    fn hunt_reports_unavailable_cpu_psi_explicitly() {
        let output = hunt(
            &HuntOptions {
                duration_ms: 1_000,
                output: OutputFormat::Text,
            },
            |_| HuntObservation {
                psi: Err(crate::psi::CpuPsiError::Malformed),
                cpu: Err(crate::cpu::CpuError::Malformed),
            },
        );
        assert!(output.contains("Capability: CPU PSI failed"));
        assert!(output.contains("did not match the expected kernel format"));
    }

    #[test]
    fn psi_failure_retains_scheduler_delay_text_context() {
        let output = hunt(
            &HuntOptions {
                duration_ms: 1_000,
                output: OutputFormat::Text,
            },
            |_| HuntObservation {
                psi: Err(crate::psi::CpuPsiError::Malformed),
                cpu: hunt_observation().cpu,
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
        let complete_text = hunt(
            &HuntOptions {
                duration_ms: 1_000,
                output: OutputFormat::Text,
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
        let retained_partial_text = hunt(
            &HuntOptions {
                duration_ms: 1_000,
                output: OutputFormat::Text,
            },
            |_| retained_partial,
        );
        assert!(retained_partial_text.contains("consumer [9]"));
        assert!(retained_partial_text.contains("Process collection is partial"));

        let mut empty_partial = hunt_observation();
        let cpu = empty_partial.cpu.as_mut().unwrap();
        cpu.processes.clear();
        cpu.collection_issues.appeared = 1;
        let empty_partial_text = hunt(
            &HuntOptions {
                duration_ms: 1_000,
                output: OutputFormat::Text,
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
        let retained_scheduler_text = hunt(
            &HuntOptions {
                duration_ms: 1_000,
                output: OutputFormat::Text,
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
        let no_contention_text = hunt(
            &HuntOptions {
                duration_ms: 1_000,
                output: OutputFormat::Text,
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
        let short_text = hunt(
            &HuntOptions {
                duration_ms: 100,
                output: OutputFormat::Text,
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
        let output = hunt(
            &HuntOptions {
                duration_ms: 10_000,
                output: OutputFormat::Text,
            },
            |_| HuntObservation {
                psi: Ok(observation),
                cpu: Ok(cpu),
            },
        );
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
            let output = capabilities(
                &CapabilitiesOptions {
                    output: OutputFormat::Text,
                },
                capability,
                CpuTelemetryCapabilities {
                    host_cpu: crate::cpu::CollectorCapability::Available,
                    process_stat: crate::cpu::CollectorCapability::Available,
                    process_schedstat: crate::cpu::SchedstatCapability::Unsupported,
                },
            );
            assert!(output.contains(&format!("CPU PSI: {}", capability.as_str())));
            assert!(output.contains(capability.explanation()));
        }
    }
}
