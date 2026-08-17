use std::time::Duration;

use serde::Serialize;

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
            "Telemetry capabilities\n\nCPU PSI: {}\n{}\nHost /proc/stat: {}\nProcess /proc/<pid>/stat: {}\n",
            cpu_psi.as_str(),
            cpu_psi.explanation(),
            cpu.host_cpu.as_str(),
            cpu.process_stat.as_str()
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
            },
        }),
    }
}

fn hunt_text(options: &HuntOptions, result: HuntObservation) -> String {
    match (result.psi, result.cpu) {
        (Ok(observation), Ok(cpu)) => {
            let process_lines = cpu
                .processes
                .iter()
                .take(10)
                .map(|process| {
                    format!(
                        "  {} [{}]  {} ticks ({:.1}% of one CPU)",
                        process.name,
                        process.key.pid,
                        process.cpu_ticks,
                        process.cpu_fraction_of_one * 100.0
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            let process_lines = if process_lines.is_empty() {
                "  No processes persisted across both snapshots.".to_owned()
            } else {
                process_lines
            };
            let load_line = match &cpu.load {
                Some(load) => format!(
                    "Load at end: {:.2} {:.2} {:.2}; runnable/total {}/{}",
                    load.avg1, load.avg5, load.avg15, load.runnable_tasks, load.total_tasks
                ),
                None => format!("Load at end: unavailable ({:?})", cpu.load_availability),
            };
            let process_context = process_context_line(&cpu);
            format!(
                "CPU telemetry observation complete\n\nRequested observation duration: {}\nActual observation duration: {}\nCPU PSI some during interval: {:.2}% ({} us cumulative stall time)\nCPU PSI rolling averages at end: avg10 {:.2}%, avg60 {:.2}%, avg300 {:.2}%\nHost CPU: {:.2}% busy across {} logical CPUs ({} / {} ticks)\n{}\nProcesses sampled: {}\n{}\nTop process CPU consumers during interval:\n{}\n\nThis is raw CPU and process evidence only. Process CPU consumption is concurrent context, not causal attribution; severity, victims, suspects, and scheduler-delay analysis are not implemented yet.\n",
                human_duration(options.duration_ms),
                human_duration_from_duration(observation.interval.elapsed),
                observation.interval.some_fraction * 100.0,
                observation.interval.total_delta_us,
                observation.end.avg10_percent,
                observation.end.avg60_percent,
                observation.end.avg300_percent,
                cpu.host.utilization_fraction * 100.0,
                cpu.host.cpu_count,
                cpu.host.busy_ticks,
                cpu.host.total_ticks,
                load_line,
                cpu.processes.len(),
                process_context,
                process_lines,
            )
        }
        (Err(error), Ok(cpu)) => format!(
            "CPU PSI observation unavailable\n\nCPU PSI capability: {}\n{}\nHost CPU: {:.2}% busy across {} logical CPUs ({} / {} ticks)\nProcesses sampled: {}\n{}\nCPU PSI is missing; retained host/process CPU evidence is raw context only, and no diagnosis or finding was produced.\n",
            error.capability().as_str(),
            error.explanation(),
            cpu.host.utilization_fraction * 100.0,
            cpu.host.cpu_count,
            cpu.host.busy_ticks,
            cpu.host.total_ticks,
            cpu.processes.len(),
            process_context_line(&cpu),
        ),
        (Err(error), Err(_)) => format!(
            "CPU PSI observation unavailable\n\nCPU PSI capability: {}\n{}\nNo complete CPU PSI interval was observed; no diagnosis or finding was produced.\n",
            error.capability().as_str(),
            error.explanation(),
        ),
        (Ok(psi), Err(error)) => format!(
            "CPU PSI observation complete\n\nActual observation duration: {}\nCPU PSI some during interval: {:.2}% ({} us cumulative stall time)\n\nCPU process telemetry was unavailable: {}\nCPU PSI is raw evidence only; no diagnosis or finding was produced.\n",
            human_duration_from_duration(psi.interval.elapsed),
            psi.interval.some_fraction * 100.0,
            psi.interval.total_delta_us,
            error.explanation(),
        ),
    }
}

fn process_context_line(cpu: &CpuProcessObservation) -> String {
    let issues = &cpu.collection_issues;
    format!(
        "Process context: {} (disappeared {}, permission-denied {}, unreadable {}, malformed {}, enumeration errors {}, counter regressions {}, cap {})",
        crate::cpu::process_capability(issues).as_str(),
        issues.disappeared,
        issues.permission_denied,
        issues.unreadable,
        issues.malformed,
        issues.enumeration_errors,
        issues.counter_regressed,
        if issues.limit_reached {
            "reached"
        } else {
            "not reached"
        },
    )
}

fn hunt_json(options: &HuntOptions, result: HuntObservation) -> String {
    let requested_observation = RequestedObservation {
        duration_ms: options.duration_ms,
    };
    match (result.psi, result.cpu) {
        (Ok(observation), Ok(cpu)) => {
            let process_stat = crate::cpu::process_capability(&cpu.collection_issues).as_str();
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
                },
                findings: Vec::new(),
                qualifiers: vec![QualifierJson {
                    kind: "implementation_limit",
                    message: "CPU PSI, host CPU counters, load context, and process CPU deltas are collected, but CPU contention inference and causal attribution are not implemented.",
                }],
            })
        }
        (Err(error), Ok(cpu)) => {
            let process_stat = crate::cpu::process_capability(&cpu.collection_issues).as_str();
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
            },
            findings: Vec::new(),
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
    findings: Vec<serde_json::Value>,
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
    let milliseconds = duration.as_millis();
    if milliseconds.is_multiple_of(60_000) {
        format!("{}m", milliseconds / 60_000)
    } else if milliseconds.is_multiple_of(1_000) {
        format!("{}s", milliseconds / 1_000)
    } else {
        format!("{milliseconds}ms")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::{
        CpuProcessObservation, HostCpuInterval, LoadAverageAvailability, LoadAverageRaw,
        ProcessCollectionIssues,
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
                processes: Vec::new(),
                collection_issues: ProcessCollectionIssues::default(),
            }),
        }
    }

    #[test]
    fn hunt_renders_raw_interval_pressure_without_a_diagnosis() {
        let output = hunt(
            &HuntOptions {
                duration_ms: 1_000,
                output: OutputFormat::Text,
            },
            |_| hunt_observation(),
        );
        assert!(output.contains("Actual observation duration: 1250ms"));
        assert!(output.contains("CPU PSI some during interval: 20.00%"));
        assert!(output.contains("not implemented yet"));
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
        assert_eq!(json["findings"], serde_json::json!([]));
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
        assert!(output.contains("CPU PSI capability: failed"));
        assert!(output.contains("did not match the expected kernel format"));
    }

    #[test]
    fn process_context_discloses_failed_enumeration() {
        let cpu = CpuProcessObservation {
            elapsed: Duration::from_secs(1),
            clock_ticks_per_second: 100,
            host: HostCpuInterval {
                total_ticks: 1,
                busy_ticks: 1,
                idle_ticks: 0,
                utilization_fraction: 1.0,
                cpu_count: 1,
            },
            load: None,
            load_availability: LoadAverageAvailability::Unreadable,
            processes: Vec::new(),
            collection_issues: ProcessCollectionIssues {
                enumeration_failed: true,
                ..ProcessCollectionIssues::default()
            },
        };
        assert!(process_context_line(&cpu).contains("failed"));
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
                },
            );
            assert!(output.contains(&format!("CPU PSI: {}", capability.as_str())));
            assert!(output.contains(capability.explanation()));
        }
    }
}
