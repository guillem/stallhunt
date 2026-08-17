use std::time::Duration;

use serde::Serialize;

use crate::cli::{CapabilitiesOptions, HelpTopic, HuntOptions, OutputFormat};
use crate::psi::{CpuPsiCapability, CpuPsiError, CpuPsiObservation};

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
    F: FnOnce(Duration) -> Result<CpuPsiObservation, CpuPsiError>,
{
    let result = observe(Duration::from_millis(options.duration_ms));
    match options.output {
        OutputFormat::Text => hunt_text(options, result),
        OutputFormat::Json => hunt_json(options, result),
    }
}

pub fn capabilities(options: &CapabilitiesOptions, cpu_psi: CpuPsiCapability) -> String {
    match options.output {
        OutputFormat::Text => format!(
            "Telemetry capabilities\n\nCPU PSI: {}\n{}\n",
            cpu_psi.as_str(),
            cpu_psi.explanation()
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
            },
        }),
    }
}

fn hunt_text(options: &HuntOptions, result: Result<CpuPsiObservation, CpuPsiError>) -> String {
    match result {
        Ok(observation) => format!(
            "CPU PSI observation complete\n\nRequested observation duration: {}\nActual observation duration: {}\nCPU PSI some during interval: {:.2}% ({} us cumulative stall time)\nCPU PSI rolling averages at end: avg10 {:.2}%, avg60 {:.2}%, avg300 {:.2}%\n\nThis is raw CPU pressure evidence only. CPU contention severity, process attribution, and causal claims are not implemented yet.\n",
            human_duration(options.duration_ms),
            human_duration_from_duration(observation.interval.elapsed),
            observation.interval.some_fraction * 100.0,
            observation.interval.total_delta_us,
            observation.end.avg10_percent,
            observation.end.avg60_percent,
            observation.end.avg300_percent,
        ),
        Err(error) => format!(
            "CPU PSI observation unavailable\n\nCPU PSI capability: {}\n{}\nNo complete CPU PSI interval was observed; no diagnosis or finding was produced.\n",
            error.capability().as_str(),
            error.explanation(),
        ),
    }
}

fn hunt_json(options: &HuntOptions, result: Result<CpuPsiObservation, CpuPsiError>) -> String {
    let requested_observation = RequestedObservation {
        duration_ms: options.duration_ms,
    };
    match result {
        Ok(observation) => to_json(&HuntJson {
            schema_version: 1,
            tool_version: env!("CARGO_PKG_VERSION"),
            status: "observed",
            requested_observation,
            observation: Some(ObservationJson::from(observation)),
            capabilities: CapabilitiesJsonValue {
                cpu_psi: CapabilityJson {
                    state: "available",
                    message: CpuPsiCapability::Available.explanation(),
                },
            },
            findings: Vec::new(),
            qualifiers: vec![QualifierJson {
                kind: "implementation_limit",
                message: "CPU PSI is collected, but CPU contention inference and process attribution are not implemented.",
            }],
        }),
        Err(error) => to_json(&HuntJson {
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
            },
            findings: Vec::new(),
            qualifiers: vec![QualifierJson {
                kind: "capability_limit",
                message: "No complete CPU PSI interval was observed; no diagnosis or finding was produced.",
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
    duration_us: u128,
    cpu_psi: CpuPsiJson,
}

impl From<CpuPsiObservation> for ObservationJson {
    fn from(observation: CpuPsiObservation) -> Self {
        Self {
            duration_us: observation.interval.elapsed.as_micros(),
            cpu_psi: CpuPsiJson {
                some_fraction: observation.interval.some_fraction,
                some_percent: observation.interval.some_fraction * 100.0,
                total_delta_us: observation.interval.total_delta_us,
                avg10_percent: observation.end.avg10_percent,
                avg60_percent: observation.end.avg60_percent,
                avg300_percent: observation.end.avg300_percent,
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

    #[test]
    fn hunt_renders_raw_interval_pressure_without_a_diagnosis() {
        let output = hunt(
            &HuntOptions {
                duration_ms: 1_000,
                output: OutputFormat::Text,
            },
            |_| Ok(observation()),
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
            |_| Ok(observation()),
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
            |_| Err(CpuPsiError::Malformed),
        );
        assert!(output.contains("CPU PSI capability: failed"));
        assert!(output.contains("did not match the expected kernel format"));
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
            );
            assert!(output.contains(&format!("CPU PSI: {}", capability.as_str())));
            assert!(output.contains(capability.explanation()));
        }
    }
}
