//! MCP tool descriptors and handlers.
//!
//! Every tool result carries both a human-readable text summary in
//! `content` and the corresponding schema_version-2 document in
//! `structuredContent`, so agents can read the verdict at a glance and
//! still consume the full evidence programmatically.

use std::time::Duration;

use serde_json::{Value, json};

use crate::cli::{self, HuntOptions, OutputFormat};
use crate::observe::HuntObservation;
use crate::{cgroup, cpu, io, memory, psi, render};

/// Default `run_hunt` observation window. Shorter than the CLI's 10s
/// default because MCP clients time tool calls out; long hunts stay
/// available by passing an explicit duration.
pub(crate) const DEFAULT_HUNT_DURATION_MS: u64 = 5_000;

pub(crate) fn descriptors() -> Vec<Value> {
    vec![
        json!({
            "name": "run_hunt",
            "description": "One-shot deep diagnosis of what is constraining useful work on this Linux host: observes CPU, memory, I/O, and cgroup pressure for the requested duration, then reports evidence-backed findings with suspect and victim processes. BLOCKS for the full duration (default 5s, range 100ms to 5m); make sure your tool-call timeout exceeds the requested duration.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "duration": {
                        "type": "string",
                        "description": "Observation duration between 100ms and 5m, e.g. \"500ms\", \"5s\", \"2m\". Defaults to 5s.",
                    },
                },
                "additionalProperties": false,
            },
        }),
        json!({
            "name": "get_capabilities",
            "description": "Report which telemetry sources this host supports (PSI for CPU/memory/I/O, procfs collectors, cgroup v2) and why any are unavailable. Instant; run it once to learn how trustworthy the other tools' verdicts can be.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false,
            },
        }),
    ]
}

/// Dispatches one tools/call by name. Returns None for unknown tools so the
/// server can answer with a JSON-RPC invalid-params error, per spec.
pub(crate) fn call(
    observe: fn(Duration) -> HuntObservation,
    name: &str,
    arguments: &Value,
) -> Option<Value> {
    match name {
        "run_hunt" => Some(run_hunt(observe, arguments)),
        "get_capabilities" => Some(get_capabilities()),
        _ => None,
    }
}

fn run_hunt(observe: fn(Duration) -> HuntObservation, arguments: &Value) -> Value {
    let duration_ms = match arguments.get("duration") {
        None | Some(Value::Null) => DEFAULT_HUNT_DURATION_MS,
        Some(Value::String(text)) => match cli::parse_duration(text) {
            Ok(value) => value,
            Err(error) => return error_result(&format!("invalid duration: {error}")),
        },
        Some(_) => {
            return error_result("invalid duration: expected a string such as \"500ms\" or \"5s\"");
        }
    };
    let options = HuntOptions {
        duration_ms,
        output: OutputFormat::Json,
        verbose: false,
        no_color: false,
    };
    let observation = observe(Duration::from_millis(duration_ms));
    match render::hunt_json_value(&options, observation) {
        Ok(document) => {
            let text = hunt_summary(&document);
            tool_result(text, document)
        }
        Err(error) => error_result(&format!("failed to serialize hunt result: {error}")),
    }
}

fn get_capabilities() -> Value {
    match render::capabilities_json_value(
        psi::probe_cpu_psi(),
        cpu::probe_cpu_telemetry(),
        psi::probe_memory_psi(),
        memory::probe_memory_context(),
        psi::probe_io_psi(),
        io::probe_io_context(),
        cgroup::probe_cgroup_v2(),
    ) {
        Ok(document) => {
            let text = capabilities_summary(&document);
            tool_result(text, document)
        }
        Err(error) => error_result(&format!("failed to serialize capabilities: {error}")),
    }
}

fn hunt_summary(document: &Value) -> String {
    let status = document["status"].as_str().unwrap_or("unknown");
    let findings = document["findings"].as_array();
    match findings {
        Some(list) if !list.is_empty() => {
            let mut lines = vec![format!(
                "Hunt {status}: {} finding(s), most severe first.",
                list.len()
            )];
            for finding in list {
                if let Some(summary) = finding["summary"].as_str() {
                    lines.push(format!("- {summary}"));
                }
            }
            lines.join("\n")
        }
        _ => {
            format!("Hunt {status}: no findings — no harmful pressure observed during the window.")
        }
    }
}

fn capabilities_summary(document: &Value) -> String {
    let mut lines = vec!["Telemetry capabilities:".to_string()];
    if let Some(capabilities) = document["capabilities"].as_object() {
        for (name, value) in capabilities {
            let state = value
                .as_str()
                .or_else(|| value["state"].as_str())
                .unwrap_or("unknown");
            lines.push(format!("- {name}: {state}"));
        }
    }
    lines.join("\n")
}

fn tool_result(text: String, structured: Value) -> Value {
    json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": structured,
        "isError": false,
    })
}

fn error_result(message: &str) -> Value {
    json!({
        "content": [{ "type": "text", "text": message }],
        "isError": true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::tests::hunt_legacy_full_fixture_observation;

    fn fixture_observe(_: Duration) -> HuntObservation {
        hunt_legacy_full_fixture_observation()
    }

    #[test]
    fn run_hunt_returns_text_and_the_schema_version_2_document() {
        let result =
            call(fixture_observe, "run_hunt", &json!({ "duration": "1s" })).expect("known tool");
        assert_eq!(result["isError"], false);
        assert_eq!(result["structuredContent"]["schema_version"], 2);
        assert_eq!(
            result["structuredContent"]["requested_observation"]["duration_ms"],
            1_000
        );
        let text = result["content"][0]["text"].as_str().expect("text");
        assert!(text.starts_with("Hunt "));
    }

    #[test]
    fn run_hunt_defaults_to_five_seconds() {
        let result = call(fixture_observe, "run_hunt", &Value::Null).expect("known tool");
        assert_eq!(
            result["structuredContent"]["requested_observation"]["duration_ms"],
            DEFAULT_HUNT_DURATION_MS
        );
    }

    #[test]
    fn run_hunt_rejects_out_of_range_durations_as_tool_errors() {
        let result =
            call(fixture_observe, "run_hunt", &json!({ "duration": "50ms" })).expect("known tool");
        assert_eq!(result["isError"], true);
        let text = result["content"][0]["text"].as_str().expect("text");
        assert!(text.starts_with("invalid duration:"));
        assert!(result.get("structuredContent").is_none());
    }

    #[test]
    fn run_hunt_rejects_non_string_durations() {
        let result =
            call(fixture_observe, "run_hunt", &json!({ "duration": 5 })).expect("known tool");
        assert_eq!(result["isError"], true);
    }

    #[test]
    fn get_capabilities_reports_every_probe() {
        let result = call(fixture_observe, "get_capabilities", &Value::Null).expect("known tool");
        assert_eq!(result["isError"], false);
        assert_eq!(result["structuredContent"]["schema_version"], 2);
        let capabilities = result["structuredContent"]["capabilities"]
            .as_object()
            .expect("capabilities object");
        for key in [
            "cpu_psi",
            "host_cpu",
            "memory_psi",
            "io_psi",
            "diskstats",
            "cgroup_v2",
        ] {
            assert!(capabilities.contains_key(key), "missing {key}");
        }
        let text = result["content"][0]["text"].as_str().expect("text");
        assert!(text.contains("cpu_psi"));
    }

    #[test]
    fn unknown_tools_return_none() {
        assert!(call(fixture_observe, "does_not_exist", &Value::Null).is_none());
    }
}
