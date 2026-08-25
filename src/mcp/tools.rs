//! MCP tool descriptors and handlers.
//!
//! Every tool result carries both a human-readable text summary in
//! `content` and the corresponding schema_version-2 document in
//! `structuredContent`, so agents can read the verdict at a glance and
//! still consume the full evidence programmatically.

use std::time::{Duration, SystemTime};

use serde_json::{Value, json};

use super::sampler::{Sampler, Snapshot};
use crate::cli::{self, HuntOptions, OutputFormat};
use crate::observe::HuntObservation;
use crate::style::{state_label, status_label};
use crate::watch::{ObservationStatus, WatchWindow};
use crate::{cgroup, cpu, io, memory, psi, render, watch};

/// Default `run_hunt` observation window. Shorter than the CLI's 10s
/// default because MCP clients time tool calls out; long hunts stay
/// available by passing an explicit duration.
pub(crate) const DEFAULT_HUNT_DURATION_MS: u64 = 5_000;

pub(crate) fn descriptors() -> Vec<Value> {
    vec![
        json!({
            "name": "get_current_pressure",
            "description": "Instant answer: what is constraining useful work on this Linux host right now, from a resident sampler that has been watching continuously. Returns the latest sampling window — CPU, memory, I/O, and cgroup pressure signals with lifecycle states (new, persistent, resolved) and suspect/victim processes. Prefer this over run_hunt for \"why is it slow?\" questions; it does not block.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false,
            },
        }),
        json!({
            "name": "get_recent_history",
            "description": "Lifecycle-tracked findings over the last up-to-16 sampling windows: what pressure appeared, persisted, and resolved recently, with per-window timestamps. Use it to answer \"what happened a moment ago?\" — including stalls that have already ended. Instant; does not block.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false,
            },
        }),
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
    sampler: Option<&Sampler>,
    name: &str,
    arguments: &Value,
) -> Option<Value> {
    match name {
        "get_current_pressure" => Some(get_current_pressure(sampler)),
        "get_recent_history" => Some(get_recent_history(sampler)),
        "run_hunt" => Some(run_hunt(observe, arguments)),
        "get_capabilities" => Some(get_capabilities()),
        _ => None,
    }
}

fn get_current_pressure(sampler: Option<&Sampler>) -> Value {
    let Some(sampler) = sampler else {
        return sampler_disabled_result();
    };
    sampler.with_snapshot(|snapshot| match snapshot {
        None => warming_up_result(sampler),
        Some(snapshot) => match watch::watch_window_value(&snapshot.window) {
            Ok(window) => tool_result(
                pressure_summary(snapshot),
                json!({
                    "sampler": sampler_info(sampler, Some(snapshot)),
                    "window": window,
                }),
            ),
            Err(error) => error_result(&format!("failed to serialize window: {error}")),
        },
    })
}

fn get_recent_history(sampler: Option<&Sampler>) -> Value {
    let Some(sampler) = sampler else {
        return sampler_disabled_result();
    };
    sampler.with_snapshot(|snapshot| match snapshot {
        None => warming_up_result(sampler),
        Some(snapshot) => {
            let window = &snapshot.window;
            let serialized = serde_json::to_value(&window.lifecycle)
                .and_then(|lifecycle| Ok((lifecycle, serde_json::to_value(&window.history)?)));
            match serialized {
                Ok((lifecycle, history)) => tool_result(
                    history_summary(snapshot),
                    json!({
                        "sampler": sampler_info(sampler, Some(snapshot)),
                        "lifecycle": lifecycle,
                        "history": history,
                        "window_timestamps": snapshot
                            .timestamps
                            .iter()
                            .map(|(index, at)| json!({
                                "window_index": index,
                                "completed_at_unix_ms": unix_ms(*at),
                            }))
                            .collect::<Vec<_>>(),
                    }),
                ),
                Err(error) => error_result(&format!("failed to serialize history: {error}")),
            }
        }
    })
}

fn sampler_disabled_result() -> Value {
    tool_result(
        "The resident sampler is disabled (--no-sampler); no recent-past view is available. \
         Use run_hunt for a one-shot diagnosis."
            .to_string(),
        json!({ "sampler": { "status": "disabled" } }),
    )
}

fn warming_up_result(sampler: &Sampler) -> Value {
    tool_result(
        format!(
            "The resident sampler has not completed its first {}ms window yet. \
             Retry shortly, or use run_hunt for an immediate one-shot diagnosis.",
            sampler.interval_ms()
        ),
        json!({ "sampler": sampler_info(sampler, None) }),
    )
}

fn sampler_info(sampler: &Sampler, snapshot: Option<&Snapshot>) -> Value {
    json!({
        "status": if snapshot.is_some() { "ok" } else { "warming_up" },
        "interval_ms": sampler.interval_ms(),
        "windows_completed": snapshot.map_or(0, |snapshot| snapshot.windows_completed),
        "latest_window_at_unix_ms": snapshot.map(|snapshot| unix_ms(snapshot.completed_at)),
    })
}

fn unix_ms(at: SystemTime) -> u64 {
    at.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

fn pressure_summary(snapshot: &Snapshot) -> String {
    let window = &snapshot.window;
    let mut lines = vec![format!(
        "Current pressure (window {}, sampled every {}ms):",
        window.index, window.interval_ms
    )];
    for (name, signal) in [
        ("cpu", &window.current.cpu),
        ("memory", &window.current.memory),
        ("io", &window.current.io),
    ] {
        lines.push(format!(
            "- {name}: {} — {}",
            status_label(signal.status),
            signal.summary
        ));
    }
    for (id, signal) in &window.current.cgroups {
        if signal.status == ObservationStatus::Pressure {
            lines.push(format!(
                "- {}: pressure — {}",
                watch::id_label(id),
                signal.summary
            ));
        }
    }
    lines.extend(lifecycle_lines(window));
    lines.push(format!(
        "Based on {} completed window(s).",
        snapshot.windows_completed
    ));
    lines.join("\n")
}

fn history_summary(snapshot: &Snapshot) -> String {
    let window = &snapshot.window;
    let events: usize = window.history.iter().map(|entry| entry.events.len()).sum();
    let mut lines = vec![format!(
        "{} window(s) retained (of {} completed, every {}ms), {} lifecycle event(s).",
        window.history.len(),
        snapshot.windows_completed,
        window.interval_ms,
        events
    )];
    lines.extend(lifecycle_lines(window));
    lines.join("\n")
}

fn lifecycle_lines(window: &WatchWindow) -> Vec<String> {
    window
        .lifecycle
        .iter()
        .map(|finding| {
            format!(
                "- {} {} ({} window(s)): {}",
                state_label(finding.state),
                watch::id_label(&finding.id),
                finding.consecutive_windows,
                finding.summary
            )
        })
        .collect()
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
        let result = call(
            fixture_observe,
            None,
            "run_hunt",
            &json!({ "duration": "1s" }),
        )
        .expect("known tool");
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
        let result = call(fixture_observe, None, "run_hunt", &Value::Null).expect("known tool");
        assert_eq!(
            result["structuredContent"]["requested_observation"]["duration_ms"],
            DEFAULT_HUNT_DURATION_MS
        );
    }

    #[test]
    fn run_hunt_rejects_out_of_range_durations_as_tool_errors() {
        let result = call(
            fixture_observe,
            None,
            "run_hunt",
            &json!({ "duration": "50ms" }),
        )
        .expect("known tool");
        assert_eq!(result["isError"], true);
        let text = result["content"][0]["text"].as_str().expect("text");
        assert!(text.starts_with("invalid duration:"));
        assert!(result.get("structuredContent").is_none());
    }

    #[test]
    fn run_hunt_rejects_non_string_durations() {
        let result =
            call(fixture_observe, None, "run_hunt", &json!({ "duration": 5 })).expect("known tool");
        assert_eq!(result["isError"], true);
    }

    #[test]
    fn get_capabilities_reports_every_probe() {
        let result =
            call(fixture_observe, None, "get_capabilities", &Value::Null).expect("known tool");
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
        assert!(call(fixture_observe, None, "does_not_exist", &Value::Null).is_none());
    }

    fn pressure_signals() -> crate::watch::WindowSignals {
        crate::watch::test_support::host_signals(
            crate::watch::test_support::pressure(
                "cpu_contention",
                crate::analysis::Severity::High,
                0.42,
            ),
            crate::watch::test_support::healthy("memory_no_harmful_pressure"),
            crate::watch::test_support::healthy("io_no_harmful_pressure"),
        )
    }

    fn ready_sampler() -> Sampler {
        let sampler = Sampler::start_with_source(1, pressure_signals);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while sampler.with_snapshot(|snapshot| snapshot.is_none()) {
            assert!(std::time::Instant::now() < deadline, "sampler never ticked");
            std::thread::sleep(Duration::from_millis(2));
        }
        sampler
    }

    #[test]
    fn sampler_tools_report_disabled_without_a_sampler() {
        for name in ["get_current_pressure", "get_recent_history"] {
            let result = call(fixture_observe, None, name, &Value::Null).expect("known tool");
            assert_eq!(result["isError"], false);
            assert_eq!(result["structuredContent"]["sampler"]["status"], "disabled");
            let text = result["content"][0]["text"].as_str().expect("text");
            assert!(text.contains("run_hunt"));
        }
    }

    #[test]
    fn sampler_tools_report_warming_up_before_the_first_window() {
        let sampler = Sampler::start_with_source(3_600_000, pressure_signals);
        let result = call(
            fixture_observe,
            Some(&sampler),
            "get_current_pressure",
            &Value::Null,
        )
        .expect("known tool");
        assert_eq!(
            result["structuredContent"]["sampler"]["status"],
            "warming_up"
        );
        assert_eq!(
            result["structuredContent"]["sampler"]["windows_completed"],
            0
        );
    }

    #[test]
    fn get_current_pressure_returns_the_watch_window_document() {
        let sampler = ready_sampler();
        let result = call(
            fixture_observe,
            Some(&sampler),
            "get_current_pressure",
            &Value::Null,
        )
        .expect("known tool");
        assert_eq!(result["isError"], false);
        assert_eq!(result["structuredContent"]["sampler"]["status"], "ok");
        let window = &result["structuredContent"]["window"];
        assert_eq!(window["kind"], "stallhunt.watch_window");
        assert_eq!(window["schema_version"], 2);
        let text = result["content"][0]["text"].as_str().expect("text");
        assert!(text.contains("cpu: pressure"));
        assert!(text.contains("NEW CPU") || text.contains("PERSISTENT CPU"));
    }

    #[test]
    fn get_recent_history_returns_lifecycle_and_timestamps() {
        let sampler = ready_sampler();
        let result = call(
            fixture_observe,
            Some(&sampler),
            "get_recent_history",
            &Value::Null,
        )
        .expect("known tool");
        assert_eq!(result["isError"], false);
        let structured = &result["structuredContent"];
        assert!(structured["lifecycle"].is_array());
        assert!(structured["history"].is_array());
        let timestamps = structured["window_timestamps"]
            .as_array()
            .expect("timestamps");
        assert!(!timestamps.is_empty());
        assert!(timestamps[0]["completed_at_unix_ms"].as_u64().unwrap() > 0);
    }
}
