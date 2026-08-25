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

/// Shared `detail` input-schema property: every tool that can return a wide
/// process-scope cascade (many pressured cgroups) accepts this so an agent
/// can opt into the full schema-version-2 document instead of the
/// deduplicated default. See ADR-0018.
fn detail_property() -> Value {
    json!({
        "type": "string",
        "enum": ["lean", "full"],
        "description": "\"lean\" (default) removes process-candidate fields that duplicate process_scopes (zero information loss) and, for run_hunt, the raw per-process/per-cgroup telemetry arrays under observation that findings/process_scopes/cgroup_findings already summarize (completeness signals like taskstats_capability are kept). Typically 60-80% smaller. \"full\" returns the complete schema-version-2 document byte-identical to the CLI's JSON output — use it when you need the raw evidence, not just the verdict.",
    })
}

pub(crate) fn descriptors() -> Vec<Value> {
    vec![
        json!({
            "name": "get_current_pressure",
            "description": "Instant answer: what is constraining useful work on this Linux host right now, from a resident sampler that has been watching continuously. Returns the latest sampling window — CPU, memory, I/O, and cgroup pressure signals with lifecycle states (new, persistent, resolved) and suspect/victim processes. Prefer this over run_hunt for \"why is it slow?\" questions; it does not block.",
            "inputSchema": {
                "type": "object",
                "properties": { "detail": detail_property() },
                "additionalProperties": false,
            },
        }),
        json!({
            "name": "get_recent_history",
            "description": "Lifecycle-tracked findings over the last up-to-16 sampling windows: what pressure appeared, persisted, and resolved recently, with per-window timestamps. Use it to answer \"what happened a moment ago?\" — including stalls that have already ended. Instant; does not block.",
            "inputSchema": {
                "type": "object",
                "properties": { "detail": detail_property() },
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
                    "detail": detail_property(),
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

/// Whether a tool result carries the deduplicated payload or the complete
/// schema-version-2 document. See ADR-0018: `process_scopes` is the
/// canonical per-process view; `ResourceSignal.process_candidates` /
/// `process_candidate_availability` / `process_role_lists` (in
/// `window.current`), `TrackedFinding.process_candidates` /
/// `process_role_lists` (in `window.lifecycle`), and
/// `CpuFinding.victims` / `.suspects` / `IoFinding.process_suspects` (in a
/// hunt's `findings`) all restate the same candidates a second or third
/// time. Lean mode removes those restatements; nothing else changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Detail {
    Lean,
    Full,
}

fn parse_detail(arguments: &Value) -> Result<Detail, Value> {
    match arguments.get("detail") {
        None | Some(Value::Null) => Ok(Detail::Lean),
        Some(Value::String(text)) if text == "lean" => Ok(Detail::Lean),
        Some(Value::String(text)) if text == "full" => Ok(Detail::Full),
        Some(_) => Err(error_result(
            "invalid detail: expected \"lean\" or \"full\"",
        )),
    }
}

/// Removes the `ResourceSignal` fields that restate `process_scopes`:
/// `process_candidates`, `process_candidate_availability`, and
/// `process_role_lists`. A no-op if `signal` is not an object with those
/// keys, so it is safe to call on any `current.{cpu,memory,io}` entry or
/// flattened `current.cgroups[*]` element.
fn strip_resource_signal_duplicates(signal: &mut Value) {
    if let Some(object) = signal.as_object_mut() {
        object.remove("process_candidates");
        object.remove("process_candidate_availability");
        object.remove("process_role_lists");
    }
}

/// Removes the `TrackedFinding` fields that restate `process_scopes`:
/// `process_candidates` and `process_role_lists`. `process_candidates_stale`
/// is kept — it is a single bool, not a restatement.
fn strip_lifecycle_duplicates(lifecycle: &mut Value) {
    if let Some(entries) = lifecycle.as_array_mut() {
        for entry in entries {
            if let Some(object) = entry.as_object_mut() {
                object.remove("process_candidates");
                object.remove("process_role_lists");
            }
        }
    }
}

/// Applies lean-mode pruning to a `stallhunt.watch_window` document in
/// place: every `current` resource signal (host cpu/memory/io and each
/// pressured cgroup) and every `lifecycle` entry loses its restated
/// candidate fields; `process_scopes` is untouched and remains the single
/// place lean-mode readers find suspect/victim processes.
fn lean_watch_window(window: &mut Value) {
    if let Some(current) = window.get_mut("current") {
        for resource in ["cpu", "memory", "io"] {
            if let Some(signal) = current.get_mut(resource) {
                strip_resource_signal_duplicates(signal);
            }
        }
        if let Some(cgroups) = current.get_mut("cgroups").and_then(Value::as_array_mut) {
            for cgroup in cgroups {
                strip_resource_signal_duplicates(cgroup);
            }
        }
    }
    if let Some(lifecycle) = window.get_mut("lifecycle") {
        strip_lifecycle_duplicates(lifecycle);
    }
}

/// The `observation` keys that carry raw per-process/per-cgroup telemetry:
/// every process's raw CPU/IO/scheduling numbers, restated in aggregate by
/// `findings`, `process_scopes`, and `cgroup_findings`. Unlike the
/// restatement fields above, dropping these is a real reduction in detail,
/// not deduplication — the *inputs* the analyzer consumed are gone, only
/// its *verdict* remains. `detail: "full"` (or `stallhunt record`, for
/// durable capture) is the way to get them back. See ADR-0018.
const LEAN_OBSERVATION_OMITTED_KEYS: &[&str] = &[
    "cgroup",
    "process_resource_evidence",
    "scheduler_delay_candidates",
    "processes",
    "process_io",
];

/// Applies lean-mode pruning to a hunt document in place:
///
/// - every finding loses the victim/suspect/process-suspect lists that
///   restate the same candidates `process_scopes` already carries for the
///   host scope (zero information loss);
/// - `observation` loses its raw per-process/per-cgroup telemetry arrays
///   (`LEAN_OBSERVATION_OMITTED_KEYS`), replaced by a same-named list under
///   `omitted_for_detail_lean` so an agent can tell the difference between
///   "trimmed for size" and "collection failed." Every completeness signal
///   (`taskstats_capability`, `delay_accounting`, the `*_collection_issues`
///   counters, PSI, capabilities) is left untouched — ADR-0015's
///   completeness reasoning about a hunt still works on the lean document.
fn lean_hunt_document(document: &mut Value) {
    if let Some(findings) = document.get_mut("findings").and_then(Value::as_array_mut) {
        for finding in findings {
            if let Some(object) = finding.as_object_mut() {
                object.remove("victims");
                object.remove("suspects");
                object.remove("process_suspects");
            }
        }
    }
    if let Some(observation) = document
        .get_mut("observation")
        .and_then(Value::as_object_mut)
    {
        let omitted: Vec<Value> = LEAN_OBSERVATION_OMITTED_KEYS
            .iter()
            .filter(|key| observation.contains_key(**key))
            .map(|key| json!(key))
            .collect();
        for key in LEAN_OBSERVATION_OMITTED_KEYS {
            observation.remove(*key);
        }
        observation.insert("omitted_for_detail_lean".to_string(), Value::Array(omitted));
    }
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
        "get_current_pressure" => Some(get_current_pressure(sampler, arguments)),
        "get_recent_history" => Some(get_recent_history(sampler, arguments)),
        "run_hunt" => Some(run_hunt(observe, arguments)),
        "get_capabilities" => Some(get_capabilities()),
        _ => None,
    }
}

fn get_current_pressure(sampler: Option<&Sampler>, arguments: &Value) -> Value {
    let Some(sampler) = sampler else {
        return sampler_disabled_result();
    };
    let detail = match parse_detail(arguments) {
        Ok(detail) => detail,
        Err(error) => return error,
    };
    sampler.with_snapshot(|snapshot| match snapshot {
        None => warming_up_result(sampler),
        Some(snapshot) => match watch::watch_window_value(&snapshot.window) {
            Ok(mut window) => {
                let text = pressure_summary(snapshot);
                if detail == Detail::Lean {
                    lean_watch_window(&mut window);
                }
                tool_result(
                    text,
                    json!({
                        "detail": detail_label(detail),
                        "sampler": sampler_info(sampler, Some(snapshot)),
                        "window": window,
                    }),
                )
            }
            Err(error) => error_result(&format!("failed to serialize window: {error}")),
        },
    })
}

fn get_recent_history(sampler: Option<&Sampler>, arguments: &Value) -> Value {
    let Some(sampler) = sampler else {
        return sampler_disabled_result();
    };
    let detail = match parse_detail(arguments) {
        Ok(detail) => detail,
        Err(error) => return error,
    };
    sampler.with_snapshot(|snapshot| match snapshot {
        None => warming_up_result(sampler),
        Some(snapshot) => {
            let window = &snapshot.window;
            let serialized = serde_json::to_value(&window.lifecycle)
                .and_then(|lifecycle| Ok((lifecycle, serde_json::to_value(&window.history)?)));
            match serialized {
                Ok((mut lifecycle, history)) => {
                    let text = history_summary(snapshot);
                    if detail == Detail::Lean {
                        strip_lifecycle_duplicates(&mut lifecycle);
                    }
                    tool_result(
                        text,
                        json!({
                            "detail": detail_label(detail),
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
                    )
                }
                Err(error) => error_result(&format!("failed to serialize history: {error}")),
            }
        }
    })
}

fn detail_label(detail: Detail) -> &'static str {
    match detail {
        Detail::Lean => "lean",
        Detail::Full => "full",
    }
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
    let detail = match parse_detail(arguments) {
        Ok(detail) => detail,
        Err(error) => return error,
    };
    let options = HuntOptions {
        duration_ms,
        output: OutputFormat::Json,
        verbose: false,
        no_color: false,
    };
    let observation = observe(Duration::from_millis(duration_ms));
    match render::hunt_json_value(&options, observation) {
        Ok(mut document) => {
            let text = hunt_summary(&document);
            if detail == Detail::Lean {
                lean_hunt_document(&mut document);
            }
            if let Some(object) = document.as_object_mut() {
                object.insert("detail".to_string(), json!(detail_label(detail)));
            }
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
    fn detail_lean_is_the_default_and_full_is_opt_in() {
        assert_eq!(parse_detail(&Value::Null).unwrap(), Detail::Lean);
        assert_eq!(parse_detail(&json!({})).unwrap(), Detail::Lean);
        assert_eq!(
            parse_detail(&json!({ "detail": "lean" })).unwrap(),
            Detail::Lean
        );
        assert_eq!(
            parse_detail(&json!({ "detail": "full" })).unwrap(),
            Detail::Full
        );
        assert!(parse_detail(&json!({ "detail": "verbose" })).is_err());
    }

    #[test]
    fn run_hunt_rejects_an_invalid_detail_value() {
        let result = call(
            fixture_observe,
            None,
            "run_hunt",
            &json!({ "detail": "verbose" }),
        )
        .expect("known tool");
        assert_eq!(result["isError"], true);
        assert!(
            result["content"][0]["text"]
                .as_str()
                .unwrap()
                .starts_with("invalid detail:")
        );
    }

    #[test]
    fn run_hunt_lean_mode_drops_victim_and_suspect_restatements() {
        let full = call(
            fixture_observe,
            None,
            "run_hunt",
            &json!({ "duration": "1s", "detail": "full" }),
        )
        .expect("known tool");
        let lean = call(
            fixture_observe,
            None,
            "run_hunt",
            &json!({ "duration": "1s" }),
        )
        .expect("known tool");
        assert_eq!(full["structuredContent"]["detail"], "full");
        assert_eq!(lean["structuredContent"]["detail"], "lean");
        // process_scopes is the canonical view and must be untouched.
        assert_eq!(
            full["structuredContent"]["process_scopes"],
            lean["structuredContent"]["process_scopes"]
        );
        for finding in lean["structuredContent"]["findings"]
            .as_array()
            .expect("findings")
        {
            assert!(finding.get("victims").is_none());
            assert!(finding.get("suspects").is_none());
            assert!(finding.get("process_suspects").is_none());
        }
        let full_len = serde_json::to_string(&full["structuredContent"])
            .unwrap()
            .len();
        let lean_len = serde_json::to_string(&lean["structuredContent"])
            .unwrap()
            .len();
        assert!(
            lean_len < full_len,
            "lean ({lean_len}) should be smaller than full ({full_len})"
        );
    }

    #[test]
    fn run_hunt_lean_mode_omits_raw_observation_telemetry_but_keeps_completeness_signals() {
        let full = call(
            fixture_observe,
            None,
            "run_hunt",
            &json!({ "duration": "1s", "detail": "full" }),
        )
        .expect("known tool");
        let lean = call(
            fixture_observe,
            None,
            "run_hunt",
            &json!({ "duration": "1s" }),
        )
        .expect("known tool");
        let full_observation = &full["structuredContent"]["observation"];
        let lean_observation = &lean["structuredContent"]["observation"];
        for key in LEAN_OBSERVATION_OMITTED_KEYS {
            assert!(
                full_observation.get(key).is_some(),
                "fixture should exercise {key} so the omission is meaningful"
            );
            assert!(
                lean_observation.get(key).is_none(),
                "{key} should be omitted"
            );
        }
        let omitted = lean_observation["omitted_for_detail_lean"]
            .as_array()
            .expect("omitted list");
        for key in LEAN_OBSERVATION_OMITTED_KEYS {
            assert!(omitted.iter().any(|value| value == key));
        }
        // ADR-0015's completeness signal must survive lean mode: an agent
        // reading a lean document can still tell degraded from complete
        // telemetry.
        for key in [
            "taskstats_capability",
            "delay_accounting",
            "process_collection_issues",
            "schedstat_collection_issues",
            "task_stat_collection_issues",
            "taskstats_collection_issues",
            "cpu_psi",
            "memory_psi",
            "io_psi",
        ] {
            assert_eq!(
                full_observation[key], lean_observation[key],
                "{key} must be preserved unchanged"
            );
        }
    }

    /// A synthetic `ResourceSignal` carrying real candidate/role-list data,
    /// large enough to be representative of a genuinely pressured resource
    /// (mirrors the shape observed against `fake_workload.sh`'s CPU
    /// oversubscription phase, which is what motivated ADR-0018).
    fn wide_pressure_signal(qualifier_kind: &'static str) -> crate::watch::ResourceSignal {
        use crate::analysis::{
            Confidence, ProcessCandidate, ProcessCandidateAvailability, ProcessCandidateEvidence,
            ProcessRole, ProcessRoleCompleteness, ProcessRoleList,
        };
        use crate::cpu::ProcessKey;

        let mut signal = crate::watch::test_support::pressure_with_qualifiers(
            "cpu_contention",
            crate::analysis::Severity::High,
            0.42,
            vec![crate::analysis::Qualifier {
                kind: qualifier_kind,
                message: "same-window correlation only; not causal proof of scheduling delay.",
            }],
        );
        let candidates: Vec<ProcessCandidate> = (0..5)
            .map(|index| ProcessCandidate {
                role: ProcessRole::CpuSuspect,
                key: ProcessKey {
                    pid: 80_000 + index,
                    start_time_ticks: 2_121_112,
                },
                name: "sh".to_string(),
                confidence: Confidence::High,
                label: "observed_same_window_cpu_consumer_candidate",
                evidence: ProcessCandidateEvidence::CpuConsumption {
                    cpu_fraction_of_one: 0.9,
                    cpu_ticks: 900,
                },
            })
            .collect();
        signal.process_candidates = candidates.clone();
        signal.process_role_lists = vec![ProcessRoleList {
            role: ProcessRole::CpuSuspect,
            availability: ProcessCandidateAvailability::Available,
            completeness: ProcessRoleCompleteness::Complete,
            stale: false,
            candidates,
        }];
        signal
    }

    /// Builds a window with `cgroup_count` pressured cgroups all carrying a
    /// realistic candidate payload, the way system-wide CPU pressure
    /// cascades up the entire cgroup ancestry (root, user.slice,
    /// user-N.slice, ... one entry per level).
    fn wide_window_signals(cgroup_count: usize) -> crate::watch::WindowSignals {
        use crate::analysis::{ProcessScope, ProcessScopeKind};

        let mut signals = crate::watch::test_support::host_signals(
            wide_pressure_signal("host_cpu"),
            crate::watch::test_support::healthy("memory_no_harmful_pressure"),
            crate::watch::test_support::healthy("io_no_harmful_pressure"),
        );
        signals.process_scopes.push(ProcessScope {
            scope: ProcessScopeKind::Host,
            roles: wide_pressure_signal("host_cpu").process_role_lists,
        });
        for index in 0..cgroup_count {
            let path = format!("/synthetic-{index}.slice");
            signals.cgroups.push((
                crate::watch::FindingId::Cgroup {
                    path: path.clone(),
                    resource: crate::analysis::CgroupResourceKind::Cpu,
                },
                wide_pressure_signal("cgroup_cpu"),
            ));
            signals.process_scopes.push(ProcessScope {
                scope: ProcessScopeKind::Cgroup { path },
                roles: wide_pressure_signal("cgroup_cpu").process_role_lists,
            });
        }
        signals
    }

    #[test]
    fn get_current_pressure_lean_mode_stays_bounded_under_a_wide_cgroup_cascade() {
        let mut tracker = crate::watch::WatchTracker::new();
        let window = tracker.ingest_signals(wide_window_signals(12));
        let full = crate::watch::watch_window_value(&window).expect("watch json");
        let mut lean = full.clone();
        lean_watch_window(&mut lean);

        let full_len = serde_json::to_string(&full).unwrap().len();
        let lean_len = serde_json::to_string(&lean).unwrap().len();
        // 12 cascading cgroups with real candidate payloads reproduced the
        // reported ~190KB blowup at full detail; lean mode must land far
        // below that regardless of how many cgroup levels are pressured,
        // since it carries the candidates exactly once (via process_scopes)
        // instead of three times (current, lifecycle, process_scopes).
        assert!(
            lean_len < 40_000,
            "lean payload grew to {lean_len} bytes for 12 pressured cgroups"
        );
        assert!(
            lean_len * 3 < full_len,
            "lean ({lean_len}) should be well under a third of full ({full_len})"
        );
        // Zero information loss: process_scopes carries the same candidates
        // in both modes.
        assert_eq!(full["process_scopes"], lean["process_scopes"]);
        assert!(
            !lean["process_scopes"]
                .as_array()
                .expect("scopes")
                .is_empty()
        );
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

    #[test]
    fn get_current_pressure_lean_drops_duplicates_full_keeps_them() {
        let sampler = ready_sampler();
        let full = call(
            fixture_observe,
            Some(&sampler),
            "get_current_pressure",
            &json!({ "detail": "full" }),
        )
        .expect("known tool");
        let lean = call(
            fixture_observe,
            Some(&sampler),
            "get_current_pressure",
            &Value::Null,
        )
        .expect("known tool");
        assert_eq!(full["structuredContent"]["detail"], "full");
        assert_eq!(lean["structuredContent"]["detail"], "lean");
        let full_cpu = &full["structuredContent"]["window"]["current"]["cpu"];
        let lean_cpu = &lean["structuredContent"]["window"]["current"]["cpu"];
        assert!(full_cpu.get("process_role_lists").is_some());
        assert!(lean_cpu.get("process_role_lists").is_none());
        assert!(lean_cpu.get("process_candidates").is_none());
        assert!(lean_cpu.get("process_candidate_availability").is_none());
        // Everything else on the resource signal is preserved.
        assert_eq!(full_cpu["status"], lean_cpu["status"]);
        assert_eq!(full_cpu["summary"], lean_cpu["summary"]);
        assert_eq!(
            full["structuredContent"]["window"]["process_scopes"],
            lean["structuredContent"]["window"]["process_scopes"]
        );
    }

    #[test]
    fn get_recent_history_lean_drops_duplicates_full_keeps_them() {
        let sampler = ready_sampler();
        let full = call(
            fixture_observe,
            Some(&sampler),
            "get_recent_history",
            &json!({ "detail": "full" }),
        )
        .expect("known tool");
        let lean = call(
            fixture_observe,
            Some(&sampler),
            "get_recent_history",
            &Value::Null,
        )
        .expect("known tool");
        let full_entry = &full["structuredContent"]["lifecycle"][0];
        let lean_entry = &lean["structuredContent"]["lifecycle"][0];
        assert!(full_entry.get("process_role_lists").is_some());
        assert!(lean_entry.get("process_role_lists").is_none());
        assert!(lean_entry.get("process_candidates").is_none());
        // process_candidates_stale is a single bool, not a restatement, and
        // stays in both modes.
        assert_eq!(
            full_entry["process_candidates_stale"],
            lean_entry["process_candidates_stale"]
        );
    }
}
