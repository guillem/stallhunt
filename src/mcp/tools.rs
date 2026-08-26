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

/// Shared `detail` input-schema property for tools whose lean mode removes
/// fields that are genuinely restated elsewhere in the *same* response. See
/// ADR-0018. `get_recent_history` does not take this — its lifecycle
/// entries have no restatement anywhere in that tool's output, so there is
/// nothing safe to remove.
fn detail_property() -> Value {
    json!({
        "type": "string",
        "enum": ["lean", "full"],
        "description": "\"lean\" (default) removes process-candidate fields that duplicate process_scopes for the current window (zero information loss; stale/resolved lifecycle entries are kept as-is, since they are not reflected in process_scopes) and, for run_hunt, five raw observation arrays (cgroup member/group detail, per-process CPU/IO/scheduling numbers) that findings/process_scopes/cgroup_findings already summarize — every completeness signal (taskstats_capability, delay_accounting, the *_collection_issues counters) is kept. \"full\" returns every field of the schema-version-2 document with the same content as the CLI's JSON output (key order is not guaranteed to match, since this server serializes through a JSON value) — use it when you need the raw evidence, not just the verdict.",
    })
}

pub(crate) fn descriptors() -> Vec<Value> {
    vec![
        json!({
            "name": "get_current_pressure",
            "title": "Inspect Current Pressure",
            "description": "Instant answer: what is constraining useful work on this Linux host right now, from a resident sampler that has been watching continuously. Returns the latest sampling window — CPU, memory, I/O, and cgroup pressure signals with lifecycle states (new, persistent, resolved) and suspect/victim processes. Prefer this over run_hunt for \"why is it slow?\" questions; it does not block.",
            "annotations": read_only_annotations("Inspect Current Pressure"),
            "inputSchema": {
                "type": "object",
                "properties": { "detail": detail_property() },
                "additionalProperties": false,
            },
        }),
        json!({
            "name": "get_recent_history",
            "title": "Inspect Recent Pressure History",
            "description": "Lifecycle-tracked findings over the last up-to-16 sampling windows: what pressure appeared, persisted, and resolved recently, with per-window timestamps and full process-candidate evidence (this is the only place resolved/stale findings' process evidence appears, so it is never trimmed). Use it to answer \"what happened a moment ago?\" — including stalls that have already ended. Instant; does not block.",
            "annotations": read_only_annotations("Inspect Recent Pressure History"),
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false,
            },
        }),
        json!({
            "name": "run_hunt",
            "title": "Run Performance Hunt",
            "description": "One-shot deep diagnosis of what is constraining useful work on this Linux host: observes CPU, memory, I/O, and cgroup pressure for the requested duration, then reports evidence-backed findings with suspect and victim processes. BLOCKS for the full duration (default 5s, range 100ms to 5m); make sure your tool-call timeout exceeds the requested duration.",
            "annotations": read_only_annotations("Run Performance Hunt"),
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
            "title": "Inspect Telemetry Capabilities",
            "description": "Report which telemetry sources this host supports (PSI for CPU/memory/I/O, procfs collectors, cgroup v2) and why any are unavailable. Instant; run it once to learn how trustworthy the other tools' verdicts can be.",
            "annotations": read_only_annotations("Inspect Telemetry Capabilities"),
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false,
            },
        }),
    ]
}

/// Directory reviewers and MCP hosts use these hints to distinguish local,
/// observational diagnostics from tools that mutate the machine or reach an
/// external service. They remain hints, per the MCP specification; the
/// implementation and privilege model are the source of truth.
fn read_only_annotations(title: &str) -> Value {
    json!({
        "title": title,
        "readOnlyHint": true,
        "destructiveHint": false,
        "idempotentHint": true,
        "openWorldHint": false,
    })
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
/// `process_candidates` and `process_role_lists`. Only applied when
/// `process_candidates_stale` is `false` — `true` means (per `watch.rs`'s
/// doc comment) these candidates were retained from a prior confirmed
/// window because the finding is unconfirmed or resolved *in this window*,
/// so they are absent from this window's `process_scopes` and would be
/// permanently lost if stripped. `process_candidates_stale` itself is kept
/// either way — it is a single bool, not a restatement.
fn strip_current_window_lifecycle_duplicates(lifecycle: &mut Value) {
    if let Some(entries) = lifecycle.as_array_mut() {
        for entry in entries {
            let Some(object) = entry.as_object_mut() else {
                continue;
            };
            let stale = object
                .get("process_candidates_stale")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if !stale {
                object.remove("process_candidates");
                object.remove("process_role_lists");
            }
        }
    }
}

/// Applies lean-mode pruning to a `stallhunt.watch_window` document in
/// place: every `current` resource signal (host cpu/memory/io and each
/// pressured cgroup) loses its restated candidate fields — those always
/// correspond to a `process_scopes` entry for the current window, so this
/// is unconditional. `lifecycle` entries lose the same fields only when
/// non-stale, for the same reason. `process_scopes` is untouched and
/// remains the place lean-mode readers find suspect/victim processes.
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
        strip_current_window_lifecycle_duplicates(lifecycle);
    }
}

/// Top-level `observation` keys dropped wholesale in lean mode: each is a
/// flat array of raw per-process telemetry with no completeness data mixed
/// in — every signal ADR-0015 needs (`process_collection_issues`,
/// `schedstat_collection_issues`, `task_stat_collection_issues`,
/// `taskstats_capability`, `delay_accounting`, ...) lives in a separate
/// sibling field that is never touched.
const LEAN_OBSERVATION_OMITTED_TOP_LEVEL_KEYS: &[&str] = &[
    "processes",
    "scheduler_delay_candidates",
    "process_resource_evidence",
];

/// `(parent, child)` pairs dropped from *inside* an `observation` object
/// that mixes raw telemetry with completeness data at the same level —
/// unlike the top-level keys above, removing the whole parent would also
/// delete the completeness signal, so only the raw-data child is removed.
/// `cgroup.issues` (used by `cgroup_membership_complete`) and
/// `process_io.{capability,issues,regressed}` survive.
const LEAN_OBSERVATION_OMITTED_NESTED_KEYS: &[(&str, &str)] = &[
    ("cgroup", "groups"),
    ("cgroup", "members"),
    ("process_io", "processes"),
];

/// Applies lean-mode pruning to a hunt document in place:
///
/// - every finding loses the victim/suspect/process-suspect lists that
///   restate the same candidates `process_scopes` already carries for the
///   host scope (zero information loss);
/// - `observation` loses its raw per-process/per-cgroup telemetry (the
///   top-level and nested keys above), replaced by a dotted-path list
///   under `observation.omitted_for_detail_lean` — built from what was
///   actually present and non-null *before* pruning, so a field that was
///   never collected (a genuinely missing host capability) is never
///   reported as "trimmed for size." Every completeness signal (see
///   `LEAN_OBSERVATION_OMITTED_TOP_LEVEL_KEYS`'s doc comment) is left
///   untouched — ADR-0015's completeness reasoning about a hunt still
///   works on the lean document.
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
        let mut omitted = Vec::new();
        for key in LEAN_OBSERVATION_OMITTED_TOP_LEVEL_KEYS {
            if observation.get(*key).is_some_and(|value| !value.is_null()) {
                omitted.push(json!(key));
            }
            observation.remove(*key);
        }
        for (parent, child) in LEAN_OBSERVATION_OMITTED_NESTED_KEYS {
            let Some(parent_object) = observation.get_mut(*parent).and_then(Value::as_object_mut)
            else {
                continue;
            };
            if parent_object
                .get(*child)
                .is_some_and(|value| !value.is_null())
            {
                omitted.push(json!(format!("{parent}.{child}")));
            }
            parent_object.remove(*child);
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
        "get_recent_history" => Some(get_recent_history(sampler)),
        "run_hunt" => Some(run_hunt(observe, arguments)),
        "get_capabilities" => Some(get_capabilities()),
        _ => None,
    }
}

fn get_current_pressure(sampler: Option<&Sampler>, arguments: &Value) -> Value {
    let detail = match parse_detail(arguments) {
        Ok(detail) => detail,
        Err(error) => return error,
    };
    let Some(sampler) = sampler else {
        return sampler_disabled_result();
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

/// No `detail` parameter: unlike `get_current_pressure`, this tool's
/// response carries no `process_scopes`/`window` for a stripped lifecycle
/// entry to restate, so there is nothing safe to remove — see ADR-0018 and
/// `detail_property`'s doc comment.
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
                Ok((lifecycle, history)) => {
                    let text = history_summary(snapshot);
                    tool_result(
                        text,
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
            tool_result(
                text,
                json!({ "detail": detail_label(detail), "hunt": document }),
            )
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
    fn every_tool_has_directory_review_metadata() {
        for descriptor in descriptors() {
            let name = descriptor["name"].as_str().expect("tool name");
            assert!(
                descriptor["title"]
                    .as_str()
                    .is_some_and(|title| !title.is_empty()),
                "{name} needs a display title"
            );
            let annotations = &descriptor["annotations"];
            assert_eq!(annotations["readOnlyHint"], true, "{name}");
            assert_eq!(annotations["destructiveHint"], false, "{name}");
            assert_eq!(annotations["idempotentHint"], true, "{name}");
            assert_eq!(annotations["openWorldHint"], false, "{name}");
            assert_eq!(annotations["title"], descriptor["title"], "{name}");
        }
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
        assert_eq!(result["structuredContent"]["detail"], "lean");
        assert_eq!(result["structuredContent"]["hunt"]["schema_version"], 2);
        assert_eq!(
            result["structuredContent"]["hunt"]["requested_observation"]["duration_ms"],
            1_000
        );
        let text = result["content"][0]["text"].as_str().expect("text");
        assert!(text.starts_with("Hunt "));
    }

    #[test]
    fn run_hunt_defaults_to_five_seconds() {
        let result = call(fixture_observe, None, "run_hunt", &Value::Null).expect("known tool");
        assert_eq!(
            result["structuredContent"]["hunt"]["requested_observation"]["duration_ms"],
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
    fn get_current_pressure_validates_detail_even_when_the_sampler_is_disabled() {
        // Regression test for review finding #10: an invalid `detail` must
        // surface as a tool error in every server state, not be silently
        // swallowed by the disabled-sampler short-circuit.
        let result = call(
            fixture_observe,
            None,
            "get_current_pressure",
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
            full["structuredContent"]["hunt"]["process_scopes"],
            lean["structuredContent"]["hunt"]["process_scopes"]
        );
        for finding in lean["structuredContent"]["hunt"]["findings"]
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
        let full_observation = &full["structuredContent"]["hunt"]["observation"];
        let lean_observation = &lean["structuredContent"]["hunt"]["observation"];
        for key in LEAN_OBSERVATION_OMITTED_TOP_LEVEL_KEYS {
            assert!(
                full_observation
                    .get(key)
                    .is_some_and(|value| !value.is_null()),
                "fixture should exercise {key} so the omission is meaningful"
            );
            assert!(
                lean_observation.get(key).is_none(),
                "{key} should be omitted"
            );
        }
        // Nested keys: the raw child is gone, but the parent object survives
        // with its completeness sibling intact (#3 in the review — dropping
        // the whole `cgroup`/`process_io` object would also delete the only
        // place their completeness data lives).
        for (parent, child) in LEAN_OBSERVATION_OMITTED_NESTED_KEYS {
            assert!(
                full_observation[parent]
                    .get(child)
                    .is_some_and(|value| !value.is_null()),
                "fixture should exercise {parent}.{child} so the omission is meaningful"
            );
            assert!(
                lean_observation[parent].get(child).is_none(),
                "{parent}.{child} should be omitted"
            );
        }
        assert_eq!(
            full_observation["cgroup"]["issues"], lean_observation["cgroup"]["issues"],
            "cgroup.issues (cgroup_membership_complete's input) must survive lean mode"
        );
        for key in ["capability", "issues", "regressed"] {
            assert_eq!(
                full_observation["process_io"][key], lean_observation["process_io"][key],
                "process_io.{key} must survive lean mode"
            );
        }
        let omitted = lean_observation["omitted_for_detail_lean"]
            .as_array()
            .expect("omitted list");
        for key in LEAN_OBSERVATION_OMITTED_TOP_LEVEL_KEYS {
            assert!(omitted.iter().any(|value| value == key));
        }
        for (parent, child) in LEAN_OBSERVATION_OMITTED_NESTED_KEYS {
            assert!(
                omitted
                    .iter()
                    .any(|value| value == &format!("{parent}.{child}"))
            );
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

    #[test]
    fn run_hunt_lean_mode_never_reports_an_already_absent_field_as_omitted() {
        // A fixture observation with no memory/io/cgroup telemetry at all
        // (e.g. injected without those collectors) must not claim
        // "cgroup"/"process_io" fields were trimmed for size — they were
        // never collected in the first place. Regression test for #8.
        fn bare_observe(_: Duration) -> HuntObservation {
            use crate::psi::{CpuPsiInterval, CpuPsiObservation, CpuPsiRaw};

            HuntObservation {
                psi: Ok(CpuPsiObservation {
                    requested: Duration::from_secs(1),
                    interval: CpuPsiInterval {
                        elapsed: Duration::from_secs(1),
                        total_delta_us: 0,
                        some_fraction: 0.0,
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
                        total_us: 1,
                    },
                }),
                cpu: Err(crate::cpu::CpuError::Unreadable),
                memory: None,
                io: None,
                cgroup: None,
            }
        }
        let result =
            call(bare_observe, None, "run_hunt", &json!({ "duration": "1s" })).expect("known tool");
        let observation = &result["structuredContent"]["hunt"]["observation"];
        let omitted = observation["omitted_for_detail_lean"]
            .as_array()
            .expect("omitted list");
        assert!(
            omitted.is_empty(),
            "nothing was collected, so nothing should be reported as trimmed: {omitted:?}"
        );
        assert!(observation.get("cgroup").is_none_or(Value::is_null));
        assert!(observation.get("process_io").is_none_or(Value::is_null));
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
    fn get_current_pressure_lean_mode_keeps_stale_lifecycle_candidates() {
        // Regression test for review finding #6: a resource that resolves
        // this window carries its last confirmed candidates forward with
        // process_candidates_stale=true (watch.rs:171-173) precisely
        // because it is no longer reflected in this window's
        // process_scopes. Lean mode must not strip those — there is
        // nowhere else in the document they survive.
        use crate::watch::test_support;

        let mut tracker = crate::watch::WatchTracker::new();
        tracker.ingest_signals(test_support::host_signals(
            wide_pressure_signal("host_cpu"),
            test_support::healthy("memory_no_harmful_pressure"),
            test_support::healthy("io_no_harmful_pressure"),
        ));
        let resolved_window = tracker.ingest_signals(test_support::host_signals(
            test_support::healthy("cpu_no_harmful_pressure"),
            test_support::healthy("memory_no_harmful_pressure"),
            test_support::healthy("io_no_harmful_pressure"),
        ));
        let full = crate::watch::watch_window_value(&resolved_window).expect("watch json");
        let mut lean = full.clone();
        lean_watch_window(&mut lean);

        let full_entry = &full["lifecycle"][0];
        let lean_entry = &lean["lifecycle"][0];
        assert_eq!(full_entry["process_candidates_stale"], true);
        assert_eq!(lean_entry["process_candidates_stale"], true);
        assert!(
            !full_entry["process_candidates"]
                .as_array()
                .expect("candidates")
                .is_empty()
        );
        assert_eq!(
            full_entry["process_candidates"], lean_entry["process_candidates"],
            "stale candidates must survive lean mode: they are not in process_scopes this window"
        );
        assert_eq!(
            full_entry["process_role_lists"],
            lean_entry["process_role_lists"]
        );
    }

    #[test]
    fn get_recent_history_never_strips_process_candidates() {
        // Regression test for review finding #7: get_recent_history's
        // response has no process_scopes/window anywhere to restate a
        // stripped lifecycle entry, so unlike get_current_pressure it never
        // removes process_candidates/process_role_lists — there is no
        // `detail` argument to even ask for that. A bogus `detail` argument
        // is silently ignored (the tool doesn't declare the parameter), not
        // an error, matching MCP's "unknown arguments are ignored" norm for
        // undeclared properties.
        let sampler = ready_sampler();
        let result = call(
            fixture_observe,
            Some(&sampler),
            "get_recent_history",
            &json!({ "detail": "lean" }),
        )
        .expect("known tool");
        assert_eq!(result["isError"], false);
        assert!(result["structuredContent"].get("detail").is_none());
        let entry = &result["structuredContent"]["lifecycle"][0];
        assert!(entry.get("process_role_lists").is_some());
        assert!(entry.get("process_candidates").is_some());
    }
}
