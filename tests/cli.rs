use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn stallhunt(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_stallhunt"))
        .args(arguments)
        .output()
        .expect("stallhunt binary should run")
}

#[test]
fn bare_invocation_runs_default_hunt() {
    let output = stallhunt(&[]);
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("stallhunt")
            && (stdout.contains("HEALTHY")
                || stdout.contains("DEGRADED")
                || stdout.contains("INCOMPLETE")
                || stdout.contains("UNAVAILABLE")
                || stdout.contains("assessment"))
    );
}

#[test]
fn completions_subcommand_prints_bash_script() {
    let output = stallhunt(&["completions", "bash"]);
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    assert!(output.status.success());
    assert!(stdout.contains("_stallhunt"));
}

#[test]
fn root_help_exposes_the_initial_command_set() {
    let output = stallhunt(&["--help"]);
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");

    assert!(output.status.success());
    assert!(stdout.contains("hunt"));
    assert!(stdout.contains("watch"));
    assert!(stdout.contains("capabilities"));
    assert!(stdout.contains("record"));
    assert!(stdout.contains("replay"));
    assert!(stdout.contains("redact"));
    assert!(stdout.contains("version"));
}

#[test]
fn version_uses_the_binary_and_package_version() {
    let output = stallhunt(&["version"]);
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");

    assert!(output.status.success());
    assert_eq!(stdout, format!("stallhunt {}\n", env!("CARGO_PKG_VERSION")));
}

#[test]
fn hunt_handles_every_cpu_psi_capability_state() {
    let output = stallhunt(&["hunt", "--duration", "100ms"]);
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");

    assert!(output.status.success());
    if stdout.contains("insufficient observation") {
        assert!(stdout.contains("PSI some") || stdout.contains("CPU"));
        assert!(stdout.contains("Timing") || stdout.contains("100ms"));
    } else {
        assert!(
            stdout.contains("CPU assessment unavailable")
                || stdout.contains("no exact CPU PSI interval")
                || stdout.contains("unavailable")
        );
    }
}

#[test]
fn hunt_json_structurally_reports_observed_or_incomplete_cpu_psi() {
    let output = stallhunt(&["hunt", "--duration=100ms", "--json"]);
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("hunt JSON should parse");

    assert!(output.status.success());
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["requested_observation"]["duration_ms"], 100);
    assert!(json["findings"].is_array());
    assert!(json["cgroup_findings"].is_array());

    let capability = json["capabilities"]["cpu_psi"]["state"]
        .as_str()
        .expect("CPU PSI state should be a string");
    assert!(matches!(
        json["capabilities"]["process_schedstat"]["state"].as_str(),
        Some("available" | "partial" | "unsupported" | "permission_denied" | "failed")
    ));
    assert!(matches!(
        json["capabilities"]["memory_psi"]["state"].as_str(),
        Some("available" | "partial" | "unsupported" | "permission_denied" | "failed")
    ));
    assert!(matches!(
        json["capabilities"]["meminfo"].as_str(),
        Some("available" | "partial" | "unsupported" | "permission_denied" | "failed")
    ));
    assert!(matches!(
        json["capabilities"]["vmstat"].as_str(),
        Some("available" | "partial" | "unsupported" | "permission_denied" | "failed")
    ));
    assert!(matches!(
        json["capabilities"]["io_psi"]["state"].as_str(),
        Some("available" | "partial" | "unsupported" | "permission_denied" | "failed")
    ));
    assert!(matches!(
        json["capabilities"]["diskstats"].as_str(),
        Some("available" | "partial" | "unsupported" | "permission_denied" | "failed")
    ));
    assert!(matches!(
        json["capabilities"]["process_io"].as_str(),
        Some("available" | "partial" | "unsupported" | "permission_denied" | "failed")
    ));
    assert!(matches!(
        json["capabilities"]["cgroup_v2"]["state"].as_str(),
        Some("available" | "partial" | "unsupported" | "permission_denied" | "failed")
    ));
    assert!(matches!(
        capability,
        "available" | "unsupported" | "permission_denied" | "failed"
    ));
    match json["status"].as_str() {
        Some("observed") => {
            assert_eq!(capability, "available");
            assert_eq!(json["findings"][0]["kind"], "insufficient_observation");
            assert!(json["observation"]["cpu_psi"]["some_fraction"].is_number());
            assert!(json["observation"]["memory_psi"]["some_fraction"].is_number());
            assert!(json["observation"]["memory_psi"]["full_state"].is_string());
            assert!(json["observation"]["memory_context"].is_object());
            assert!(json["findings"].as_array().is_some_and(|findings| {
                findings
                    .iter()
                    .any(|finding| finding["resource"] == "memory")
            }));
            assert!(json["observation"]["scheduler_delay_candidates"].is_array());
            assert!(json["observation"]["schedstat_collection_issues"].is_object());
        }
        Some("incomplete") => {
            assert!(json["observation"].is_null() || json["observation"].is_object());
            assert!(
                capability != "available"
                    || json["capabilities"]["host_cpu"] != "available"
                    || json["capabilities"]["memory_psi"]["state"] != "available"
                    || json["capabilities"]["meminfo"] != "available"
                    || json["capabilities"]["vmstat"] != "available"
                    || json["capabilities"]["io_psi"]["state"] != "available"
                    || json["capabilities"]["diskstats"] != "available"
                    || json["capabilities"]["process_io"] != "available"
            );
        }
        status => panic!("unexpected hunt status: {status:?}"),
    }
}

#[test]
fn capabilities_json_reports_the_actual_cpu_psi_probe_state() {
    let output = stallhunt(&["capabilities", "--json"]);
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("capabilities JSON should parse");

    assert!(output.status.success());
    assert!(matches!(
        json["capabilities"]["cpu_psi"]["state"].as_str(),
        Some("available" | "unsupported" | "permission_denied" | "failed")
    ));
    assert!(json["capabilities"]["cpu_psi"]["message"].is_string());
    assert!(matches!(
        json["capabilities"]["process_schedstat"]["state"].as_str(),
        Some("available" | "partial" | "unsupported" | "permission_denied" | "failed")
    ));
    assert!(json["capabilities"]["process_schedstat"]["message"].is_string());
    assert!(matches!(
        json["capabilities"]["memory_psi"]["state"].as_str(),
        Some("available" | "partial" | "unsupported" | "permission_denied" | "failed")
    ));
    assert!(json["capabilities"]["memory_psi"]["message"].is_string());
    assert!(matches!(
        json["capabilities"]["meminfo"].as_str(),
        Some("available" | "partial" | "unsupported" | "permission_denied" | "failed")
    ));
    assert!(matches!(
        json["capabilities"]["vmstat"].as_str(),
        Some("available" | "partial" | "unsupported" | "permission_denied" | "failed")
    ));
    assert!(matches!(
        json["capabilities"]["io_psi"]["state"].as_str(),
        Some("available" | "partial" | "unsupported" | "permission_denied" | "failed")
    ));
    assert!(json["capabilities"]["io_psi"]["message"].is_string());
    assert!(matches!(
        json["capabilities"]["diskstats"].as_str(),
        Some("available" | "partial" | "unsupported" | "permission_denied" | "failed")
    ));
    assert!(matches!(
        json["capabilities"]["process_io"].as_str(),
        Some("available" | "partial" | "unsupported" | "permission_denied" | "failed")
    ));
    assert!(json["capabilities"]["cgroup_v2"]["message"].is_string());
}

#[test]
fn invalid_invocation_uses_a_nonzero_exit_and_stderr() {
    let output = stallhunt(&["hunt", "--duration", "10"]);
    let stderr = String::from_utf8(output.stderr).expect("stderr should be UTF-8");

    assert_eq!(output.status.code(), Some(2));
    assert!(stderr.contains("invalid duration '10'"));
    assert!(output.stdout.is_empty());
}

fn unique_temp_path(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "stallhunt-{label}-{}-{nanos}.json",
        std::process::id()
    ))
}

#[test]
fn record_replay_and_redact_round_trip() {
    let path = unique_temp_path("record");
    let redacted = unique_temp_path("redacted");
    let _cleanup = Cleanup(vec![path.clone(), redacted.clone()]);

    let recorded = stallhunt(&[
        "record",
        "--duration",
        "100ms",
        "--output",
        path.to_str().expect("utf-8 path"),
    ]);
    let stdout = String::from_utf8(recorded.stdout).expect("stdout should be UTF-8");
    assert!(
        recorded.status.success(),
        "{}",
        String::from_utf8_lossy(&recorded.stderr)
    );
    assert!(stdout.contains("Wrote recording"));
    assert!(stdout.contains("schema 1"));

    let json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).expect("recording should be readable"))
            .expect("recording JSON should parse");
    assert_eq!(json["kind"], "stallhunt.recording");
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["redaction"], "none");
    assert_eq!(json["requested_duration_ms"], 100);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    let replayed = stallhunt(&["replay", "--json", path.to_str().expect("utf-8 path")]);
    let replay_stdout = String::from_utf8(replayed.stdout).expect("stdout should be UTF-8");
    assert!(
        replayed.status.success(),
        "{}",
        String::from_utf8_lossy(&replayed.stderr)
    );
    let replay_json: serde_json::Value =
        serde_json::from_str(&replay_stdout).expect("replay JSON should parse");
    assert_eq!(replay_json["schema_version"], 1);
    assert!(replay_json["findings"].is_array());

    let duplicate = stallhunt(&[
        "record",
        "--duration",
        "100ms",
        "--output",
        path.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(duplicate.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("already exists"));

    let redacted_out = stallhunt(&[
        "redact",
        path.to_str().expect("utf-8 path"),
        "--output",
        redacted.to_str().expect("utf-8 path"),
    ]);
    assert!(
        redacted_out.status.success(),
        "{}",
        String::from_utf8_lossy(&redacted_out.stderr)
    );
    let redacted_json: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&redacted).expect("redacted recording should be readable"),
    )
    .expect("redacted JSON should parse");
    assert_eq!(redacted_json["redaction"], "identifiers");
}

#[test]
fn record_without_output_is_invalid_invocation() {
    let output = stallhunt(&["record"]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("option '--output' is required")
            || stderr.contains("--output")
            || stderr.contains("required"),
        "{stderr}"
    );
}

#[test]
fn watch_emits_one_lifecycle_window_and_json_stream_object() {
    let text = stallhunt(&["watch", "--interval", "100ms", "--count", "1", "--plain"]);
    let stdout = String::from_utf8(text.stdout).expect("stdout should be UTF-8");
    assert!(
        text.status.success(),
        "{}",
        String::from_utf8_lossy(&text.stderr)
    );
    assert!(stdout.contains("WATCH  window 1/1  interval 100ms"));
    assert!(stdout.contains("CPU") && stdout.contains("MEM") && stdout.contains("I/O"));
    assert!(stdout.contains("NEW") || stdout.contains("no pressure findings this window"));

    let json_out = stallhunt(&["watch", "--interval=100ms", "--count=1", "--json"]);
    let json_stdout = String::from_utf8(json_out.stdout).expect("stdout should be UTF-8");
    assert!(
        json_out.status.success(),
        "{}",
        String::from_utf8_lossy(&json_out.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_str(json_stdout.trim()).expect("watch JSON should parse");
    assert_eq!(json["kind"], "stallhunt.watch_window");
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["window_index"], 1);
    assert_eq!(json["window_count"], 1);
    assert_eq!(json["interval_ms"], 100);
    assert!(json["lifecycle"].is_array());
    assert!(json["current"]["cpu"]["status"].is_string());
    assert!(json["history"].is_array());
}

#[test]
fn second_sigint_terminates_unlimited_watch_immediately() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_stallhunt"))
        .args(["watch", "--interval", "5m"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("unlimited watch should start");

    // Give watch time to install its cooperative handler before interrupting
    // the deliberately long in-flight window.
    thread::sleep(Duration::from_millis(250));
    send_sigint(child.id());
    thread::sleep(Duration::from_millis(100));
    send_sigint(child.id());

    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(status) = child.try_wait().expect("watch status should be readable") {
            assert_eq!(status.code(), Some(130));
            break;
        }
        if Instant::now() >= deadline {
            child.kill().expect("timed-out watch should be killed");
            let _ = child.wait();
            panic!("second SIGINT did not terminate unlimited watch promptly");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn send_sigint(pid: u32) {
    let status = Command::new("kill")
        .args(["-INT", &pid.to_string()])
        .status()
        .expect("kill command should send SIGINT");
    assert!(status.success(), "kill command should succeed");
}

#[test]
fn replay_rejects_hunt_json() {
    let path = unique_temp_path("not-a-recording");
    fs::write(&path, "{\"schema_version\":1,\"status\":\"observed\"}\n")
        .expect("fixture should write");
    let output = stallhunt(&["replay", path.to_str().expect("utf-8 path")]);
    let _ = fs::remove_file(&path);
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("recording JSON is invalid"));
}

struct Cleanup(Vec<PathBuf>);

impl Drop for Cleanup {
    fn drop(&mut self) {
        for path in &self.0 {
            let _ = fs::remove_file(path);
        }
    }
}
