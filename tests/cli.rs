use std::process::{Command, Output};

fn bottleneck(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bottleneck"))
        .args(arguments)
        .output()
        .expect("bottleneck binary should run")
}

#[test]
fn root_help_exposes_the_initial_command_set() {
    let output = bottleneck(&["--help"]);
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");

    assert!(output.status.success());
    assert!(stdout.contains("hunt"));
    assert!(stdout.contains("capabilities"));
    assert!(stdout.contains("version"));
}

#[test]
fn version_uses_the_binary_and_package_version() {
    let output = bottleneck(&["version"]);
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");

    assert!(output.status.success());
    assert_eq!(
        stdout,
        format!("bottleneck {}\n", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn hunt_handles_every_cpu_psi_capability_state_without_claiming_a_diagnosis() {
    let output = bottleneck(&["hunt", "--duration", "100ms"]);
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");

    assert!(output.status.success());
    if stdout.contains("CPU PSI observation complete") {
        assert!(stdout.contains("Requested observation duration: 100ms"));
        assert!(stdout.contains("CPU PSI some during interval:"));
        assert!(stdout.contains("not implemented yet"));
    } else {
        assert!(stdout.contains("CPU PSI observation unavailable"));
        assert!(stdout.contains("No complete CPU PSI interval was observed"));
    }
}

#[test]
fn hunt_json_structurally_reports_observed_or_incomplete_cpu_psi() {
    let output = bottleneck(&["hunt", "--duration=100ms", "--json"]);
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("hunt JSON should parse");

    assert!(output.status.success());
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["requested_observation"]["duration_ms"], 100);
    assert_eq!(json["findings"], serde_json::json!([]));

    let capability = json["capabilities"]["cpu_psi"]["state"]
        .as_str()
        .expect("CPU PSI state should be a string");
    assert!(matches!(
        capability,
        "available" | "unsupported" | "permission_denied" | "failed"
    ));
    match json["status"].as_str() {
        Some("observed") => {
            assert_eq!(capability, "available");
            assert!(json["observation"]["cpu_psi"]["some_fraction"].is_number());
        }
        Some("incomplete") => assert!(json["observation"].is_null()),
        status => panic!("unexpected hunt status: {status:?}"),
    }
}

#[test]
fn capabilities_json_reports_the_actual_cpu_psi_probe_state() {
    let output = bottleneck(&["capabilities", "--json"]);
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("capabilities JSON should parse");

    assert!(output.status.success());
    assert!(matches!(
        json["capabilities"]["cpu_psi"]["state"].as_str(),
        Some("available" | "unsupported" | "permission_denied" | "failed")
    ));
    assert!(json["capabilities"]["cpu_psi"]["message"].is_string());
}

#[test]
fn invalid_invocation_uses_a_nonzero_exit_and_stderr() {
    let output = bottleneck(&["hunt", "--duration", "10"]);
    let stderr = String::from_utf8(output.stderr).expect("stderr should be UTF-8");

    assert_eq!(output.status.code(), Some(2));
    assert!(stderr.contains("invalid duration '10'"));
    assert!(output.stdout.is_empty());
}
