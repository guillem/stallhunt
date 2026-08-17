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
fn hunt_reports_an_explicit_placeholder_without_waiting_or_diagnosing() {
    let output = bottleneck(&["hunt", "--duration", "1s"]);
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");

    assert!(output.status.success());
    assert!(stdout.contains("Hunt unavailable"));
    assert!(stdout.contains("Requested observation duration: 1s"));
    assert!(stdout.contains("No observation was performed"));
    assert!(!stdout.contains("healthy"));
}

#[test]
fn hunt_json_keeps_unavailability_machine_readable() {
    let output = bottleneck(&["hunt", "--duration=500ms", "--json"]);
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");

    assert!(output.status.success());
    assert!(stdout.contains("\"schema_version\": 1"));
    assert!(stdout.contains("\"status\": \"unavailable\""));
    assert!(stdout.contains("\"duration_ms\": 500"));
    assert!(stdout.contains("\"observation\": null"));
    assert!(stdout.contains("\"findings\": []"));
}

#[test]
fn capabilities_does_not_claim_to_have_probed_the_host() {
    let output = bottleneck(&["capabilities"]);
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");

    assert!(output.status.success());
    assert!(stdout.contains("Capability discovery is not implemented"));
    assert!(stdout.contains("No system capabilities were checked"));
}

#[test]
fn invalid_invocation_uses_a_nonzero_exit_and_stderr() {
    let output = bottleneck(&["hunt", "--duration", "10"]);
    let stderr = String::from_utf8(output.stderr).expect("stderr should be UTF-8");

    assert_eq!(output.status.code(), Some(2));
    assert!(stderr.contains("invalid duration '10'"));
    assert!(output.stdout.is_empty());
}
