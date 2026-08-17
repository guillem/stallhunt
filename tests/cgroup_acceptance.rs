//! Opt-in live coverage for a caller-provided, delegated cgroup-v2 scope.
//!
//! The test never creates, moves, configures, or deletes a cgroup. Set
//! `BOTTLENECK_CGROUP_ACCEPTANCE_PATH` to a uniquely owned delegated subtree
//! that already contains this test process, then run it explicitly.

use std::env;
use std::fs;
use std::process::Command;

#[test]
#[ignore = "requires a uniquely owned delegated cgroup; run with BOTTLENECK_CGROUP_ACCEPTANCE_PATH=/path cargo test --test cgroup_acceptance -- --ignored"]
fn delegated_scope_is_collected_without_mutating_the_hierarchy() {
    if !cfg!(target_os = "linux") {
        eprintln!("skipping cgroup acceptance: Linux is required");
        return;
    }
    let Ok(expected_path) = env::var("BOTTLENECK_CGROUP_ACCEPTANCE_PATH") else {
        eprintln!("skipping cgroup acceptance: BOTTLENECK_CGROUP_ACCEPTANCE_PATH is unset");
        return;
    };
    if !expected_path.starts_with('/') || expected_path.contains("..") {
        eprintln!("skipping cgroup acceptance: configured path is not normalized");
        return;
    }
    if fs::read_to_string("/proc/pressure/cpu").is_err() {
        eprintln!("skipping cgroup acceptance: CPU PSI is unavailable or unreadable");
        return;
    }

    let output = Command::new(env!("CARGO_BIN_EXE_bottleneck"))
        .args(["hunt", "--duration", "1s", "--json"])
        .output()
        .expect("bottleneck binary should run");
    assert!(output.status.success());
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("hunt JSON should parse");
    let groups = json["observation"]["cgroup"]["groups"]
        .as_array()
        .expect("cgroup observation should be present for a delegated scope");
    assert!(
        groups
            .iter()
            .any(|group| group["path"].as_str() == Some(expected_path.as_str())),
        "the configured delegated scope was not retained"
    );
    assert_ne!(
        json["capabilities"]["cgroup_v2"]["state"], "failed",
        "a readable delegated scope should not produce a failed cgroup capability"
    );
}
