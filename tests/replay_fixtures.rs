use std::process::Command;

fn stallhunt(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_stallhunt"))
        .args(arguments)
        .output()
        .expect("stallhunt binary should run")
}

#[test]
fn replay_fixtures_emit_expected_finding_kinds() {
    let cases: [(&str, &[&str]); 4] = [
        (
            "cpu-healthy",
            &["cpu_no_meaningful_contention", "memory_no_harmful_pressure"],
        ),
        ("cpu-contention", &["cpu_scheduling_contention"]),
        (
            "memory-pressure",
            &["memory_reclaim_pressure", "memory_pressure"],
        ),
        ("io-pressure", &["io_pressure"]),
    ];

    for (name, expected_kinds) in cases {
        let path = format!("tests/fixtures/recordings/{name}.redacted.json");
        let output = stallhunt(&["replay", "--json", &path]);
        assert!(
            output.status.success(),
            "{}: {}",
            name,
            String::from_utf8_lossy(&output.stderr)
        );
        let json: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("replay JSON should parse");
        let kinds = json["findings"]
            .as_array()
            .expect("findings array")
            .iter()
            .filter_map(|finding| finding["kind"].as_str())
            .collect::<Vec<_>>();
        assert!(
            expected_kinds.iter().any(|kind| kinds.contains(kind)),
            "{name}: expected one of {expected_kinds:?}, got {kinds:?}"
        );
    }
}

#[test]
fn replay_fixtures_render_human_output() {
    for name in [
        "cpu-healthy",
        "cpu-contention",
        "memory-pressure",
        "io-pressure",
    ] {
        let path = format!("tests/fixtures/recordings/{name}.redacted.json");
        let output = stallhunt(&["replay", &path]);
        assert!(
            output.status.success(),
            "{}: {}",
            name,
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
        assert!(
            stdout.contains("Verdict:"),
            "{name} should render a verdict"
        );
    }
}

#[test]
fn replay_accepts_legacy_bottleneck_recording_kind() {
    let legacy = std::fs::read_to_string("tests/fixtures/recordings/cpu-healthy.redacted.json")
        .expect("fixture");
    let legacy = legacy.replace("stallhunt.recording", "bottleneck.recording");
    let path = std::env::temp_dir().join(format!(
        "stallhunt-legacy-{}-{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::write(&path, legacy).expect("write legacy fixture");
    let output = stallhunt(&["replay", "--json", path.to_str().expect("utf-8 path")]);
    let _ = std::fs::remove_file(path);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
