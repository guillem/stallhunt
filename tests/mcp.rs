//! End-to-end test of `stallhunt mcp` over real pipes: one MCP session
//! covering the handshake, tool listing, every tool family, and EOF
//! shutdown, plus the framing guarantee that stdout carries only
//! newline-delimited JSON.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

struct McpSession {
    child: Child,
    stdin: std::process::ChildStdin,
    reader: BufReader<ChildStdout>,
    next_id: u64,
}

impl McpSession {
    fn spawn(arguments: &[&str]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_stallhunt"))
            .arg("mcp")
            .args(arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("stallhunt mcp should spawn");
        let stdin = child.stdin.take().expect("stdin pipe");
        let reader = BufReader::new(child.stdout.take().expect("stdout pipe"));
        Self {
            child,
            stdin,
            reader,
            next_id: 0,
        }
    }

    fn send(&mut self, frame: &Value) {
        let mut line = frame.to_string();
        line.push('\n');
        self.stdin
            .write_all(line.as_bytes())
            .expect("write to server stdin");
        self.stdin.flush().expect("flush server stdin");
    }

    /// Sends a request and reads exactly one response line, asserting the
    /// line parses standalone as JSON (the framing guard) and answers the
    /// request's id.
    fn request(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        self.send(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }));
        let mut line = String::new();
        self.reader
            .read_line(&mut line)
            .expect("read a response line");
        let response: Value = serde_json::from_str(line.trim_end_matches('\n'))
            .expect("every stdout line parses standalone as JSON");
        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], id, "response answers the request id");
        response
    }

    fn initialize(&mut self) {
        let response = self.request(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "integration-test", "version": "0.0.0" },
            }),
        );
        assert_eq!(response["result"]["protocolVersion"], "2025-06-18");
        assert_eq!(response["result"]["serverInfo"]["name"], "stallhunt");
        self.send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
    }

    /// Drops stdin (EOF, the shutdown signal) and asserts the server exits
    /// zero within the deadline, failing fast instead of wedging the suite.
    fn shutdown(mut self) {
        drop(self.stdin);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match self.child.try_wait().expect("poll server process") {
                Some(status) => {
                    assert!(status.success(), "server should exit cleanly on EOF");
                    return;
                }
                None if Instant::now() > deadline => {
                    self.child.kill().expect("kill wedged server");
                    panic!("server did not exit within the deadline after stdin EOF");
                }
                None => thread::sleep(Duration::from_millis(20)),
            }
        }
    }
}

#[test]
fn a_full_session_serves_every_tool_family_and_exits_on_eof() {
    let mut session = McpSession::spawn(&["--interval", "100ms"]);
    session.initialize();

    let tools = session.request("tools/list", Value::Null);
    let names: Vec<&str> = tools["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name"))
        .collect();
    assert_eq!(
        names,
        [
            "get_current_pressure",
            "get_recent_history",
            "run_hunt",
            "get_capabilities",
        ]
    );

    let capabilities = session.request(
        "tools/call",
        json!({ "name": "get_capabilities", "arguments": {} }),
    );
    assert_eq!(capabilities["result"]["isError"], false);
    assert_eq!(
        capabilities["result"]["structuredContent"]["schema_version"],
        2
    );

    let hunt = session.request(
        "tools/call",
        json!({ "name": "run_hunt", "arguments": { "duration": "100ms" } }),
    );
    assert_eq!(hunt["result"]["isError"], false);
    assert_eq!(hunt["result"]["structuredContent"]["detail"], "lean");
    assert_eq!(
        hunt["result"]["structuredContent"]["hunt"]["schema_version"],
        2
    );
    assert_eq!(
        hunt["result"]["structuredContent"]["hunt"]["requested_observation"]["duration_ms"],
        100
    );

    // Give the 100ms sampler time to complete at least one window, then the
    // stateful tools must serve real snapshots rather than warming_up.
    let deadline = Instant::now() + Duration::from_secs(10);
    let pressure = loop {
        let response = session.request(
            "tools/call",
            json!({ "name": "get_current_pressure", "arguments": {} }),
        );
        if response["result"]["structuredContent"]["sampler"]["status"] == "ok" {
            break response;
        }
        assert!(
            Instant::now() < deadline,
            "sampler never completed a window"
        );
        thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(pressure["result"]["structuredContent"]["detail"], "lean");
    let window = &pressure["result"]["structuredContent"]["window"];
    assert_eq!(window["kind"], "stallhunt.watch_window");
    assert_eq!(window["schema_version"], 2);
    assert!(
        window["current"]["cpu"].get("process_role_lists").is_none(),
        "default detail should omit the process_scopes restatement"
    );

    let full_pressure = session.request(
        "tools/call",
        json!({ "name": "get_current_pressure", "arguments": { "detail": "full" } }),
    );
    assert_eq!(
        full_pressure["result"]["structuredContent"]["detail"],
        "full"
    );
    assert!(
        full_pressure["result"]["structuredContent"]["window"]["current"]["cpu"]
            .get("process_role_lists")
            .is_some(),
        "full detail should still carry the byte-identical schema-2 document"
    );

    let history = session.request(
        "tools/call",
        json!({ "name": "get_recent_history", "arguments": {} }),
    );
    assert_eq!(history["result"]["isError"], false);
    assert!(history["result"]["structuredContent"]["window_timestamps"].is_array());

    session.shutdown();
}

#[test]
fn no_sampler_mode_reports_disabled_and_still_exits_cleanly() {
    let mut session = McpSession::spawn(&["--no-sampler"]);
    session.initialize();
    let response = session.request(
        "tools/call",
        json!({ "name": "get_current_pressure", "arguments": {} }),
    );
    assert_eq!(
        response["result"]["structuredContent"]["sampler"]["status"],
        "disabled"
    );
    session.shutdown();
}
