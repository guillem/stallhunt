//! The MCP request loop: a blocking read-line → dispatch → write-line cycle
//! over generic reader/writer pairs so unit tests can drive it in memory.

use std::io::{self, BufRead, Write};

use serde_json::{Value, json};

use super::protocol::{
    self, INVALID_REQUEST, Incoming, METHOD_NOT_FOUND, PARSE_ERROR, parse_incoming,
};
use crate::cli::McpOptions;

/// The one protocol revision this server speaks. Offered back to clients
/// that request a revision we do not recognize, per the MCP version
/// negotiation rules.
pub(crate) const PROTOCOL_VERSION: &str = "2025-06-18";

pub(crate) struct ServerState {
    options: McpOptions,
    initialize_received: bool,
}

impl ServerState {
    pub(crate) fn new(options: McpOptions) -> Self {
        Self {
            options,
            initialize_received: false,
        }
    }
}

/// Serves one MCP session until the reader reaches EOF, which is the
/// shutdown signal for a stdio transport: the client closing our stdin.
pub(crate) fn serve(
    reader: impl BufRead,
    writer: &mut impl Write,
    state: &mut ServerState,
) -> io::Result<()> {
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(&line) {
            Ok(message) => handle_message(writer, state, &message)?,
            Err(_) => protocol::write_error(writer, &Value::Null, PARSE_ERROR, "parse error")?,
        }
    }
    Ok(())
}

fn handle_message(
    writer: &mut impl Write,
    state: &mut ServerState,
    message: &Value,
) -> io::Result<()> {
    match parse_incoming(message) {
        Incoming::Request { id, method, params } => {
            handle_request(writer, state, &id, &method, &params)
        }
        // Unknown notifications are ignored per JSON-RPC; the only one we
        // act on marks the handshake as complete on the client side, and we
        // already accept requests once we have answered initialize.
        Incoming::Notification => Ok(()),
        // A response frame (we never send requests) is dropped; a frame
        // with an id but no method is malformed and gets an error.
        Incoming::Other { id: Some(id) } => {
            protocol::write_error(writer, &id, INVALID_REQUEST, "invalid request")
        }
        Incoming::Other { id: None } => Ok(()),
    }
}

fn handle_request(
    writer: &mut impl Write,
    state: &mut ServerState,
    id: &Value,
    method: &str,
    params: &Value,
) -> io::Result<()> {
    match method {
        "initialize" => {
            state.initialize_received = true;
            protocol::write_result(writer, id, initialize_result(&state.options, params))
        }
        "ping" => protocol::write_result(writer, id, json!({})),
        _ if !state.initialize_received => protocol::write_error(
            writer,
            id,
            INVALID_REQUEST,
            "server not initialized: send initialize first",
        ),
        "tools/list" => protocol::write_result(writer, id, json!({ "tools": [] })),
        "tools/call" => protocol::write_error(writer, id, protocol::INVALID_PARAMS, "unknown tool"),
        _ => protocol::write_error(writer, id, METHOD_NOT_FOUND, "method not found"),
    }
}

fn initialize_result(options: &McpOptions, params: &Value) -> Value {
    // We speak a single protocol revision, so negotiation collapses: echo
    // it when the client requested it, and offer it as our best otherwise —
    // the client then decides whether to continue or disconnect.
    let _requested = params.get("protocolVersion").and_then(Value::as_str);
    let version = PROTOCOL_VERSION;
    let sampler_note = if options.sampler {
        format!(
            "A resident sampler observes host pressure every {}ms.",
            options.interval_ms
        )
    } else {
        "The resident sampler is disabled; only one-shot tools are available.".to_string()
    };
    json!({
        "protocolVersion": version,
        "capabilities": { "tools": {} },
        "serverInfo": {
            "name": "stallhunt",
            "title": "Stallhunt",
            "version": env!("CARGO_PKG_VERSION"),
        },
        "instructions": format!(
            "Stallhunt diagnoses what is constraining useful work on this Linux host. {sampler_note} run_hunt blocks for its full duration; prefer the sampler-backed tools for instant answers."
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn options() -> McpOptions {
        McpOptions {
            interval_ms: 2_000,
            sampler: true,
        }
    }

    fn serve_lines(lines: &str) -> Vec<Value> {
        let mut state = ServerState::new(options());
        let mut output = Vec::new();
        serve(Cursor::new(lines.to_string()), &mut output, &mut state).expect("serve");
        String::from_utf8(output)
            .expect("utf8 output")
            .lines()
            .map(|line| serde_json::from_str(line).expect("each stdout line parses as JSON"))
            .collect()
    }

    fn initialize_line() -> String {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": { "name": "test", "version": "0.0.0" },
            },
        })
        .to_string()
    }

    #[test]
    fn initialize_negotiates_the_supported_version() {
        let responses = serve_lines(&initialize_line());
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0]["id"], 1);
        assert_eq!(responses[0]["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(responses[0]["result"]["serverInfo"]["name"], "stallhunt");
        assert!(responses[0]["result"]["capabilities"]["tools"].is_object());
    }

    #[test]
    fn unsupported_client_version_is_answered_with_ours() {
        let line = json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "initialize",
            "params": { "protocolVersion": "2024-11-05" },
        })
        .to_string();
        let responses = serve_lines(&line);
        assert_eq!(responses[0]["result"]["protocolVersion"], PROTOCOL_VERSION);
    }

    #[test]
    fn ping_works_before_and_after_initialize() {
        let input = format!(
            "{}\n{}\n{}\n",
            json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" }),
            initialize_line().replace("\"id\":1", "\"id\":2"),
            json!({ "jsonrpc": "2.0", "id": 3, "method": "ping" }),
        );
        let responses = serve_lines(&input);
        assert_eq!(responses.len(), 3);
        assert!(responses[0]["result"].is_object());
        assert!(responses[2]["result"].is_object());
    }

    #[test]
    fn requests_before_initialize_are_rejected() {
        let line = json!({ "jsonrpc": "2.0", "id": 5, "method": "tools/list" }).to_string();
        let responses = serve_lines(&line);
        assert_eq!(responses[0]["error"]["code"], INVALID_REQUEST);
    }

    #[test]
    fn unknown_methods_get_method_not_found() {
        let input = format!(
            "{}\n{}\n",
            initialize_line(),
            json!({ "jsonrpc": "2.0", "id": 2, "method": "resources/list" }),
        );
        let responses = serve_lines(&input);
        assert_eq!(responses[1]["error"]["code"], METHOD_NOT_FOUND);
    }

    #[test]
    fn malformed_lines_get_a_parse_error_and_do_not_kill_the_session() {
        let input = format!("this is not json\n{}\n", initialize_line());
        let responses = serve_lines(&input);
        assert_eq!(responses[0]["error"]["code"], PARSE_ERROR);
        assert_eq!(responses[0]["id"], Value::Null);
        assert!(responses[1]["result"].is_object());
    }

    #[test]
    fn notifications_are_never_answered() {
        let input = format!(
            "{}\n{}\n",
            initialize_line(),
            json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        );
        let responses = serve_lines(&input);
        assert_eq!(responses.len(), 1);
    }

    #[test]
    fn eof_ends_the_session_cleanly() {
        let mut state = ServerState::new(options());
        let mut output = Vec::new();
        serve(Cursor::new(String::new()), &mut output, &mut state).expect("serve");
        assert!(output.is_empty());
    }
}
