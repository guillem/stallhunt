//! JSON-RPC 2.0 framing for the MCP stdio transport.
//!
//! MCP stdio messages are newline-delimited JSON objects: one message per
//! line, no embedded newlines, nothing on stdout that is not a protocol
//! frame. Frames are therefore serialized compactly (never pretty-printed)
//! and every diagnostic goes to stderr.

use std::io::{self, Write};

use serde_json::{Value, json};

pub(crate) const PARSE_ERROR: i64 = -32700;
pub(crate) const INVALID_REQUEST: i64 = -32600;
pub(crate) const METHOD_NOT_FOUND: i64 = -32601;
pub(crate) const INVALID_PARAMS: i64 = -32602;

/// One parsed incoming frame, split by JSON-RPC role.
pub(crate) enum Incoming {
    /// A request carrying an id that must receive exactly one response.
    Request {
        id: Value,
        method: String,
        params: Value,
    },
    /// A notification; never answered.
    Notification,
    /// Anything else: a client response (we never send requests) or a
    /// structurally invalid message.
    Other { id: Option<Value> },
}

pub(crate) fn parse_incoming(message: &Value) -> Incoming {
    let id = message.get("id").cloned();
    let method = message.get("method").and_then(Value::as_str);
    match (id, method) {
        (Some(id), Some(method)) => Incoming::Request {
            id,
            method: method.to_string(),
            params: message.get("params").cloned().unwrap_or(Value::Null),
        },
        (None, Some(_)) => Incoming::Notification,
        (id, None) => Incoming::Other { id },
    }
}

pub(crate) fn write_result(writer: &mut impl Write, id: &Value, result: Value) -> io::Result<()> {
    write_frame(
        writer,
        &json!({ "jsonrpc": "2.0", "id": id, "result": result }),
    )
}

pub(crate) fn write_error(
    writer: &mut impl Write,
    id: &Value,
    code: i64,
    message: &str,
) -> io::Result<()> {
    write_frame(
        writer,
        &json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }),
    )
}

fn write_frame(writer: &mut impl Write, frame: &Value) -> io::Result<()> {
    let line = serde_json::to_string(frame).map_err(io::Error::other)?;
    debug_assert!(!line.contains('\n'));
    writer.write_all(line.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()
}
