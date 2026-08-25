//! `stallhunt mcp`: a Model Context Protocol server over stdio.
//!
//! Serves stallhunt's diagnoses as typed MCP tools for coding agents. The
//! transport is newline-delimited JSON-RPC 2.0 on stdin/stdout; stdout
//! carries protocol frames exclusively, and stdin EOF is the shutdown
//! signal. See docs/mcp-server.md and ADR-0017.

mod protocol;
mod server;
mod tools;

use std::io;

use crate::cli::McpOptions;

pub fn run(options: &McpOptions) -> io::Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut state = server::ServerState::new(*options, crate::observe::observe_hunt);
    server::serve(stdin.lock(), &mut stdout.lock(), &mut state)
}
