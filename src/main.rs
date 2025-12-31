//! Sentinel JavaScript Agent CLI
//!
//! Command-line interface for the JavaScript scripting agent.

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing::info;

use sentinel_agent_js::JsAgent;
use sentinel_agent_protocol::AgentServer;

/// Command line arguments
#[derive(Parser, Debug)]
#[command(name = "sentinel-js-agent")]
#[command(about = "JavaScript scripting agent for Sentinel reverse proxy")]
struct Args {
    /// Path to Unix socket
    #[arg(long, default_value = "/tmp/sentinel-js.sock", env = "AGENT_SOCKET")]
    socket: PathBuf,

    /// Path to JavaScript script file
    #[arg(long, env = "JS_SCRIPT")]
    script: PathBuf,

    /// Enable verbose logging
    #[arg(short, long, env = "JS_VERBOSE")]
    verbose: bool,

    /// Fail open on script errors (allow requests instead of blocking)
    #[arg(long, env = "FAIL_OPEN")]
    fail_open: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Initialize tracing
    let log_level = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(format!(
            "{}={},sentinel_agent_protocol=info",
            env!("CARGO_CRATE_NAME"),
            log_level
        ))
        .json()
        .init();

    info!("Starting Sentinel JavaScript Agent");

    // Create agent
    let agent = JsAgent::new(args.script.clone(), args.fail_open)?;

    info!(
        script = ?args.script,
        fail_open = args.fail_open,
        "Agent configured"
    );

    // Start agent server
    info!(socket = ?args.socket, "Starting agent server");
    let server = AgentServer::new("sentinel-js-agent", args.socket, Box::new(agent));
    server.run().await.map_err(|e| anyhow::anyhow!("{}", e))?;

    Ok(())
}
