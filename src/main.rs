//! Sentinel JavaScript Agent CLI
//!
//! Command-line interface for the JavaScript scripting agent.
//!
//! Supports both UDS (Unix Domain Socket) and gRPC transports for v2 protocol.

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use tracing::info;

use sentinel_agent_js::JsAgent;
use sentinel_agent_protocol::v2::GrpcAgentServerV2;

/// Command line arguments
#[derive(Parser, Debug)]
#[command(name = "sentinel-js-agent")]
#[command(about = "JavaScript scripting agent for Sentinel reverse proxy (v2 protocol)")]
#[command(version)]
struct Args {
    /// Path to JavaScript script file
    #[arg(long, env = "JS_SCRIPT")]
    script: PathBuf,

    /// gRPC address to listen on (e.g., "0.0.0.0:50052").
    /// If not specified, defaults to "0.0.0.0:50052".
    #[arg(long, env = "GRPC_ADDRESS")]
    grpc_address: Option<String>,

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

    info!("Starting Sentinel JavaScript Agent (v2 protocol)");

    // Create agent
    let agent = JsAgent::new(args.script.clone(), args.fail_open)?;

    info!(
        script = ?args.script,
        fail_open = args.fail_open,
        "Agent configured"
    );

    // Determine gRPC address
    let grpc_addr = args
        .grpc_address
        .unwrap_or_else(|| "0.0.0.0:50052".to_string());

    info!(
        grpc_address = %grpc_addr,
        "Starting gRPC v2 agent server"
    );

    let addr = grpc_addr
        .parse()
        .context("Invalid gRPC address format (expected host:port)")?;

    let server = GrpcAgentServerV2::new("sentinel-js-agent", Box::new(agent));

    info!("JavaScript agent ready and listening on gRPC");

    server
        .run(addr)
        .await
        .context("Failed to run JavaScript agent gRPC server")?;

    Ok(())
}
