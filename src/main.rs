//! Sentinel JavaScript Agent
//!
//! A scripting agent for Sentinel reverse proxy that allows custom JavaScript
//! logic to inspect and modify HTTP requests and responses.
//!
//! Uses QuickJS engine for fast, lightweight JavaScript execution.
//!
//! # Example Script
//!
//! ```javascript
//! function on_request_headers(request) {
//!     if (request.uri.includes("/admin")) {
//!         return { decision: "block", status: 403, body: "Forbidden" };
//!     }
//!     return { decision: "allow" };
//! }
//! ```

use anyhow::{Context, Result};
use async_trait::async_trait;
use clap::Parser;
use rquickjs::{Context as JsContext, Function, Object, Runtime, Value};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing::{debug, error, info, warn};

use sentinel_agent_protocol::{
    AgentHandler, AgentResponse, AgentServer, AuditMetadata, HeaderOp, RequestHeadersEvent,
    ResponseHeadersEvent,
};

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

/// Result from JavaScript script execution
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ScriptResult {
    /// Decision: "allow", "block", "deny", or "redirect"
    decision: String,
    /// HTTP status code for block/redirect
    status: Option<u16>,
    /// Response body for block, or URL for redirect
    body: Option<String>,
    /// Request headers to add
    add_request_headers: Option<HashMap<String, String>>,
    /// Request headers to remove
    remove_request_headers: Option<Vec<String>>,
    /// Response headers to add
    add_response_headers: Option<HashMap<String, String>>,
    /// Response headers to remove
    remove_response_headers: Option<Vec<String>>,
    /// Audit tags
    tags: Option<Vec<String>>,
}

/// Request data exposed to JavaScript
#[derive(Debug, Clone, Serialize, Deserialize)]
struct JsRequest {
    method: String,
    uri: String,
    client_ip: String,
    correlation_id: String,
    headers: HashMap<String, String>,
}

/// Response data exposed to JavaScript
#[derive(Debug, Clone, Serialize, Deserialize)]
struct JsResponse {
    status: u16,
    correlation_id: String,
    headers: HashMap<String, String>,
}

/// JavaScript scripting agent
struct JsAgent {
    /// JavaScript runtime
    runtime: Arc<Mutex<Runtime>>,
    /// Script content
    script_content: String,
    /// Whether to fail open on errors
    fail_open: bool,
}

// Safety: We protect the runtime with a Mutex
unsafe impl Send for JsAgent {}
unsafe impl Sync for JsAgent {}

impl JsAgent {
    /// Create a new JavaScript agent with the given script
    fn new(script_path: PathBuf, fail_open: bool) -> Result<Self> {
        // Read script file
        let script_content = std::fs::read_to_string(&script_path)
            .with_context(|| format!("Failed to read script file: {:?}", script_path))?;

        // Create JavaScript runtime
        let runtime = Runtime::new().context("Failed to create JavaScript runtime")?;

        info!(script = ?script_path, "JavaScript agent initialized");

        Ok(Self {
            runtime: Arc::new(Mutex::new(runtime)),
            script_content,
            fail_open,
        })
    }

    /// Convert serde_json::Value to QuickJS Value
    fn json_to_js<'js>(ctx: &rquickjs::Ctx<'js>, value: &serde_json::Value) -> rquickjs::Result<Value<'js>> {
        match value {
            serde_json::Value::Null => Ok(Value::new_null(ctx.clone())),
            serde_json::Value::Bool(b) => Ok(Value::new_bool(ctx.clone(), *b)),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Ok(Value::new_int(ctx.clone(), i as i32))
                } else if let Some(f) = n.as_f64() {
                    Ok(Value::new_float(ctx.clone(), f))
                } else {
                    Ok(Value::new_int(ctx.clone(), 0))
                }
            }
            serde_json::Value::String(s) => {
                rquickjs::String::from_str(ctx.clone(), s).map(|s| s.into())
            }
            serde_json::Value::Array(arr) => {
                let js_array = rquickjs::Array::new(ctx.clone())?;
                for (i, item) in arr.iter().enumerate() {
                    let js_item = Self::json_to_js(ctx, item)?;
                    js_array.set(i, js_item)?;
                }
                Ok(js_array.into())
            }
            serde_json::Value::Object(obj) => {
                let js_obj = Object::new(ctx.clone())?;
                for (key, val) in obj {
                    let js_val = Self::json_to_js(ctx, val)?;
                    js_obj.set(key.as_str(), js_val)?;
                }
                Ok(js_obj.into())
            }
        }
    }

    /// Convert QuickJS Value to serde_json::Value
    fn js_to_json(value: &Value) -> serde_json::Value {
        if value.is_null() || value.is_undefined() {
            serde_json::Value::Null
        } else if let Some(b) = value.as_bool() {
            serde_json::Value::Bool(b)
        } else if let Some(i) = value.as_int() {
            serde_json::json!(i)
        } else if let Some(f) = value.as_float() {
            serde_json::json!(f)
        } else if let Some(s) = value.clone().into_string() {
            if let Ok(rust_str) = s.to_string() {
                serde_json::Value::String(rust_str)
            } else {
                serde_json::Value::Null
            }
        } else if let Some(arr) = value.clone().into_array() {
            let mut vec = Vec::new();
            for i in 0..arr.len() {
                if let Ok(item) = arr.get::<Value>(i) {
                    vec.push(Self::js_to_json(&item));
                }
            }
            serde_json::Value::Array(vec)
        } else if let Some(obj) = value.clone().into_object() {
            let mut map = serde_json::Map::new();
            for key in obj.keys::<String>().flatten() {
                if let Ok(val) = obj.get::<_, Value>(&key) {
                    map.insert(key, Self::js_to_json(&val));
                }
            }
            serde_json::Value::Object(map)
        } else {
            serde_json::Value::Null
        }
    }

    /// Execute a JavaScript function
    fn call_function(&self, fn_name: &str, arg: serde_json::Value) -> Result<Option<ScriptResult>> {
        let runtime = self.runtime.lock().map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;

        let ctx = JsContext::full(&runtime).context("Failed to create JS context")?;

        ctx.with(|ctx| {
            // Set up console object
            let console = Object::new(ctx.clone())?;

            let log_fn = Function::new(ctx.clone(), |args: rquickjs::function::Rest<Value>| {
                let msg: Vec<String> = args.iter().map(|v| format!("{:?}", v)).collect();
                info!(target: "js_console", "{}", msg.join(" "));
            })?;
            console.set("log", log_fn)?;

            let warn_fn = Function::new(ctx.clone(), |args: rquickjs::function::Rest<Value>| {
                let msg: Vec<String> = args.iter().map(|v| format!("{:?}", v)).collect();
                warn!(target: "js_console", "{}", msg.join(" "));
            })?;
            console.set("warn", warn_fn)?;

            let error_fn = Function::new(ctx.clone(), |args: rquickjs::function::Rest<Value>| {
                let msg: Vec<String> = args.iter().map(|v| format!("{:?}", v)).collect();
                error!(target: "js_console", "{}", msg.join(" "));
            })?;
            console.set("error", error_fn)?;

            let globals = ctx.globals();
            globals.set("console", console)?;

            // Execute the script to define functions
            ctx.eval::<(), _>(self.script_content.as_str())?;

            // Check if function exists
            let func: Option<Function> = globals.get(fn_name).ok();

            let Some(func) = func else {
                debug!(function = fn_name, "Function not defined in script");
                return Ok(None);
            };

            // Convert argument to JS value
            let js_arg = Self::json_to_js(&ctx, &arg)?;

            // Call the function
            let result: Value = func.call((js_arg,))?;

            // Convert result to ScriptResult
            let json_result = Self::js_to_json(&result);

            if json_result.is_null() {
                return Ok(Some(ScriptResult {
                    decision: "allow".to_string(),
                    ..Default::default()
                }));
            }

            let script_result: ScriptResult = serde_json::from_value(json_result)
                .map_err(|e| rquickjs::Error::FromJs {
                    from: "object",
                    to: "ScriptResult",
                    message: Some(format!("Failed to parse result: {}", e)),
                })?;

            Ok(Some(script_result))
        })
        .map_err(|e: rquickjs::Error| anyhow::anyhow!("JavaScript error: {}", e))
    }

    /// Build AgentResponse from ScriptResult
    fn build_response(result: ScriptResult) -> AgentResponse {
        let decision = result.decision.to_lowercase();

        let mut response = match decision.as_str() {
            "block" | "deny" => {
                let status = result.status.unwrap_or(403);
                AgentResponse::block(status, result.body)
            }
            "redirect" => {
                let status = result.status.unwrap_or(302);
                let mut resp = AgentResponse::block(status, None);
                if let Some(url) = result.body {
                    resp = resp.add_response_header(HeaderOp::Set {
                        name: "Location".to_string(),
                        value: url,
                    });
                }
                resp
            }
            _ => AgentResponse::default_allow(),
        };

        // Add request headers
        if let Some(headers) = result.add_request_headers {
            for (name, value) in headers {
                response = response.add_request_header(HeaderOp::Set { name, value });
            }
        }

        // Remove request headers
        if let Some(headers) = result.remove_request_headers {
            for name in headers {
                response = response.add_request_header(HeaderOp::Remove { name });
            }
        }

        // Add response headers
        if let Some(headers) = result.add_response_headers {
            for (name, value) in headers {
                response = response.add_response_header(HeaderOp::Set { name, value });
            }
        }

        // Remove response headers
        if let Some(headers) = result.remove_response_headers {
            for name in headers {
                response = response.add_response_header(HeaderOp::Remove { name });
            }
        }

        // Add audit tags
        if let Some(tags) = result.tags {
            response = response.with_audit(AuditMetadata {
                tags,
                ..Default::default()
            });
        }

        response
    }

    /// Handle script error
    fn handle_error(&self, error: anyhow::Error, correlation_id: &str) -> AgentResponse {
        error!(
            correlation_id = correlation_id,
            error = %error,
            "Script execution failed"
        );

        if self.fail_open {
            AgentResponse::default_allow().with_audit(AuditMetadata {
                tags: vec!["js-error".to_string(), "fail-open".to_string()],
                reason_codes: vec![error.to_string()],
                ..Default::default()
            })
        } else {
            AgentResponse::block(500, Some("Script Error".to_string())).with_audit(AuditMetadata {
                tags: vec!["js-error".to_string()],
                reason_codes: vec![error.to_string()],
                ..Default::default()
            })
        }
    }
}

#[async_trait]
impl AgentHandler for JsAgent {
    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        let correlation_id = event.metadata.correlation_id.clone();

        // Build request object for JavaScript
        let mut headers: HashMap<String, String> = HashMap::new();
        for (name, values) in &event.headers {
            headers.insert(name.clone(), values.join(", "));
        }

        let request = JsRequest {
            method: event.method.clone(),
            uri: event.uri.clone(),
            client_ip: event.metadata.client_ip.clone(),
            correlation_id: correlation_id.clone(),
            headers,
        };

        let request_json = match serde_json::to_value(&request) {
            Ok(v) => v,
            Err(e) => return self.handle_error(e.into(), &correlation_id),
        };

        // Call JavaScript function (blocking - QuickJS is fast)
        let result = self.call_function("on_request_headers", request_json);

        match result {
            Ok(Some(script_result)) => {
                debug!(
                    correlation_id = correlation_id,
                    decision = script_result.decision,
                    "Script returned result"
                );
                Self::build_response(script_result)
            }
            Ok(None) => {
                // Function not defined, allow by default
                AgentResponse::default_allow()
            }
            Err(e) => self.handle_error(e, &correlation_id),
        }
    }

    async fn on_response_headers(&self, event: ResponseHeadersEvent) -> AgentResponse {
        let correlation_id = event.correlation_id.clone();

        // Build response object for JavaScript
        let mut headers: HashMap<String, String> = HashMap::new();
        for (name, values) in &event.headers {
            headers.insert(name.clone(), values.join(", "));
        }

        let response = JsResponse {
            status: event.status,
            correlation_id: correlation_id.clone(),
            headers,
        };

        let response_json = match serde_json::to_value(&response) {
            Ok(v) => v,
            Err(e) => return self.handle_error(e.into(), &correlation_id),
        };

        // Call JavaScript function
        let result = self.call_function("on_response_headers", response_json);

        match result {
            Ok(Some(script_result)) => {
                debug!(
                    correlation_id = correlation_id,
                    decision = script_result.decision,
                    "Script returned result"
                );
                Self::build_response(script_result)
            }
            Ok(None) => AgentResponse::default_allow(),
            Err(e) => self.handle_error(e, &correlation_id),
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_agent_protocol::{AgentClient, EventType, RequestMetadata};
    use std::io::Write;
    use tempfile::tempdir;
    use tokio::time::Duration;

    fn make_metadata() -> RequestMetadata {
        let id = uuid::Uuid::new_v4().to_string();
        RequestMetadata {
            correlation_id: id.clone(),
            request_id: id,
            client_ip: "127.0.0.1".to_string(),
            client_port: 12345,
            server_name: Some("example.com".to_string()),
            protocol: "HTTP/1.1".to_string(),
            tls_version: None,
            tls_cipher: None,
            route_id: Some("default".to_string()),
            upstream_id: None,
            timestamp: "2025-01-01T00:00:00Z".to_string(),
        }
    }

    async fn start_test_server(
        script: &str,
    ) -> (tempfile::TempDir, std::path::PathBuf, tempfile::TempDir) {
        let script_dir = tempdir().expect("Failed to create script dir");
        let script_path = script_dir.path().join("test.js");
        let mut file = std::fs::File::create(&script_path).expect("Failed to create script file");
        file.write_all(script.as_bytes())
            .expect("Failed to write script");

        let socket_dir = tempdir().expect("Failed to create socket dir");
        let socket_path = socket_dir.path().join("test.sock");

        let agent = JsAgent::new(script_path, false).expect("Failed to create agent");
        let server = AgentServer::new("test-js", socket_path.clone(), Box::new(agent));

        tokio::spawn(async move {
            let _ = server.run().await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        (script_dir, socket_path, socket_dir)
    }

    #[tokio::test]
    async fn test_allow_script() {
        let script = r#"
            function on_request_headers(request) {
                return { decision: "allow" };
            }
        "#;

        let (_script_dir, socket_path, _socket_dir) = start_test_server(script).await;

        let mut client = AgentClient::unix_socket("test", &socket_path, Duration::from_secs(5))
            .await
            .expect("Failed to connect");

        let event = RequestHeadersEvent {
            metadata: make_metadata(),
            method: "GET".to_string(),
            uri: "/api/users".to_string(),
            headers: HashMap::new(),
        };

        let response = client
            .send_event(EventType::RequestHeaders, &event)
            .await
            .expect("Failed to send event");

        assert!(matches!(
            response.decision,
            sentinel_agent_protocol::Decision::Allow
        ));
    }

    #[tokio::test]
    async fn test_block_script() {
        let script = r#"
            function on_request_headers(request) {
                if (request.uri.includes("/admin")) {
                    return { decision: "block", status: 403, body: "Forbidden" };
                }
                return { decision: "allow" };
            }
        "#;

        let (_script_dir, socket_path, _socket_dir) = start_test_server(script).await;

        let mut client = AgentClient::unix_socket("test", &socket_path, Duration::from_secs(5))
            .await
            .expect("Failed to connect");

        // Test blocked request
        let event = RequestHeadersEvent {
            metadata: make_metadata(),
            method: "GET".to_string(),
            uri: "/admin/settings".to_string(),
            headers: HashMap::new(),
        };

        let response = client
            .send_event(EventType::RequestHeaders, &event)
            .await
            .expect("Failed to send event");

        assert!(matches!(
            response.decision,
            sentinel_agent_protocol::Decision::Block { status: 403, .. }
        ));
    }

    #[tokio::test]
    async fn test_add_headers_script() {
        let script = r#"
            function on_request_headers(request) {
                return {
                    decision: "allow",
                    add_request_headers: {
                        "X-Custom-Header": "custom-value"
                    }
                };
            }
        "#;

        let (_script_dir, socket_path, _socket_dir) = start_test_server(script).await;

        let mut client = AgentClient::unix_socket("test", &socket_path, Duration::from_secs(5))
            .await
            .expect("Failed to connect");

        let event = RequestHeadersEvent {
            metadata: make_metadata(),
            method: "GET".to_string(),
            uri: "/api".to_string(),
            headers: HashMap::new(),
        };

        let response = client
            .send_event(EventType::RequestHeaders, &event)
            .await
            .expect("Failed to send event");

        assert!(matches!(
            response.decision,
            sentinel_agent_protocol::Decision::Allow
        ));

        let has_header = response.request_headers.iter().any(|h| match h {
            HeaderOp::Set { name, value } => {
                name == "X-Custom-Header" && value == "custom-value"
            }
            _ => false,
        });
        assert!(has_header, "Expected X-Custom-Header to be added");
    }

    #[tokio::test]
    async fn test_console_log() {
        let script = r#"
            function on_request_headers(request) {
                console.log("Processing request:", request.uri);
                console.warn("This is a warning");
                console.error("This is an error");
                return { decision: "allow" };
            }
        "#;

        let (_script_dir, socket_path, _socket_dir) = start_test_server(script).await;

        let mut client = AgentClient::unix_socket("test", &socket_path, Duration::from_secs(5))
            .await
            .expect("Failed to connect");

        let event = RequestHeadersEvent {
            metadata: make_metadata(),
            method: "GET".to_string(),
            uri: "/test".to_string(),
            headers: HashMap::new(),
        };

        let response = client
            .send_event(EventType::RequestHeaders, &event)
            .await
            .expect("Failed to send event");

        assert!(matches!(
            response.decision,
            sentinel_agent_protocol::Decision::Allow
        ));
    }

    #[tokio::test]
    async fn test_header_inspection() {
        let script = r#"
            function on_request_headers(request) {
                if (request.headers["User-Agent"] &&
                    request.headers["User-Agent"].includes("BadBot")) {
                    return { decision: "block", status: 403 };
                }
                return { decision: "allow" };
            }
        "#;

        let (_script_dir, socket_path, _socket_dir) = start_test_server(script).await;

        let mut client = AgentClient::unix_socket("test", &socket_path, Duration::from_secs(5))
            .await
            .expect("Failed to connect");

        let mut headers = HashMap::new();
        headers.insert("User-Agent".to_string(), vec!["BadBot/1.0".to_string()]);

        let event = RequestHeadersEvent {
            metadata: make_metadata(),
            method: "GET".to_string(),
            uri: "/api".to_string(),
            headers,
        };

        let response = client
            .send_event(EventType::RequestHeaders, &event)
            .await
            .expect("Failed to send event");

        assert!(matches!(
            response.decision,
            sentinel_agent_protocol::Decision::Block { status: 403, .. }
        ));
    }
}
