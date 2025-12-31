//! Sentinel JavaScript Agent Library
//!
//! A scripting agent for Sentinel reverse proxy that allows custom JavaScript
//! logic to inspect and modify HTTP requests and responses.
//!
//! Uses QuickJS engine for fast, lightweight JavaScript execution.

use anyhow::{Context, Result};
use async_trait::async_trait;
use rquickjs::{Context as JsContext, Function, Object, Runtime, Value};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing::{debug, error, info, warn};

use sentinel_agent_protocol::{
    AgentHandler, AgentResponse, AuditMetadata, HeaderOp, RequestHeadersEvent, ResponseHeadersEvent,
};

/// Result from JavaScript script execution
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScriptResult {
    /// Decision: "allow", "block", "deny", or "redirect"
    pub decision: String,
    /// HTTP status code for block/redirect
    pub status: Option<u16>,
    /// Response body for block, or URL for redirect
    pub body: Option<String>,
    /// Request headers to add
    pub add_request_headers: Option<HashMap<String, String>>,
    /// Request headers to remove
    pub remove_request_headers: Option<Vec<String>>,
    /// Response headers to add
    pub add_response_headers: Option<HashMap<String, String>>,
    /// Response headers to remove
    pub remove_response_headers: Option<Vec<String>>,
    /// Audit tags
    pub tags: Option<Vec<String>>,
}

/// Request data exposed to JavaScript
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsRequest {
    pub method: String,
    pub uri: String,
    pub client_ip: String,
    pub correlation_id: String,
    pub headers: HashMap<String, String>,
}

/// Response data exposed to JavaScript
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsResponse {
    pub status: u16,
    pub correlation_id: String,
    pub headers: HashMap<String, String>,
}

/// JavaScript scripting agent
pub struct JsAgent {
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
    /// Create a new JavaScript agent with the given script file
    pub fn new(script_path: PathBuf, fail_open: bool) -> Result<Self> {
        let script_content = std::fs::read_to_string(&script_path)
            .with_context(|| format!("Failed to read script file: {:?}", script_path))?;

        Self::from_source(script_content, fail_open)
    }

    /// Create a new JavaScript agent from script source code
    pub fn from_source(script_content: String, fail_open: bool) -> Result<Self> {
        let runtime = Runtime::new().context("Failed to create JavaScript runtime")?;

        info!("JavaScript agent initialized");

        Ok(Self {
            runtime: Arc::new(Mutex::new(runtime)),
            script_content,
            fail_open,
        })
    }

    /// Convert serde_json::Value to QuickJS Value
    fn json_to_js<'js>(
        ctx: &rquickjs::Ctx<'js>,
        value: &serde_json::Value,
    ) -> rquickjs::Result<Value<'js>> {
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
    pub fn call_function(
        &self,
        fn_name: &str,
        arg: serde_json::Value,
    ) -> Result<Option<ScriptResult>> {
        let runtime = self
            .runtime
            .lock()
            .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;

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

            let script_result: ScriptResult =
                serde_json::from_value(json_result).map_err(|e| rquickjs::Error::FromJs {
                    from: "object",
                    to: "ScriptResult",
                    message: Some(format!("Failed to parse result: {}", e)),
                })?;

            Ok(Some(script_result))
        })
        .map_err(|e: rquickjs::Error| anyhow::anyhow!("JavaScript error: {}", e))
    }

    /// Build AgentResponse from ScriptResult
    pub fn build_response(result: ScriptResult) -> AgentResponse {
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
