//! Integration tests for the JavaScript agent using AgentHandlerV2 trait.
//!
//! These tests directly invoke the handler methods to verify the JavaScript
//! scripting logic works correctly with the v2 protocol.

use sentinel_agent_js::JsAgent;
use sentinel_agent_protocol::v2::{AgentHandlerV2, DrainReason, ShutdownReason};
use sentinel_agent_protocol::{Decision, EventType, HeaderOp, RequestHeadersEvent, RequestMetadata, ResponseHeadersEvent};
use std::collections::HashMap;

/// Create a basic request metadata
fn make_metadata() -> RequestMetadata {
    let id = uuid::Uuid::new_v4().to_string();
    RequestMetadata {
        correlation_id: id.clone(),
        request_id: id,
        client_ip: "192.168.1.100".to_string(),
        client_port: 54321,
        server_name: Some("test.example.com".to_string()),
        protocol: "HTTP/1.1".to_string(),
        tls_version: Some("TLSv1.3".to_string()),
        tls_cipher: None,
        route_id: Some("default".to_string()),
        upstream_id: None,
        timestamp: "2025-01-01T12:00:00Z".to_string(),
        traceparent: None,
    }
}

/// Create a request headers event
fn make_request_headers(
    method: &str,
    uri: &str,
    headers: HashMap<String, Vec<String>>,
) -> RequestHeadersEvent {
    RequestHeadersEvent {
        metadata: make_metadata(),
        method: method.to_string(),
        uri: uri.to_string(),
        headers,
    }
}

/// Create a response headers event
fn make_response_headers(
    status: u16,
    headers: HashMap<String, Vec<String>>,
) -> ResponseHeadersEvent {
    ResponseHeadersEvent {
        correlation_id: uuid::Uuid::new_v4().to_string(),
        status,
        headers,
    }
}

/// Check if decision is Block
fn is_block(decision: &Decision) -> bool {
    matches!(decision, Decision::Block { .. })
}

/// Check if decision is Allow
fn is_allow(decision: &Decision) -> bool {
    matches!(decision, Decision::Allow)
}

/// Get block status code
fn get_block_status(decision: &Decision) -> Option<u16> {
    match decision {
        Decision::Block { status, .. } => Some(*status),
        _ => None,
    }
}

// ============================================================================
// Capabilities and Metadata Tests
// ============================================================================

#[test]
fn test_capabilities() {
    let script = r#"function on_request_headers(request) { return { decision: "allow" }; }"#;
    let agent = JsAgent::from_source(script.to_string(), false).expect("Failed to create agent");

    let caps = agent.capabilities();
    assert_eq!(caps.agent_id, "sentinel-js-agent");
    assert_eq!(caps.name, "JavaScript Scripting Agent");
    assert!(caps.supports_event(EventType::RequestHeaders));
    assert!(caps.supports_event(EventType::ResponseHeaders));
    assert!(caps.features.config_push);
    assert!(caps.features.metrics_export);
    assert!(caps.features.health_reporting);
}

#[test]
fn test_health_status() {
    let script = r#"function on_request_headers(request) { return { decision: "allow" }; }"#;
    let agent = JsAgent::from_source(script.to_string(), false).expect("Failed to create agent");

    let health = agent.health_status();
    assert!(health.is_healthy());
    assert_eq!(health.agent_id, "sentinel-js-agent");
}

#[test]
fn test_metrics_report() {
    let script = r#"function on_request_headers(request) { return { decision: "allow" }; }"#;
    let agent = JsAgent::from_source(script.to_string(), false).expect("Failed to create agent");

    let report = agent.metrics_report();
    assert!(report.is_some());
    let report = report.unwrap();
    assert_eq!(report.agent_id, "sentinel-js-agent");
    assert!(!report.counters.is_empty());
    assert!(!report.gauges.is_empty());
}

// ============================================================================
// Basic Decision Tests
// ============================================================================

#[tokio::test]
async fn test_allow_decision() {
    let script = r#"
        function on_request_headers(request) {
            return { decision: "allow" };
        }
    "#;

    let agent = JsAgent::from_source(script.to_string(), false).expect("Failed to create agent");
    let event = make_request_headers("GET", "/api/users", HashMap::new());
    let response = agent.on_request_headers(event).await;

    assert!(is_allow(&response.decision), "Expected Allow decision");
}

#[tokio::test]
async fn test_block_decision() {
    let script = r#"
        function on_request_headers(request) {
            return { decision: "block", status: 403, body: "Forbidden" };
        }
    "#;

    let agent = JsAgent::from_source(script.to_string(), false).expect("Failed to create agent");
    let event = make_request_headers("GET", "/admin", HashMap::new());
    let response = agent.on_request_headers(event).await;

    assert!(is_block(&response.decision), "Expected Block decision");
    assert_eq!(get_block_status(&response.decision), Some(403));
}

#[tokio::test]
async fn test_deny_decision() {
    let script = r#"
        function on_request_headers(request) {
            return { decision: "deny", status: 401 };
        }
    "#;

    let agent = JsAgent::from_source(script.to_string(), false).expect("Failed to create agent");
    let event = make_request_headers("GET", "/protected", HashMap::new());
    let response = agent.on_request_headers(event).await;

    assert!(is_block(&response.decision), "Expected Block decision");
    assert_eq!(get_block_status(&response.decision), Some(401));
}

#[tokio::test]
async fn test_redirect_decision() {
    let script = r#"
        function on_request_headers(request) {
            return { decision: "redirect", status: 302, body: "https://login.example.com" };
        }
    "#;

    let agent = JsAgent::from_source(script.to_string(), false).expect("Failed to create agent");
    let event = make_request_headers("GET", "/secure", HashMap::new());
    let response = agent.on_request_headers(event).await;

    assert!(
        is_block(&response.decision),
        "Expected Block decision for redirect"
    );
    assert_eq!(get_block_status(&response.decision), Some(302));

    let has_location = response.response_headers.iter().any(|h| match h {
        HeaderOp::Set { name, value } => name == "Location" && value == "https://login.example.com",
        _ => false,
    });
    assert!(has_location, "Expected Location header");
}

#[tokio::test]
async fn test_default_status_codes() {
    // Block without status should default to 403
    let script = r#"
        function on_request_headers(request) {
            return { decision: "block" };
        }
    "#;

    let agent = JsAgent::from_source(script.to_string(), false).expect("Failed to create agent");
    let event = make_request_headers("GET", "/test", HashMap::new());
    let response = agent.on_request_headers(event).await;

    assert_eq!(get_block_status(&response.decision), Some(403));
}

// ============================================================================
// Request Inspection Tests
// ============================================================================

#[tokio::test]
async fn test_uri_inspection() {
    let script = r#"
        function on_request_headers(request) {
            if (request.uri.includes("/admin")) {
                return { decision: "block", status: 403 };
            }
            return { decision: "allow" };
        }
    "#;

    let agent = JsAgent::from_source(script.to_string(), false).expect("Failed to create agent");

    // Should block admin
    let event = make_request_headers("GET", "/admin/settings", HashMap::new());
    let response = agent.on_request_headers(event).await;
    assert!(
        is_block(&response.decision),
        "Expected admin path to be blocked"
    );

    // Should allow other paths
    let event = make_request_headers("GET", "/api/users", HashMap::new());
    let response = agent.on_request_headers(event).await;
    assert!(
        is_allow(&response.decision),
        "Expected non-admin path to be allowed"
    );
}

#[tokio::test]
async fn test_method_inspection() {
    let script = r#"
        function on_request_headers(request) {
            if (request.method === "DELETE") {
                return { decision: "block", status: 405 };
            }
            return { decision: "allow" };
        }
    "#;

    let agent = JsAgent::from_source(script.to_string(), false).expect("Failed to create agent");

    // Should block DELETE
    let event = make_request_headers("DELETE", "/api/resource", HashMap::new());
    let response = agent.on_request_headers(event).await;
    assert!(
        is_block(&response.decision),
        "Expected DELETE to be blocked"
    );
    assert_eq!(get_block_status(&response.decision), Some(405));

    // Should allow GET
    let event = make_request_headers("GET", "/api/resource", HashMap::new());
    let response = agent.on_request_headers(event).await;
    assert!(is_allow(&response.decision), "Expected GET to be allowed");
}

#[tokio::test]
async fn test_header_inspection() {
    let script = r#"
        function on_request_headers(request) {
            const ua = request.headers["User-Agent"] || "";
            if (ua.includes("BadBot")) {
                return { decision: "block", status: 403 };
            }
            return { decision: "allow" };
        }
    "#;

    let agent = JsAgent::from_source(script.to_string(), false).expect("Failed to create agent");

    // Should block BadBot
    let mut headers = HashMap::new();
    headers.insert("User-Agent".to_string(), vec!["BadBot/1.0".to_string()]);

    let event = make_request_headers("GET", "/api", headers);
    let response = agent.on_request_headers(event).await;
    assert!(
        is_block(&response.decision),
        "Expected BadBot to be blocked"
    );

    // Should allow good user agent
    let mut headers = HashMap::new();
    headers.insert("User-Agent".to_string(), vec!["Mozilla/5.0".to_string()]);

    let event = make_request_headers("GET", "/api", headers);
    let response = agent.on_request_headers(event).await;
    assert!(
        is_allow(&response.decision),
        "Expected Mozilla to be allowed"
    );
}

// ============================================================================
// Header Manipulation Tests
// ============================================================================

#[tokio::test]
async fn test_add_request_headers() {
    let script = r#"
        function on_request_headers(request) {
            return {
                decision: "allow",
                add_request_headers: {
                    "X-Processed-By": "js-agent",
                    "X-Request-Time": "2025-01-01T12:00:00Z"
                }
            };
        }
    "#;

    let agent = JsAgent::from_source(script.to_string(), false).expect("Failed to create agent");
    let event = make_request_headers("GET", "/api", HashMap::new());
    let response = agent.on_request_headers(event).await;

    assert!(is_allow(&response.decision));

    let has_processed_by = response.request_headers.iter().any(|h| match h {
        HeaderOp::Set { name, value } => name == "X-Processed-By" && value == "js-agent",
        _ => false,
    });
    assert!(has_processed_by, "Expected X-Processed-By header");
}

#[tokio::test]
async fn test_remove_request_headers() {
    let script = r#"
        function on_request_headers(request) {
            return {
                decision: "allow",
                remove_request_headers: ["X-Debug", "X-Internal"]
            };
        }
    "#;

    let agent = JsAgent::from_source(script.to_string(), false).expect("Failed to create agent");
    let event = make_request_headers("GET", "/api", HashMap::new());
    let response = agent.on_request_headers(event).await;

    assert!(is_allow(&response.decision));

    let has_remove_debug = response.request_headers.iter().any(|h| match h {
        HeaderOp::Remove { name } => name == "X-Debug",
        _ => false,
    });
    assert!(has_remove_debug, "Expected X-Debug removal");
}

#[tokio::test]
async fn test_add_response_headers() {
    let script = r#"
        function on_request_headers(request) {
            return {
                decision: "allow",
                add_response_headers: {
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY"
                }
            };
        }
    "#;

    let agent = JsAgent::from_source(script.to_string(), false).expect("Failed to create agent");
    let event = make_request_headers("GET", "/api", HashMap::new());
    let response = agent.on_request_headers(event).await;

    assert!(is_allow(&response.decision));

    let has_nosniff = response.response_headers.iter().any(|h| match h {
        HeaderOp::Set { name, value } => name == "X-Content-Type-Options" && value == "nosniff",
        _ => false,
    });
    assert!(has_nosniff, "Expected X-Content-Type-Options header");
}

// ============================================================================
// Response Headers Hook Tests
// ============================================================================

#[tokio::test]
async fn test_response_headers_hook() {
    let script = r#"
        function on_response_headers(response) {
            if (response.status >= 500) {
                return {
                    decision: "allow",
                    add_response_headers: {
                        "X-Error-Logged": "true"
                    }
                };
            }
            return { decision: "allow" };
        }
    "#;

    let agent = JsAgent::from_source(script.to_string(), false).expect("Failed to create agent");

    // 500 error should add header
    let event = make_response_headers(500, HashMap::new());
    let response = agent.on_response_headers(event).await;

    assert!(is_allow(&response.decision));
    let has_error_logged = response.response_headers.iter().any(|h| match h {
        HeaderOp::Set { name, value } => name == "X-Error-Logged" && value == "true",
        _ => false,
    });
    assert!(has_error_logged, "Expected X-Error-Logged header for 500");

    // 200 should not add header
    let event = make_response_headers(200, HashMap::new());
    let response = agent.on_response_headers(event).await;

    assert!(is_allow(&response.decision));
    let has_error_logged = response.response_headers.iter().any(|h| match h {
        HeaderOp::Set { name, .. } => name == "X-Error-Logged",
        _ => false,
    });
    assert!(!has_error_logged, "Should not have X-Error-Logged for 200");
}

// ============================================================================
// Audit Tags Tests
// ============================================================================

#[tokio::test]
async fn test_audit_tags() {
    let script = r#"
        function on_request_headers(request) {
            return {
                decision: "allow",
                tags: ["processed", "logged", "rate-limited"]
            };
        }
    "#;

    let agent = JsAgent::from_source(script.to_string(), false).expect("Failed to create agent");
    let event = make_request_headers("GET", "/api", HashMap::new());
    let response = agent.on_request_headers(event).await;

    assert!(is_allow(&response.decision));

    assert!(response.audit.tags.contains(&"processed".to_string()));
    assert!(response.audit.tags.contains(&"logged".to_string()));
    assert!(response.audit.tags.contains(&"rate-limited".to_string()));
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[tokio::test]
async fn test_undefined_function_allows() {
    // Script without on_request_headers should allow by default
    let script = r#"
        function some_other_function() {
            return { decision: "block" };
        }
    "#;

    let agent = JsAgent::from_source(script.to_string(), false).expect("Failed to create agent");
    let event = make_request_headers("GET", "/api", HashMap::new());
    let response = agent.on_request_headers(event).await;

    assert!(
        is_allow(&response.decision),
        "Expected Allow when function undefined"
    );
}

#[tokio::test]
async fn test_null_return_allows() {
    let script = r#"
        function on_request_headers(request) {
            return null;
        }
    "#;

    let agent = JsAgent::from_source(script.to_string(), false).expect("Failed to create agent");
    let event = make_request_headers("GET", "/api", HashMap::new());
    let response = agent.on_request_headers(event).await;

    assert!(
        is_allow(&response.decision),
        "Expected Allow for null return"
    );
}

#[tokio::test]
async fn test_script_error_blocks_by_default() {
    let script = r#"
        function on_request_headers(request) {
            throw new Error("Script error");
        }
    "#;

    let agent = JsAgent::from_source(script.to_string(), false).expect("Failed to create agent");
    let event = make_request_headers("GET", "/api", HashMap::new());
    let response = agent.on_request_headers(event).await;

    assert!(
        is_block(&response.decision),
        "Expected Block on script error"
    );
    assert_eq!(get_block_status(&response.decision), Some(500));
}

#[tokio::test]
async fn test_script_error_allows_with_fail_open() {
    let script = r#"
        function on_request_headers(request) {
            throw new Error("Script error");
        }
    "#;

    let agent = JsAgent::from_source(script.to_string(), true).expect("Failed to create agent"); // fail_open = true
    let event = make_request_headers("GET", "/api", HashMap::new());
    let response = agent.on_request_headers(event).await;

    assert!(
        is_allow(&response.decision),
        "Expected Allow with fail-open"
    );

    assert!(response.audit.tags.contains(&"js-error".to_string()));
    assert!(response.audit.tags.contains(&"fail-open".to_string()));
}

// ============================================================================
// Configuration Tests
// ============================================================================

#[tokio::test]
async fn test_on_configure() {
    let script = r#"
        function on_request_headers(request) {
            return { decision: "allow" };
        }
    "#;

    let agent = JsAgent::from_source(script.to_string(), false).expect("Failed to create agent");

    // Valid configuration should be accepted
    let config = serde_json::json!({
        "fail-open": true
    });
    let result = agent.on_configure(config, Some("1.0.0".to_string())).await;
    assert!(result, "Expected configuration to be accepted");

    // Invalid configuration should be rejected (note: empty config is valid due to Default trait)
    let config = serde_json::json!("invalid");
    let result = agent.on_configure(config, Some("1.0.0".to_string())).await;
    assert!(!result, "Expected invalid configuration to be rejected");
}

// ============================================================================
// Lifecycle Tests
// ============================================================================

#[tokio::test]
async fn test_on_shutdown() {
    let script = r#"
        function on_request_headers(request) {
            return { decision: "allow" };
        }
    "#;

    let agent = JsAgent::from_source(script.to_string(), false).expect("Failed to create agent");

    // Agent should not be draining initially
    assert!(!agent.is_draining());

    // After shutdown, agent should be draining
    agent.on_shutdown(ShutdownReason::Graceful, 5000).await;
    assert!(agent.is_draining());

    // Health status should reflect draining state
    let health = agent.health_status();
    assert!(!health.is_healthy());
}

#[tokio::test]
async fn test_on_drain() {
    let script = r#"
        function on_request_headers(request) {
            return { decision: "allow" };
        }
    "#;

    let agent = JsAgent::from_source(script.to_string(), false).expect("Failed to create agent");

    // Agent should not be draining initially
    assert!(!agent.is_draining());

    // After drain, agent should be draining
    agent.on_drain(5000, DrainReason::Maintenance).await;
    assert!(agent.is_draining());

    // Requests while draining should still be allowed
    let event = make_request_headers("GET", "/api", HashMap::new());
    let response = agent.on_request_headers(event).await;
    assert!(is_allow(&response.decision), "Expected Allow while draining");
}

// ============================================================================
// Complex Logic Tests
// ============================================================================

#[tokio::test]
async fn test_rate_limit_tier_by_path() {
    let script = r#"
        function on_request_headers(request) {
            let tier = "standard";
            if (request.uri.startsWith("/api/v1/")) {
                tier = "api";
            } else if (request.uri.startsWith("/admin/")) {
                tier = "admin";
            }

            return {
                decision: "allow",
                add_request_headers: {
                    "X-Rate-Limit-Tier": tier
                }
            };
        }
    "#;

    let agent = JsAgent::from_source(script.to_string(), false).expect("Failed to create agent");

    // API path
    let event = make_request_headers("GET", "/api/v1/users", HashMap::new());
    let response = agent.on_request_headers(event).await;

    let has_api_tier = response.request_headers.iter().any(|h| match h {
        HeaderOp::Set { name, value } => name == "X-Rate-Limit-Tier" && value == "api",
        _ => false,
    });
    assert!(has_api_tier, "Expected API tier for /api/v1/ path");

    // Admin path
    let event = make_request_headers("GET", "/admin/dashboard", HashMap::new());
    let response = agent.on_request_headers(event).await;

    let has_admin_tier = response.request_headers.iter().any(|h| match h {
        HeaderOp::Set { name, value } => name == "X-Rate-Limit-Tier" && value == "admin",
        _ => false,
    });
    assert!(has_admin_tier, "Expected admin tier for /admin/ path");

    // Standard path
    let event = make_request_headers("GET", "/public/page", HashMap::new());
    let response = agent.on_request_headers(event).await;

    let has_standard_tier = response.request_headers.iter().any(|h| match h {
        HeaderOp::Set { name, value } => name == "X-Rate-Limit-Tier" && value == "standard",
        _ => false,
    });
    assert!(has_standard_tier, "Expected standard tier for other paths");
}

#[tokio::test]
async fn test_authentication_required() {
    let script = r#"
        function on_request_headers(request) {
            // Skip for public paths
            if (request.uri.startsWith("/public/") || request.uri === "/health") {
                return { decision: "allow" };
            }

            // Check for auth header
            if (!request.headers["Authorization"]) {
                return {
                    decision: "block",
                    status: 401,
                    body: "Authentication required"
                };
            }

            return { decision: "allow" };
        }
    "#;

    let agent = JsAgent::from_source(script.to_string(), false).expect("Failed to create agent");

    // Public path - should allow without auth
    let event = make_request_headers("GET", "/public/page", HashMap::new());
    let response = agent.on_request_headers(event).await;
    assert!(
        is_allow(&response.decision),
        "Expected public path to be allowed"
    );

    // Health endpoint - should allow without auth
    let event = make_request_headers("GET", "/health", HashMap::new());
    let response = agent.on_request_headers(event).await;
    assert!(
        is_allow(&response.decision),
        "Expected health to be allowed"
    );

    // Protected path without auth - should block
    let event = make_request_headers("GET", "/api/users", HashMap::new());
    let response = agent.on_request_headers(event).await;
    assert!(
        is_block(&response.decision),
        "Expected protected path to be blocked without auth"
    );
    assert_eq!(get_block_status(&response.decision), Some(401));

    // Protected path with auth - should allow
    let mut headers = HashMap::new();
    headers.insert(
        "Authorization".to_string(),
        vec!["Bearer token123".to_string()],
    );
    let event = make_request_headers("GET", "/api/users", headers);
    let response = agent.on_request_headers(event).await;
    assert!(
        is_allow(&response.decision),
        "Expected protected path with auth to be allowed"
    );
}

#[tokio::test]
async fn test_scanner_detection() {
    let script = r#"
        function on_request_headers(request) {
            const ua = (request.headers["User-Agent"] || "").toLowerCase();
            const badBots = ["sqlmap", "nikto", "nessus", "masscan"];

            for (const bot of badBots) {
                if (ua.includes(bot)) {
                    return {
                        decision: "block",
                        status: 403,
                        tags: ["bot-blocked", bot]
                    };
                }
            }
            return { decision: "allow" };
        }
    "#;

    let agent = JsAgent::from_source(script.to_string(), false).expect("Failed to create agent");

    // SQLMap should be blocked
    let mut headers = HashMap::new();
    headers.insert("User-Agent".to_string(), vec!["sqlmap/1.0".to_string()]);
    let event = make_request_headers("GET", "/api", headers);
    let response = agent.on_request_headers(event).await;
    assert!(
        is_block(&response.decision),
        "Expected sqlmap to be blocked"
    );

    // Nikto should be blocked
    let mut headers = HashMap::new();
    headers.insert("User-Agent".to_string(), vec!["Nikto/2.1".to_string()]);
    let event = make_request_headers("GET", "/api", headers);
    let response = agent.on_request_headers(event).await;
    assert!(is_block(&response.decision), "Expected Nikto to be blocked");

    // Normal browser should be allowed
    let mut headers = HashMap::new();
    headers.insert(
        "User-Agent".to_string(),
        vec!["Mozilla/5.0 Chrome/100".to_string()],
    );
    let event = make_request_headers("GET", "/api", headers);
    let response = agent.on_request_headers(event).await;
    assert!(
        is_allow(&response.decision),
        "Expected normal browser to be allowed"
    );
}

#[tokio::test]
async fn test_security_headers_for_html() {
    let script = r#"
        function on_response_headers(response) {
            const contentType = response.headers["Content-Type"] || "";

            if (contentType.includes("text/html")) {
                return {
                    decision: "allow",
                    add_response_headers: {
                        "X-Content-Type-Options": "nosniff",
                        "X-Frame-Options": "DENY",
                        "X-XSS-Protection": "1; mode=block",
                        "Referrer-Policy": "strict-origin-when-cross-origin"
                    }
                };
            }

            return { decision: "allow" };
        }
    "#;

    let agent = JsAgent::from_source(script.to_string(), false).expect("Failed to create agent");

    // HTML response should get security headers
    let mut headers = HashMap::new();
    headers.insert(
        "Content-Type".to_string(),
        vec!["text/html; charset=utf-8".to_string()],
    );
    let event = make_response_headers(200, headers);
    let response = agent.on_response_headers(event).await;

    assert!(is_allow(&response.decision));
    assert_eq!(response.response_headers.len(), 4);

    // JSON response should not get security headers
    let mut headers = HashMap::new();
    headers.insert(
        "Content-Type".to_string(),
        vec!["application/json".to_string()],
    );
    let event = make_response_headers(200, headers);
    let response = agent.on_response_headers(event).await;

    assert!(is_allow(&response.decision));
    assert!(response.response_headers.is_empty());
}
