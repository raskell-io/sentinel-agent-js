//! Integration tests for the JavaScript agent using sentinel-agent-protocol.
//!
//! These tests spin up an actual AgentServer and connect via AgentClient
//! to verify the full protocol flow.

use sentinel_agent_js::JsAgent;
use sentinel_agent_protocol::{
    AgentClient, AgentServer, Decision, EventType, HeaderOp, RequestHeadersEvent, RequestMetadata,
    ResponseHeadersEvent,
};
use std::collections::HashMap;
use std::time::Duration;
use tempfile::tempdir;

/// Helper to start a JS agent server with given script and return the socket path
async fn start_test_server(script: &str, fail_open: bool) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempdir().expect("Failed to create temp dir");
    let socket_path = dir.path().join("js-test.sock");

    let agent = JsAgent::from_source(script.to_string(), fail_open).expect("Failed to create agent");
    let server = AgentServer::new("test-js", socket_path.clone(), Box::new(agent));

    tokio::spawn(async move {
        let _ = server.run().await;
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    (dir, socket_path)
}

/// Create a client connected to the test server
async fn create_client(socket_path: &std::path::Path) -> AgentClient {
    AgentClient::unix_socket("test-client", socket_path, Duration::from_secs(5))
        .await
        .expect("Failed to connect to agent")
}

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
// Basic Decision Tests
// ============================================================================

#[tokio::test]
async fn test_allow_decision() {
    let script = r#"
        function on_request_headers(request) {
            return { decision: "allow" };
        }
    "#;

    let (_dir, socket_path) = start_test_server(script, false).await;
    let mut client = create_client(&socket_path).await;

    let event = make_request_headers("GET", "/api/users", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_allow(&response.decision), "Expected Allow decision");
}

#[tokio::test]
async fn test_block_decision() {
    let script = r#"
        function on_request_headers(request) {
            return { decision: "block", status: 403, body: "Forbidden" };
        }
    "#;

    let (_dir, socket_path) = start_test_server(script, false).await;
    let mut client = create_client(&socket_path).await;

    let event = make_request_headers("GET", "/admin", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

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

    let (_dir, socket_path) = start_test_server(script, false).await;
    let mut client = create_client(&socket_path).await;

    let event = make_request_headers("GET", "/protected", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

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

    let (_dir, socket_path) = start_test_server(script, false).await;
    let mut client = create_client(&socket_path).await;

    let event = make_request_headers("GET", "/secure", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision), "Expected Block decision for redirect");
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

    let (_dir, socket_path) = start_test_server(script, false).await;
    let mut client = create_client(&socket_path).await;

    let event = make_request_headers("GET", "/test", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

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

    let (_dir, socket_path) = start_test_server(script, false).await;
    let mut client = create_client(&socket_path).await;

    // Should block admin
    let event = make_request_headers("GET", "/admin/settings", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");
    assert!(is_block(&response.decision), "Expected admin path to be blocked");

    // Should allow other paths
    let event = make_request_headers("GET", "/api/users", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");
    assert!(is_allow(&response.decision), "Expected non-admin path to be allowed");
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

    let (_dir, socket_path) = start_test_server(script, false).await;
    let mut client = create_client(&socket_path).await;

    // Should block DELETE
    let event = make_request_headers("DELETE", "/api/resource", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");
    assert!(is_block(&response.decision), "Expected DELETE to be blocked");
    assert_eq!(get_block_status(&response.decision), Some(405));

    // Should allow GET
    let event = make_request_headers("GET", "/api/resource", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");
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

    let (_dir, socket_path) = start_test_server(script, false).await;
    let mut client = create_client(&socket_path).await;

    // Should block BadBot
    let mut headers = HashMap::new();
    headers.insert("User-Agent".to_string(), vec!["BadBot/1.0".to_string()]);

    let event = make_request_headers("GET", "/api", headers);
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");
    assert!(is_block(&response.decision), "Expected BadBot to be blocked");

    // Should allow good user agent
    let mut headers = HashMap::new();
    headers.insert("User-Agent".to_string(), vec!["Mozilla/5.0".to_string()]);

    let event = make_request_headers("GET", "/api", headers);
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");
    assert!(is_allow(&response.decision), "Expected Mozilla to be allowed");
}

#[tokio::test]
async fn test_client_ip_inspection() {
    let script = r#"
        function on_request_headers(request) {
            if (request.client_ip.startsWith("10.")) {
                return { decision: "block", status: 403, body: "Internal network blocked" };
            }
            return { decision: "allow" };
        }
    "#;

    let (_dir, socket_path) = start_test_server(script, false).await;
    let mut client = create_client(&socket_path).await;

    // Our test uses 192.168.1.100, so should be allowed
    let event = make_request_headers("GET", "/api", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");
    assert!(is_allow(&response.decision), "Expected 192.168.x to be allowed");
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

    let (_dir, socket_path) = start_test_server(script, false).await;
    let mut client = create_client(&socket_path).await;

    let event = make_request_headers("GET", "/api", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_allow(&response.decision));

    let has_processed_by = response.request_headers.iter().any(|h| match h {
        HeaderOp::Set { name, value } => name == "X-Processed-By" && value == "js-agent",
        _ => false,
    });
    assert!(has_processed_by, "Expected X-Processed-By header");

    let has_request_time = response.request_headers.iter().any(|h| match h {
        HeaderOp::Set { name, .. } => name == "X-Request-Time",
        _ => false,
    });
    assert!(has_request_time, "Expected X-Request-Time header");
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

    let (_dir, socket_path) = start_test_server(script, false).await;
    let mut client = create_client(&socket_path).await;

    let event = make_request_headers("GET", "/api", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_allow(&response.decision));

    let has_remove_debug = response.request_headers.iter().any(|h| match h {
        HeaderOp::Remove { name } => name == "X-Debug",
        _ => false,
    });
    assert!(has_remove_debug, "Expected X-Debug removal");

    let has_remove_internal = response.request_headers.iter().any(|h| match h {
        HeaderOp::Remove { name } => name == "X-Internal",
        _ => false,
    });
    assert!(has_remove_internal, "Expected X-Internal removal");
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

    let (_dir, socket_path) = start_test_server(script, false).await;
    let mut client = create_client(&socket_path).await;

    let event = make_request_headers("GET", "/api", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_allow(&response.decision));

    let has_nosniff = response.response_headers.iter().any(|h| match h {
        HeaderOp::Set { name, value } => name == "X-Content-Type-Options" && value == "nosniff",
        _ => false,
    });
    assert!(has_nosniff, "Expected X-Content-Type-Options header");

    let has_frame = response.response_headers.iter().any(|h| match h {
        HeaderOp::Set { name, value } => name == "X-Frame-Options" && value == "DENY",
        _ => false,
    });
    assert!(has_frame, "Expected X-Frame-Options header");
}

#[tokio::test]
async fn test_remove_response_headers() {
    let script = r#"
        function on_request_headers(request) {
            return {
                decision: "allow",
                remove_response_headers: ["Server", "X-Powered-By"]
            };
        }
    "#;

    let (_dir, socket_path) = start_test_server(script, false).await;
    let mut client = create_client(&socket_path).await;

    let event = make_request_headers("GET", "/api", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_allow(&response.decision));

    let has_remove_server = response.response_headers.iter().any(|h| match h {
        HeaderOp::Remove { name } => name == "Server",
        _ => false,
    });
    assert!(has_remove_server, "Expected Server removal");
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

    let (_dir, socket_path) = start_test_server(script, false).await;
    let mut client = create_client(&socket_path).await;

    // 500 error should add header
    let event = make_response_headers(500, HashMap::new());
    let response = client
        .send_event(EventType::ResponseHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_allow(&response.decision));
    let has_error_logged = response.response_headers.iter().any(|h| match h {
        HeaderOp::Set { name, value } => name == "X-Error-Logged" && value == "true",
        _ => false,
    });
    assert!(has_error_logged, "Expected X-Error-Logged header for 500");

    // 200 should not add header
    let event = make_response_headers(200, HashMap::new());
    let response = client
        .send_event(EventType::ResponseHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_allow(&response.decision));
    let has_error_logged = response.response_headers.iter().any(|h| match h {
        HeaderOp::Set { name, .. } => name == "X-Error-Logged",
        _ => false,
    });
    assert!(!has_error_logged, "Should not have X-Error-Logged for 200");
}

#[tokio::test]
async fn test_response_headers_inspection() {
    let script = r#"
        function on_response_headers(response) {
            const contentType = response.headers["Content-Type"] || "";
            if (contentType.includes("text/html")) {
                return {
                    decision: "allow",
                    add_response_headers: {
                        "Content-Security-Policy": "default-src 'self'"
                    }
                };
            }
            return { decision: "allow" };
        }
    "#;

    let (_dir, socket_path) = start_test_server(script, false).await;
    let mut client = create_client(&socket_path).await;

    let mut headers = HashMap::new();
    headers.insert("Content-Type".to_string(), vec!["text/html".to_string()]);

    let event = make_response_headers(200, headers);
    let response = client
        .send_event(EventType::ResponseHeaders, &event)
        .await
        .expect("Failed to send event");

    let has_csp = response.response_headers.iter().any(|h| match h {
        HeaderOp::Set { name, .. } => name == "Content-Security-Policy",
        _ => false,
    });
    assert!(has_csp, "Expected CSP header for HTML content");
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

    let (_dir, socket_path) = start_test_server(script, false).await;
    let mut client = create_client(&socket_path).await;

    let event = make_request_headers("GET", "/api", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

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

    let (_dir, socket_path) = start_test_server(script, false).await;
    let mut client = create_client(&socket_path).await;

    let event = make_request_headers("GET", "/api", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_allow(&response.decision), "Expected Allow when function undefined");
}

#[tokio::test]
async fn test_null_return_allows() {
    let script = r#"
        function on_request_headers(request) {
            return null;
        }
    "#;

    let (_dir, socket_path) = start_test_server(script, false).await;
    let mut client = create_client(&socket_path).await;

    let event = make_request_headers("GET", "/api", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_allow(&response.decision), "Expected Allow for null return");
}

#[tokio::test]
async fn test_script_error_blocks_by_default() {
    let script = r#"
        function on_request_headers(request) {
            throw new Error("Script error");
        }
    "#;

    let (_dir, socket_path) = start_test_server(script, false).await;
    let mut client = create_client(&socket_path).await;

    let event = make_request_headers("GET", "/api", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision), "Expected Block on script error");
    assert_eq!(get_block_status(&response.decision), Some(500));
}

#[tokio::test]
async fn test_script_error_allows_with_fail_open() {
    let script = r#"
        function on_request_headers(request) {
            throw new Error("Script error");
        }
    "#;

    let (_dir, socket_path) = start_test_server(script, true).await; // fail_open = true
    let mut client = create_client(&socket_path).await;

    let event = make_request_headers("GET", "/api", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_allow(&response.decision), "Expected Allow with fail-open");

    assert!(response.audit.tags.contains(&"js-error".to_string()));
    assert!(response.audit.tags.contains(&"fail-open".to_string()));
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

    let (_dir, socket_path) = start_test_server(script, false).await;
    let mut client = create_client(&socket_path).await;

    // API path
    let event = make_request_headers("GET", "/api/v1/users", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    let has_api_tier = response.request_headers.iter().any(|h| match h {
        HeaderOp::Set { name, value } => name == "X-Rate-Limit-Tier" && value == "api",
        _ => false,
    });
    assert!(has_api_tier, "Expected API tier for /api/v1/ path");

    // Admin path
    let event = make_request_headers("GET", "/admin/dashboard", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    let has_admin_tier = response.request_headers.iter().any(|h| match h {
        HeaderOp::Set { name, value } => name == "X-Rate-Limit-Tier" && value == "admin",
        _ => false,
    });
    assert!(has_admin_tier, "Expected admin tier for /admin/ path");

    // Standard path
    let event = make_request_headers("GET", "/public/page", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

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

    let (_dir, socket_path) = start_test_server(script, false).await;
    let mut client = create_client(&socket_path).await;

    // Public path - should allow without auth
    let event = make_request_headers("GET", "/public/page", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");
    assert!(is_allow(&response.decision), "Expected public path to be allowed");

    // Health endpoint - should allow without auth
    let event = make_request_headers("GET", "/health", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");
    assert!(is_allow(&response.decision), "Expected health to be allowed");

    // Protected path without auth - should block
    let event = make_request_headers("GET", "/api/users", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");
    assert!(is_block(&response.decision), "Expected protected path to be blocked without auth");
    assert_eq!(get_block_status(&response.decision), Some(401));

    // Protected path with auth - should allow
    let mut headers = HashMap::new();
    headers.insert("Authorization".to_string(), vec!["Bearer token123".to_string()]);
    let event = make_request_headers("GET", "/api/users", headers);
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");
    assert!(is_allow(&response.decision), "Expected protected path with auth to be allowed");
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

    let (_dir, socket_path) = start_test_server(script, false).await;
    let mut client = create_client(&socket_path).await;

    // SQLMap should be blocked
    let mut headers = HashMap::new();
    headers.insert("User-Agent".to_string(), vec!["sqlmap/1.0".to_string()]);
    let event = make_request_headers("GET", "/api", headers);
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");
    assert!(is_block(&response.decision), "Expected sqlmap to be blocked");

    // Nikto should be blocked
    let mut headers = HashMap::new();
    headers.insert("User-Agent".to_string(), vec!["Nikto/2.1".to_string()]);
    let event = make_request_headers("GET", "/api", headers);
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");
    assert!(is_block(&response.decision), "Expected Nikto to be blocked");

    // Normal browser should be allowed
    let mut headers = HashMap::new();
    headers.insert("User-Agent".to_string(), vec!["Mozilla/5.0 Chrome/100".to_string()]);
    let event = make_request_headers("GET", "/api", headers);
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");
    assert!(is_allow(&response.decision), "Expected normal browser to be allowed");
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

    let (_dir, socket_path) = start_test_server(script, false).await;
    let mut client = create_client(&socket_path).await;

    // HTML response should get security headers
    let mut headers = HashMap::new();
    headers.insert("Content-Type".to_string(), vec!["text/html; charset=utf-8".to_string()]);
    let event = make_response_headers(200, headers);
    let response = client
        .send_event(EventType::ResponseHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_allow(&response.decision));
    assert_eq!(response.response_headers.len(), 4);

    // JSON response should not get security headers
    let mut headers = HashMap::new();
    headers.insert("Content-Type".to_string(), vec!["application/json".to_string()]);
    let event = make_response_headers(200, headers);
    let response = client
        .send_event(EventType::ResponseHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_allow(&response.decision));
    assert!(response.response_headers.is_empty());
}
